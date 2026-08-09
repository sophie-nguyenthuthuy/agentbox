/**
 * agentbox Node runtime shim — injected via NODE_OPTIONS="--require .../agentbox.cjs".
 *
 * Arms a policy guard before user code runs, appends to the same hash-chained
 * JSONL trace as the Python runtime (the chain is cross-language: the Python
 * runner's meta entries and this shim's entries verify as one chain), and
 * exposes the effects SDK as `globalThis.agentbox` for deterministic replay.
 *
 * Honesty note: unlike CPython's irremovable audit hooks, this guard works by
 * monkeypatching `fs`, `net.Socket.prototype.connect`, and `child_process`.
 * It reliably contains well-behaved agents and prompt-injected tool calls; it
 * is not a security boundary against code that deliberately unpatches it.
 * Determinism caveats vs Python: `clock.now` returns integer milliseconds,
 * `rand.random` returns an integer in [0, 2^48) — both chosen so every traced
 * value round-trips byte-identically through Python's canonical JSON.
 */
'use strict';

if (!process.env.AGENTBOX_POLICY) return;

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const cp = require('child_process');

const MODE = process.env.AGENTBOX_MODE || 'record';
const ROOT = process.env.AGENTBOX_ROOT || process.cwd();
const ENFORCE = process.env.AGENTBOX_ENFORCE !== '0';
const TRACE = path.resolve(process.env.AGENTBOX_TRACE);
const POLICY_PATH = path.resolve(process.env.AGENTBOX_POLICY);
const REPORT = process.env.AGENTBOX_REPORT ? path.resolve(process.env.AGENTBOX_REPORT) : null;
const HASH_CAP = 1_000_000;
const GENESIS = '0'.repeat(64);

const o = {
  readFileSync: fs.readFileSync.bind(fs),
  writeFileSync: fs.writeFileSync.bind(fs),
  appendFileSync: fs.appendFileSync.bind(fs),
  statSync: fs.statSync.bind(fs),
  realpathSync: fs.realpathSync.bind(fs),
  mkdirSync: fs.mkdirSync.bind(fs),
  spawnSync: cp.spawnSync.bind(cp),
};

let quietDepth = 0;
function quiet(fn) { quietDepth++; try { return fn(); } finally { quietDepth--; } }

function sha256(data) { return crypto.createHash('sha256').update(data, typeof data === 'string' ? 'utf8' : undefined).digest('hex'); }

function realish(p) {
  try { return o.realpathSync(p); } catch {
    const d = path.dirname(p);
    if (d === p) return p;
    return path.join(realish(d), path.basename(p));
  }
}

// ---------------------------------------------------------------- policy ---

const KEYS = ['read', 'write', 'net', 'exec', 'env'];

function parsePolicy(text, root) {
  const rules = { read: [], write: [], net: [], exec: [], env: [] };
  let key = null;
  text.split('\n').forEach((raw, idx) => {
    const line = raw.split('#', 1)[0].trim();
    if (!line) { key = null; return; }
    for (let seg of line.split(',')) {
      seg = seg.trim();
      if (!seg) continue;
      let head = seg.split(':', 1)[0].trim().toLowerCase();
      let value;
      if (seg.includes(':') && (head === 'allow' || KEYS.includes(head))) {
        value = seg.slice(seg.indexOf(':') + 1).trim();
        if (head === 'allow') {
          const sp = value.indexOf(' ');
          head = (sp === -1 ? value : value.slice(0, sp)).trim().toLowerCase();
          value = sp === -1 ? '' : value.slice(sp + 1).trim();
          if (!KEYS.includes(head)) throw new Error(`policy line ${idx + 1}: unknown verb '${head}' after 'allow:'`);
        }
        key = head;
      } else {
        value = seg;
      }
      if (key === null) throw new Error(`policy line ${idx + 1}: value '${seg}' appears before any rule key`);
      if (!value) throw new Error(`policy line ${idx + 1}: empty value for '${key}'`);
      rules[key].push(value);
    }
  });
  const resolve = (p) => realish(path.resolve(root, p.replace(/^~(?=\/|$)/, process.env.HOME || '~')));
  return {
    reads: rules.read.map(resolve),
    writes: rules.write.map(resolve),
    nets: rules.net,
    execs: rules.exec,
  };
}

function contains(root, p) {
  return p === root || p.startsWith(root.endsWith(path.sep) ? root : root + path.sep);
}

function globToRe(pat) {
  return new RegExp('^' + pat.toLowerCase().replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
}

const policy = {
  ...parsePolicy(quiet(() => o.readFileSync(POLICY_PATH, 'utf8')), ROOT),
  allowsRead(p) { const rp = realish(path.resolve(p)); return [...this.reads, ...this.writes].some((r) => contains(r, rp)); },
  allowsWrite(p) { const rp = realish(path.resolve(p)); return this.writes.some((r) => contains(r, rp)); },
  allowsNet(host, port) {
    if (host === undefined || host === null) host = 'localhost';
    host = String(host).toLowerCase().replace(/\.$/, '');
    for (const rule of this.nets) {
      if (rule.startsWith('unix:')) continue;
      let rhost = rule, rport = null;
      const m = rule.match(/^(.*):(\d+)$/);
      if (m) { rhost = m[1]; rport = Number(m[2]); }
      if (globToRe(rhost).test(host)) {
        if (rport === null || port === undefined || port === null || Number(port) === rport) return true;
      }
    }
    return false;
  },
  allowsUnix(p) { return this.nets.some((r) => r.startsWith('unix:') && globToRe(r.slice(5)).test(String(p))); },
  allowsExec(argv) {
    if (!argv || !argv.length) return false;
    argv = argv.map(String);
    for (const rule of this.execs) {
      const want = rule.split(/\s+/).filter(Boolean);
      if (!want.length) continue;
      const prog = argv[0];
      if (prog !== want[0] && path.basename(prog) !== want[0]) continue;
      if (want.slice(1).every((w, i) => argv[i + 1] === w)) return true;
    }
    return false;
  },
};

// ----------------------------------------------------------------- trace ---

function sortDeep(v) {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortDeep(v[k]);
    return out;
  }
  return v;
}
function canonical(obj) { return JSON.stringify(sortDeep(obj)); }

let prev = GENESIS;
let nextI = 0;
try {
  const lines = quiet(() => o.readFileSync(TRACE, 'utf8')).split('\n').filter(Boolean);
  if (lines.length) {
    const last = JSON.parse(lines[lines.length - 1]);
    prev = last.sha;
    nextI = last.i + 1;
  }
} catch {}

function appendEntry(kind, op, args, result) {
  const body = { i: nextI, ts: Date.now(), kind, op, args };
  if (result !== undefined && result !== null) body.result = result;
  body.prev = prev;
  const sha = sha256(prev + canonical(body));
  quiet(() => o.appendFileSync(TRACE, canonical({ ...body, sha }) + '\n'));
  prev = sha;
  nextI += 1;
}

// ---------------------------------------------------------------- replay ---

let entries = [];
let cursor = 0;
let diverged = null;

if (MODE === 'replay') {
  entries = quiet(() => o.readFileSync(TRACE, 'utf8'))
    .split('\n').filter(Boolean).map((l) => JSON.parse(l))
    .filter((e) => e.kind === 'effect' || e.kind === 'observe');
  process.on('exit', () => {
    if (REPORT) {
      try { quiet(() => o.writeFileSync(REPORT, JSON.stringify({ consumed: cursor, total: entries.length, diverged }))); } catch {}
    }
  });
}

function diverge(msg) {
  if (!diverged) diverged = msg;
  const err = new Error(`agentbox ReplayDivergence: ${msg}`);
  err.name = 'ReplayDivergence';
  throw err;
}

function expect(kind, op, args) {
  if (cursor >= entries.length) {
    diverge(`live run issued ${op} ${canonical(args)} but the recording ended after ${entries.length} steps`);
  }
  const e = entries[cursor];
  if (e.kind !== kind || e.op !== op || canonical(e.args) !== canonical(args)) {
    diverge(`step ${e.i}: recorded ${e.kind} ${e.op} ${canonical(e.args)}, but live run issued ${kind} ${op} ${canonical(args)}`);
  }
  cursor += 1;
  return e;
}

function observe(op, args) {
  if (MODE === 'record') appendEntry('observe', op, args);
  else expect('observe', op, args);
}

function deny(op, target) {
  if (MODE === 'record') {
    try { appendEntry('deny', op, { target: String(target), enforced: ENFORCE }); } catch {}
  }
  if (ENFORCE) {
    const err = new Error(`agentbox: policy denies ${op} ${target}`);
    err.name = 'AgentboxPolicyError';
    throw err;
  }
  process.stderr.write(`agentbox[observe]: would deny ${op} ${target}\n`);
}

// ----------------------------------------------------------------- guard ---

const REAL_ROOT = realish(path.resolve(ROOT));
const ENTRY = process.argv[1] ? realish(path.resolve(process.argv[1])) : null;
const CODE_EXT = /\.(js|cjs|mjs|json|node|ts)$/;

function guardRead(pRaw) {
  if (quietDepth || typeof pRaw === 'number') return;
  const p = String(pRaw);
  const rp = realish(path.resolve(p));
  if (rp === TRACE || rp === REPORT || rp === POLICY_PATH) return;
  // Module loading goes through the patched fs: exempt the entry script and
  // code files under the project root / node_modules (mirrors the Python
  // guard's silent allowance for .py files on sys.path).
  if (rp === ENTRY) return;
  if (CODE_EXT.test(rp) && (contains(REAL_ROOT, rp) || rp.includes(`${path.sep}node_modules${path.sep}`))) return;
  if (policy.allowsRead(rp)) {
    const info = { path: p };
    quiet(() => {
      try {
        const st = o.statSync(rp);
        if (st.isFile() && st.size <= HASH_CAP) info.sha256 = sha256(o.readFileSync(rp));
        else info.size = st.size;
      } catch { info.exists = false; }
    });
    observe('fs.open_read', info);
    return;
  }
  deny('read', p);
}

function guardWrite(pRaw) {
  if (quietDepth || typeof pRaw === 'number') return;
  const p = String(pRaw);
  const rp = realish(path.resolve(p));
  if (rp === TRACE || rp === REPORT) return;
  if (policy.allowsWrite(rp)) { observe('fs.open_write', { path: p }); return; }
  deny('write', p);
}

function guardOpen(pRaw, flags) {
  if (typeof flags === 'function' || flags === undefined || flags === null) flags = 'r';
  const writing = typeof flags === 'string'
    ? /[wa+]/.test(flags)
    : Boolean(flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_APPEND | fs.constants.O_CREAT | fs.constants.O_TRUNC));
  (writing ? guardWrite : guardRead)(pRaw);
}

function guardSpawn(argv, label) {
  if (quietDepth) return;
  argv = argv.filter((x) => x !== undefined && x !== null).map(String);
  if (!argv.length) { deny('exec', label); return; }
  if (MODE === 'replay') { deny('exec', `${argv[0]} (replay mode blocks spawns; use the agentbox SDK run)`); return; }
  if (policy.allowsExec(argv)) { observe('proc.spawn', { argv }); return; }
  deny('exec', argv.join(' '));
}

function wrap(obj, name, pre) {
  const fn = obj[name];
  if (typeof fn !== 'function') return;
  obj[name] = function (...args) { pre(...args); return fn.apply(this, args); };
}

for (const name of ['readFile', 'readFileSync', 'createReadStream']) wrap(fs, name, (p) => guardRead(p));
for (const name of ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream',
  'unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync', 'mkdir', 'mkdirSync',
  'truncate', 'truncateSync']) wrap(fs, name, (p) => guardWrite(p));
for (const name of ['open', 'openSync']) wrap(fs, name, (p, flags) => guardOpen(p, flags));
for (const name of ['rename', 'renameSync']) wrap(fs, name, (a, b) => { guardWrite(a); guardWrite(b); });
for (const name of ['copyFile', 'copyFileSync']) wrap(fs, name, (a, b) => { guardRead(a); guardWrite(b); });
for (const name of ['readFile']) wrap(fs.promises, name, (p) => guardRead(p));
for (const name of ['writeFile', 'appendFile', 'unlink', 'rm', 'rmdir', 'mkdir', 'truncate']) wrap(fs.promises, name, (p) => guardWrite(p));
wrap(fs.promises, 'open', (p, flags) => guardOpen(p, flags));
wrap(fs.promises, 'rename', (a, b) => { guardWrite(a); guardWrite(b); });
wrap(fs.promises, 'copyFile', (a, b) => { guardRead(a); guardWrite(b); });

const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  if (!quietDepth) {
    let opts = Array.isArray(args[0]) ? args[0][0] : args[0];
    let host, port, unixPath;
    if (opts && typeof opts === 'object') { host = opts.host || 'localhost'; port = opts.port; unixPath = opts.path; }
    else if (typeof opts === 'number' || (typeof opts === 'string' && /^\d+$/.test(opts))) {
      port = Number(opts);
      host = typeof args[1] === 'string' ? args[1] : 'localhost';
    } else if (typeof opts === 'string') { unixPath = opts; }
    if (MODE === 'replay') deny('net', `${host || unixPath} (replay mode blocks all live network; use the agentbox SDK)`);
    else if (unixPath) { if (!policy.allowsUnix(unixPath)) deny('net', `unix:${unixPath}`); }
    else if (policy.allowsNet(host, port)) observe('net.resolve', { host: String(host) });
    else deny('net', `${host}:${port}`);
  }
  return origConnect.apply(this, args);
};

for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync'])
  wrap(cp, name, (file, args) => guardSpawn([file, ...(Array.isArray(args) ? args : [])], name));
for (const name of ['exec', 'execSync'])
  wrap(cp, name, (cmd) => guardSpawn(String(cmd).split(/\s+/).filter(Boolean), name));
wrap(cp, 'fork', (modulePath) => guardSpawn([process.execPath, String(modulePath)], 'fork'));

// ------------------------------------------------------------------- SDK ---

function effect(op, args, doFn) {
  if (MODE === 'record') {
    const result = quiet(doFn);
    appendEntry('effect', op, args, result);
    return result;
  }
  return expect('effect', op, args).result;
}

async function effectAsync(op, args, doFn) {
  if (MODE === 'record') {
    quietDepth += 1;
    let result;
    try { result = await doFn(); } finally { quietDepth -= 1; }
    appendEntry('effect', op, args, result);
    return result;
  }
  return expect('effect', op, args).result;
}

function policyError(msg) {
  const err = new Error(`agentbox: ${msg}`);
  err.name = 'AgentboxPolicyError';
  return err;
}

globalThis.agentbox = {
  readText(p) {
    if (!policy.allowsRead(p)) throw policyError(`policy denies read ${p}`);
    return effect('fs.read_text', { path: String(p) }, () => o.readFileSync(p, 'utf8'));
  },
  writeText(p, text) {
    if (!policy.allowsWrite(p)) throw policyError(`policy denies write ${p}`);
    return effect('fs.write_text', { path: String(p), sha256: sha256(String(text)) }, () => {
      o.mkdirSync(path.dirname(path.resolve(p)), { recursive: true });
      o.writeFileSync(p, String(text));
      return { bytes: Buffer.byteLength(String(text)) };
    });
  },
  get(url, headers) {
    const u = new URL(url);
    if (!policy.allowsNet(u.hostname, u.port ? Number(u.port) : null)) {
      return Promise.reject(policyError(`policy denies net ${u.hostname}`));
    }
    return effectAsync('net.get', { url: String(url) }, () => new Promise((resolve, reject) => {
      const mod = u.protocol === 'https:' ? require('https') : require('http');
      const req = mod.get(url, { headers: headers || {} }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          resolve({ status: res.statusCode, body: buf.toString('utf8'), sha256: sha256(buf) });
        });
      });
      req.on('error', reject);
    }));
  },
  run(argv) {
    argv = argv.map(String);
    if (!policy.allowsExec(argv)) throw policyError(`policy denies exec ${argv[0]}`);
    return effect('proc.run', { argv }, () => {
      const r = o.spawnSync(argv[0], argv.slice(1), { encoding: 'utf8' });
      return { code: r.status === null ? -1 : r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
    });
  },
  now() { return effect('clock.now', {}, () => Date.now()); },
  random() { return effect('rand.random', {}, () => crypto.randomInt(0, 2 ** 48 - 1)); },
};
