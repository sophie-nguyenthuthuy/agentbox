/** Node demo agent. Run it sandboxed from the examples/ directory:
 *
 *    agentbox run    -p agentbox.policy -- node demo_agent.js
 *    agentbox replay -p agentbox.policy -- node demo_agent.js
 */
const fs = require("fs");
const box = globalThis.agentbox;

const notes = box.readText("data/notes.txt");        // replayable effect
const raw = fs.readFileSync("data/notes.txt", "utf8"); // direct IO: guard-observed
const stamp = box.now();                             // frozen on replay
const echoed = box.run(["echo", "sandboxed subprocess"]);

box.writeText("out/summary.txt", `[${stamp}] ${notes.length} bytes of notes\n${echoed.stdout}`);
console.log("wrote out/summary.txt at", stamp);

try {
  fs.readFileSync("/etc/passwd", "utf8");
} catch (err) {
  console.log("blocked as expected:", err.message);
}
