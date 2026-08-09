import json

import pytest

from agentbox.trace import GENESIS, TraceWriter, read_trace, verify_chain


def test_chain_appends_and_verifies(tmp_path):
    t = tmp_path / "t.jsonl"
    w = TraceWriter(str(t))
    w.append("effect", "fs.read_text", {"path": "a"}, "hello")
    w.append("observe", "fs.open_read", {"path": "b"})
    entries = read_trace(str(t))
    assert [e["i"] for e in entries] == [0, 1]
    assert entries[0]["prev"] == GENESIS
    assert entries[1]["prev"] == entries[0]["sha"]
    assert verify_chain(entries) == (True, None)


def test_writer_continues_existing_chain(tmp_path):
    t = tmp_path / "t.jsonl"
    TraceWriter(str(t)).append("meta", "run.start", {})
    TraceWriter(str(t)).append("effect", "clock.now", {}, 1.0)
    entries = read_trace(str(t))
    assert len(entries) == 2
    assert verify_chain(entries) == (True, None)


def test_fresh_discards_old_trace(tmp_path):
    t = tmp_path / "t.jsonl"
    TraceWriter(str(t)).append("meta", "run.start", {})
    TraceWriter(str(t), fresh=True).append("meta", "run.start", {"v": 2})
    entries = read_trace(str(t))
    assert len(entries) == 1 and entries[0]["args"] == {"v": 2}


def test_edit_detected(tmp_path):
    t = tmp_path / "t.jsonl"
    w = TraceWriter(str(t))
    for i in range(3):
        w.append("effect", "clock.now", {}, float(i))
    entries = read_trace(str(t))
    entries[1]["result"] = 99.0
    assert verify_chain(entries) == (False, 1)


def test_deletion_detected(tmp_path):
    t = tmp_path / "t.jsonl"
    w = TraceWriter(str(t))
    for i in range(3):
        w.append("effect", "clock.now", {}, float(i))
    entries = read_trace(str(t))
    del entries[1]
    ok, bad = verify_chain(entries)
    assert not ok and bad == 1


def test_reorder_detected(tmp_path):
    t = tmp_path / "t.jsonl"
    w = TraceWriter(str(t))
    w.append("effect", "a", {})
    w.append("effect", "b", {})
    entries = read_trace(str(t))
    ok, bad = verify_chain(entries[::-1])
    assert not ok and bad == 0
