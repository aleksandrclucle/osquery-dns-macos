#!/usr/bin/env python3
# Copyright 2026 DNS Events contributors
# SPDX-License-Identifier: Apache-2.0
"""Opt-in macOS test with an isolated osquery process, database, and schedules.

Does not install or restart the system service. Masked events are accepted unless
--require-unredacted is given. The unique state directory is kept for diagnostics.
"""
import argparse
import collections
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

from live_support import wait_for_answer

ROOT = Path(__file__).resolve().parent.parent
SCHEDULES = ("dns_fast", "dns_slow")


def executable(value):
    # osquery selects shell/daemon mode from argv[0]. Preserve the osqueryi
    # symlink name even when both commands point to the same binary.
    path = Path(os.path.abspath(os.path.expanduser(shutil.which(value) or value)))
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("Executable not found: " + str(path))
    return str(path)


def stop(process):
    if process is None:
        return
    # Every daemon below starts a new process group. Signal only the test group,
    # including surviving children if its supervisor has already exited.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def check_rows(rows, requests, require_unredacted):
    query_types = collections.Counter(row["query_type"] for row in rows if row["kind"] == "query")
    assert query_types == {"A": requests, "AAAA": requests}, ("Unexpected A/AAAA starts", dict(query_types))
    assert all(row["correlated"] == "1" for row in rows), "Uncorrelated test events"
    for row in rows:
        masked = any(marker in row["domain"] for marker in ("<private>", "<mask.", "<redacted>", "<dn:"))
        assert row["domain"] == "example.com." or (row["redacted"] == "1" and masked), row
        if require_unredacted:
            assert row["redacted"] == "0", ("Private data is masked", row)
        if row["kind"] == "no_data":
            assert row["answer"] == "<none>", row
    assert any(row["kind"] == "answer" and row["answer"] for row in rows), "No DNS answers"


def delivery_summary(ids, counts):
    summary = {}
    for name, count in counts.items():
        missing = sorted(ids - count.keys())
        duplicates = [(eid, count[eid]) for eid in sorted(ids) if count[eid] > 1]
        summary[name] = {"expected": len(ids), "received": len(ids & count.keys()),
                         "missing": len(missing), "missing_sample": missing[:10],
                         "duplicates": len(duplicates), "duplicate_sample": duplicates[:10]}
    return summary


def run_test(options, state, daemon, shell, extension):
    # Privileged launchers can leave SIGTERM blocked across exec. The test
    # daemon and its extensions must receive the termination signals we send.
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM})
    (state / "logs").mkdir()
    (state / "extensions.load").write_text(extension + "\n")
    config = {"options": {"events_optimize": "true", "events_expiry": "3600"},
              "schedule": {name: {"query": "SELECT * FROM dns_events;", "interval": interval}
                           for name, interval in zip(SCHEDULES, (2, 5))}}
    (state / "osquery.conf").write_text(json.dumps(config))
    command = [daemon, "--flagfile=/dev/null", "--allow_unsafe=true",
               "--disable_events=false", "--disable_extensions=false",
               # Registration precedes config loading. The extension must use
               # the later events_optimize=true option before its first read.
               "--events_optimize=false",
               "--disable_watchdog=false", "--enable_extensions_watchdog=true",
               "--extensions_timeout=3", "--extensions_require=dns_events",
               "--schedule_splay_percent=0", "--config_plugin=filesystem",
               "--logger_plugin=filesystem", "--logger_rotate=false",
               "--logger_event_type=false",
               "--config_path=" + str(state / "osquery.conf"),
               "--database_path=" + str(state / "db"),
               "--pidfile=" + str(state / "pid"),
               "--logger_path=" + str(state / "logs"),
               "--extensions_socket=" + str(state / "em"),
               "--extensions_autoload=" + str(state / "extensions.load")]
    process = None

    def sql(query):
        result = subprocess.run(
            [shell, "--flagfile=/dev/null", "--extensions_autoload=",
             "--extensions_require=", "--extensions_socket=" + str(state / "shell.em"),
             "--connect=" + str(state / "em"), "--json", query],
            text=True, capture_output=True, timeout=5)
        if result.returncode:
            raise RuntimeError(result.stderr + result.stdout)
        return json.loads(result.stdout[result.stdout.index("["):])

    def ready(phase, old_pid=None):
        deadline = time.monotonic() + 60
        last = None
        current_pid = None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Test daemon exited during " + phase + ": " + str(process.returncode))
            try:
                rows = sql("SELECT * FROM dns_events_status;")
                last = rows
                current_pid = rows[0].get("stream_pid") if rows else None
                if (rows and rows[0]["stream_running"] == "1"
                        and rows[0]["subscriber_active"] == "1"
                        and current_pid and current_pid != old_pid):
                    return rows[0]
            except (ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
                last = error
            time.sleep(0.25)
        raise RuntimeError("Test extension is not ready during %s: previous_pid=%s, current_pid=%s, last=%s"
                           % (phase, old_pid, current_pid, last))

    def result_rows():
        path = state / "logs/osqueryd.results.log"
        result = collections.defaultdict(list)
        if not path.exists():
            return result
        for line in path.read_text().splitlines(keepends=True):
            if not line.endswith("\n"):
                continue  # osquery may still be writing the final line.
            record = json.loads(line)
            if record.get("action") == "added":
                result[record["name"]].append(record["columns"])
            for row in record.get("diffResults", {}).get("added", []):
                result[record["name"]].append(row)
        return result

    def check_delivery(ids, client_pid=None):
        if client_pid is None:
            client_pid = os.getpid()
        deadline = time.monotonic() + 20
        while True:
            rows = result_rows()
            counts = {name: collections.Counter(row["eid"] for row in rows[name]
                                               if row.get("client_pid") == str(client_pid))
                      for name in SCHEDULES}
            if all(ids <= set(counts[name]) for name in SCHEDULES):
                break
            if time.monotonic() >= deadline:
                raise AssertionError(("Scheduled events missing", delivery_summary(ids, counts)))
            time.sleep(0.25)
        for name, count in counts.items():
            assert all(count[eid] == 1 for eid in ids), (
                "Duplicate delivery", delivery_summary(ids, {name: count}))

    with (state / "daemon.log").open("w") as output:
        try:
            process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=True, cwd=state)
            ready("initial startup")
            wait_for_answer(sql)
            epoch = int(time.time())
            for _ in range(options.requests):
                socket.getaddrinfo("example.com", 443)
            history_query = ("SELECT * FROM dns_events WHERE time >= %d AND client_pid = %d;"
                             % (epoch, os.getpid()))
            deadline = time.monotonic() + 20
            while True:
                own = sql(history_query)
                if (sum(row["kind"] == "query" for row in own) >= 2 * options.requests
                        and any(row["kind"] == "answer" for row in own)):
                    break
                if time.monotonic() >= deadline:
                    raise AssertionError(("Test events did not arrive", {
                        "expected_queries": 2 * options.requests, "received_rows": len(own),
                        "kinds": dict(collections.Counter(row["kind"] for row in own)),
                        "sample_eids": [row["eid"] for row in own[:10]]}))
                time.sleep(0.25)
            time.sleep(1)  # Allow the last response batch to be stored.
            own = sql(history_query)
            check_rows(own, options.requests, options.require_unredacted)
            ids = {row["eid"] for row in own}
            check_delivery(ids)
            before = sql("SELECT * FROM dns_events_status;")[0]
            for counter in ("write_errors", "write_drops", "stream_queue_drops", "loss_notices"):
                assert int(before[counter]) == 0, before
            extension_pid = int(before["stream_pid"])
            assert os.getpgid(extension_pid) == process.pid, "Extension is outside the test process group"
            os.kill(extension_pid, signal.SIGTERM)
            ready("extension recovery after SIGTERM", before["stream_pid"])
            wait_for_answer(sql)
            stop(process)
            process = None
            process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=True, cwd=state)
            ready("daemon restart")
            restart_probe = wait_for_answer(sql)
            persisted = sql(history_query)
            assert ids <= {row["eid"] for row in persisted}, "Retained events lost on restart"
            # Fresh probe IDs prove that both schedules ran after the restart.
            # Old result-log entries alone cannot establish cursor persistence.
            check_delivery(set(restart_probe["event_ids"]), restart_probe["probe_pid"])
            check_delivery(ids)
            health = sql("SELECT * FROM dns_events_status;")[0]
            for counter in ("write_errors", "write_drops", "stream_queue_drops", "loss_notices"):
                assert int(health[counter]) == 0, health
            return {"status": "PASS", "requests": options.requests, "events_checked": len(ids),
                    "redacted_events": sum(row["redacted"] == "1" for row in own),
                    "checks": ["DNS/PID correlation", "all A/AAAA request starts",
                               "two independent schedule cursors", "historical reads do not consume",
                               "extension watchdog recovery", "DB persistence", "cursor persistence"],
                    "workload_health": before, "health_after_restart": health}
        finally:
            stop(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests", type=int, default=15)
    parser.add_argument("--extension", default=str(ROOT / "build/dns_events.ext"))
    parser.add_argument("--osqueryd", default="/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd")
    parser.add_argument("--osqueryi", default="/usr/local/bin/osqueryi")
    parser.add_argument("--state-dir", type=Path, default=Path("/tmp"),
                        help="parent directory for a unique retained test directory")
    parser.add_argument("--require-unredacted", action="store_true")
    options = parser.parse_args()
    if not __debug__:
        parser.error("Run without -O or PYTHONOPTIMIZE: this test requires assertions")
    if sys.platform != "darwin":
        parser.error("The live integration test requires macOS")
    if options.requests < 1:
        parser.error("--requests must be positive")
    try:
        daemon, shell, extension = map(executable, (options.osqueryd, options.osqueryi, options.extension))
    except ValueError as error:
        parser.error(str(error))
    options.state_dir.mkdir(parents=True, exist_ok=True)
    state = Path(tempfile.mkdtemp(prefix="dns-events-", dir=options.state_dir.absolute()))
    if len(os.fsencode(str(state / "shell.em"))) >= 100:
        parser.error("--state-dir is too long for macOS Unix sockets; use /tmp")
    print("Isolated test state: " + str(state), file=sys.stderr)
    try:
        report = run_test(options, state, daemon, shell, extension)
    except Exception as error:
        report = {"status": "FAIL", "error": repr(error)}
        log = state / "daemon.log"
        if log.exists():
            report["daemon_log_tail"] = log.read_text(errors="replace")[-4000:]
    report["state"] = str(state)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
