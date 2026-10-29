#!/usr/bin/env python3
# Copyright 2026 DNS Events contributors
# SPDX-License-Identifier: Apache-2.0
"""Opt-in macOS regression for host schedule RPC contention and recovery.

Runs an isolated daemon and removes its private state after shutdown. The system
service, installed extension, and configuration are never changed.
"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from integration import executable, stop
from live_support import wait_for_answer

ROOT = Path(__file__).resolve().parent.parent
SCHEDULE_FIELDS = ("schedule_ready", "schedule_refresh_ok",
                   "schedule_refresh_errors", "schedule_last_success_time",
                   "schedule_last_error_time", "schedule_last_error")
HEALTH_FIELDS = ("stream_running", "stream_starts", "stream_restarts",
                 "subscriber_active", "disable_events", "events_expiry",
                 "events_max", "write_errors", "write_drops", "loss_notices",
                 "stream_queue_drops", "last_error") + SCHEDULE_FIELDS
NORMAL_BINARY = "/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def system_snapshot():
    files = {}
    for filename in (NORMAL_BINARY, "/var/osquery/osquery.flags",
                     "/var/osquery/osquery.conf", "/var/osquery/extensions.load",
                     "/Library/LaunchDaemons/io.osquery.agent.plist"):
        try:
            files[filename] = hashlib.sha256(Path(filename).read_bytes()).hexdigest()
        except FileNotFoundError:
            files[filename] = "absent"
        except PermissionError:
            files[filename] = "unreadable"
    processes = subprocess.check_output(["/bin/ps", "-axo", "pid=,ppid=,comm="], text=True)
    identities = sorted(line.split(None, 2)[:2] for line in processes.splitlines()
                        if line.split(None, 2)[-1] == NORMAL_BINARY)
    return files, identities


class ScheduleProbe:
    def __init__(self, daemon, extension, state):
        self.daemon, self.extension, self.state = daemon, extension, state
        self.process = None
        self.output = None
        self.config = {"options": {"config_refresh": "1", "events_optimize": "true",
                                   "events_expiry": "3600", "events_max": "50000"},
                       "schedule": {}}
        for name, interval in (("dns_fast", 2), ("dns_slow", 5)):
            self.config["schedule"][name] = {
                "query": "SELECT eid,client_pid,kind,query_type FROM dns_events;",
                "interval": interval, "removed": False}
        self.config["schedule"]["health"] = {
            "query": "SELECT * FROM dns_events_status;", "interval": 1, "snapshot": True}
        self.positions, self.delivered = {}, collections.defaultdict(collections.Counter)

    def guard(self):
        require(shutil.disk_usage(self.state).free >= 2 * 1024**3,
                "Less than 2 GiB free disk space")
        sizes = [path.stat().st_size for path in self.state.rglob("*")
                 if path.is_file() and not path.is_symlink()]
        require(sum(sizes) <= 64 * 1024**2 and all(n <= 32 * 1024**2 for n in sizes),
                "Isolated test state exceeded its storage bound")
        if self.process is not None:
            require(self.process.poll() is None, "Isolated daemon exited unexpectedly")

    def write_config(self):
        temporary = self.state / "config.tmp"
        temporary.write_text(json.dumps(self.config))
        temporary.replace(self.state / "config.json")

    def start(self):
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM})
        (self.state / "logs").mkdir()
        (self.state / "extensions.load").write_text(self.extension + "\n")
        self.write_config()
        self.output = (self.state / "daemon.log").open("w")
        command = [self.daemon, "--flagfile=/dev/null", "--allow_unsafe=true",
                   "--disable_events=false", "--disable_extensions=false",
                   "--events_optimize=true", "--config_refresh=1",
                   "--enable_extensions_watchdog=true", "--watchdog_level=-1",
                   "--extensions_timeout=10", "--extensions_require=dns_events",
                   "--schedule_splay_percent=0", "--config_plugin=filesystem",
                   "--logger_plugin=filesystem", "--logger_event_type=false",
                   "--config_path=" + str(self.state / "config.json"),
                   "--database_path=" + str(self.state / "db"),
                   "--pidfile=" + str(self.state / "pid"),
                   "--logger_path=" + str(self.state / "logs"),
                   "--extensions_socket=" + str(self.state / "em"),
                   "--extensions_autoload=" + str(self.state / "extensions.load")]
        self.process = subprocess.Popen(command, stdout=self.output, stderr=subprocess.STDOUT,
                                        start_new_session=True, cwd=self.state)

    def sql(self, query):
        self.guard()
        result = subprocess.run(
            [self.daemon, "--S", "--flagfile=/dev/null", "--extensions_autoload=",
             "--extensions_require=", "--extensions_socket=" + str(self.state / "shell.em"),
             "--extensions_timeout=10", "--connect=" + str(self.state / "em"),
             "--json", query], text=True, capture_output=True, timeout=12)
        require(result.returncode == 0, "Isolated SQL RPC failed")
        try:
            return json.loads(result.stdout[result.stdout.index("["):])
        except (ValueError, json.JSONDecodeError):
            raise AssertionError("Isolated SQL RPC returned invalid JSON") from None

    def health(self):
        rows = self.sql("SELECT * FROM dns_events_status;")
        require(bool(rows), "Extension health row is unavailable")
        return rows[0]

    def wait(self, predicate, timeout=30):
        deadline, last = time.monotonic() + timeout, None
        while time.monotonic() < deadline:
            self.guard()
            try:
                last = predicate()
                if last:
                    return last
            except (AssertionError, subprocess.SubprocessError):
                pass
            time.sleep(0.3)
        raise AssertionError("Isolated condition did not become ready within its deadline")

    def read_deliveries(self):
        path = self.state / "logs/osqueryd.results.log"
        if not path.exists():
            return self.delivered
        with path.open() as stream:
            stream.seek(self.positions.get(str(path), 0))
            while True:
                before = stream.tell()
                line = stream.readline()
                if not line or not line.endswith("\n"):
                    stream.seek(before)
                    break
                record = json.loads(line)
                name = record.get("name")
                if name not in ("dns_fast", "dns_slow"):
                    continue
                rows = ([record["columns"]] if record.get("action") == "added" else [])
                rows += record.get("diffResults", {}).get("added", [])
                for row in rows:
                    self.delivered[(name, row.get("client_pid"))][row["eid"]] += 1
                require(sum(len(ids) for ids in self.delivered.values()) <= 50000,
                        "Delivery record memory bound exceeded")
            self.positions[str(path)] = stream.tell()
        return self.delivered

    def workload(self, count=10):
        epoch = int(time.time())
        code = ("import socket,time\nfor _ in range(%d):\n"
                " socket.getaddrinfo('example.com',443,type=socket.SOCK_STREAM)\n"
                " time.sleep(.03)\n") % count
        resolver = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
        try:
            resolver.wait(timeout=20)
        finally:
            if resolver.poll() is None:
                resolver.kill()
                resolver.wait(timeout=5)
        require(resolver.returncode == 0, "Controlled DNS resolver failed")
        query = ("SELECT eid,kind,query_type FROM dns_events WHERE time >= %d "
                 "AND client_pid=%d;") % (epoch, resolver.pid)
        previous, stable = None, time.monotonic()

        def retained():
            nonlocal previous, stable
            rows = self.sql(query)
            starts = collections.Counter(row["query_type"] for row in rows if row["kind"] == "query")
            if len(rows) != previous:
                previous, stable = len(rows), time.monotonic()
            if starts == {"A": count, "AAAA": count} and any(row["kind"] == "answer" for row in rows):
                if time.monotonic() - stable >= 2:
                    return rows

        rows = self.wait(retained)
        ids = {row["eid"] for row in rows}
        require(len(ids) == len(rows), "Retained DNS event IDs are not unique")

        def delivered():
            actual = self.read_deliveries()
            return all(ids <= actual[(name, str(resolver.pid))].keys()
                       for name in ("dns_fast", "dns_slow"))

        self.wait(delivered)
        time.sleep(5)
        actual = self.read_deliveries()
        require(all(all(actual[(name, str(resolver.pid))][eid] == 1 for eid in ids)
                    for name in ("dns_fast", "dns_slow")), "DNS events were delivered more than once")
        return {"resolver_calls": count, "retained_events": len(rows),
                "a_and_aaaa_starts_complete": True, "two_schedules_exactly_once": True}

    def close(self):
        try:
            stop(self.process)
        finally:
            if self.output is not None:
                self.output.close()


def safe_health(row):
    return {name: row.get(name) for name in HEALTH_FIELDS}


def run_test(probe, report):
    probe.start()
    initial = probe.wait(lambda: (row if row.get("stream_running") == "1" else None)
                         if (row := probe.health()) else None, timeout=60)
    report["initial_health"] = safe_health(initial)
    wait_for_answer(probe.sql)
    report["before_contention"] = probe.workload()
    require(not initial.get("last_error"), "Extension already reported an error before contention")
    initial_errors = int(initial.get("schedule_refresh_errors", "0"))
    # Cache this schedule while cheap, then contend and recover without editing
    # it. The scheduler owns its schedule mutex while the query runs.
    expensive_from = int(time.time()) + 15
    expensive_until = expensive_from + 20
    query = ("WITH RECURSIVE cnt(x,n) AS (SELECT 0,CASE WHEN "
             "CAST(strftime('%%s','now') AS INTEGER) BETWEEN %d AND %d "
             "THEN 20000000 ELSE 1 END UNION ALL SELECT x+1,n FROM cnt "
             "WHERE x<n) SELECT max(x) AS maximum FROM cnt;") % (expensive_from, expensive_until)
    probe.config["packs"] = {"contention": {"queries": {"bounded_slow_query": {
        "query": query, "interval": 11, "snapshot": True}}}}
    schedule_before = json.dumps(probe.config["packs"], sort_keys=True)
    probe.write_config()
    probe.wait(lambda: probe.sql("SELECT name FROM osquery_schedule WHERE "
                                "name='pack_contention_bounded_slow_query';"), timeout=8)
    observed_at = int(time.time())
    if all(name in initial for name in SCHEDULE_FIELDS):
        timestamps = set()

        def cached():
            row = probe.health()
            if row.get("schedule_refresh_ok") == "1" and int(row["schedule_last_success_time"]) > observed_at:
                timestamps.add(row["schedule_last_success_time"])
            return len(timestamps) >= 2

        probe.wait(cached, timeout=8)
        report["schedule_cached_before_contention"] = True
    require(int(time.time()) < expensive_from,
            "The scheduled query became expensive before cache readiness")

    def fault_observed():
        row = probe.health()
        if int(row.get("schedule_refresh_errors", "0")) > initial_errors:
            return row
        if row.get("last_error") == "Cannot refresh host event schedule":
            return row

    fault = probe.wait(fault_observed, timeout=45)
    report["contention_health"] = safe_health(fault)
    require(fault.get("stream_running") == "1", "Schedule refresh failure stopped the DNS stream")
    if "schedule_last_error" in fault:
        require(fault["schedule_last_error"] == "Host event schedule RPC timed out",
                "The scheduled query did not produce the expected RPC timeout")
    performance = probe.sql("SELECT last_wall_time_ms FROM osquery_schedule "
                            "WHERE name='pack_contention_bounded_slow_query';")
    require(bool(performance) and int(performance[0]["last_wall_time_ms"]) > 2000,
            "One scheduled query execution did not exceed two seconds")
    report["slow_query_last_wall_time_ms"] = int(performance[0]["last_wall_time_ms"])
    probe.config["options"].update(disable_events="true", events_expiry="7200", events_max="40000")
    probe.write_config()

    def disabled():
        row = probe.health()
        if all(row.get(key) == value for key, value in (
                ("disable_events", "1"), ("stream_running", "0"),
                ("events_expiry", "7200"), ("events_max", "40000"))):
            return row

    report["configuration_applied_health"] = safe_health(probe.wait(disabled, timeout=40))
    probe.config["options"]["disable_events"] = "false"
    probe.write_config()

    def recovered():
        row = probe.health()
        if row.get("stream_running") != "1":
            return None
        if all(name in row for name in SCHEDULE_FIELDS):
            if row["schedule_ready"] == "1" and row["schedule_refresh_ok"] == "1" and not row["schedule_last_error"]:
                return row
        elif int(time.time()) > expensive_until + 5:
            return row

    recovered_health = probe.wait(recovered, timeout=40)
    report["recovered_health"] = safe_health(recovered_health)
    require(json.dumps(probe.config["packs"], sort_keys=True) == schedule_before,
            "The recovery test changed the scheduled query")
    report["recovery_schedule_unchanged"] = True
    report["slow_query_exceeded_rpc_timeout"] = True
    require(all(name in recovered_health for name in SCHEDULE_FIELDS),
            "The extension does not expose current schedule refresh health")
    require(int(recovered_health["schedule_refresh_errors"]) > initial_errors,
            "The schedule refresh failure was not retained in its cumulative counter")
    require(int(recovered_health["schedule_last_success_time"]) >= int(recovered_health["schedule_last_error_time"]),
            "Schedule refresh recovery did not advance its success timestamp")
    report["after_recovery"] = probe.workload()
    final = probe.health()
    report["final_health"] = safe_health(final)
    for counter in ("write_errors", "write_drops", "loss_notices", "stream_queue_drops"):
        require(final.get(counter) == "0", "The schedule contention test lost DNS events")
    require(final.get("stream_restarts") == initial.get("stream_restarts"),
            "Schedule contention unexpectedly restarted the logging source")
    report["status"] = "PASS"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extension", default=str(ROOT / "build/dns_events.ext"))
    parser.add_argument("--osqueryd", default=NORMAL_BINARY)
    parser.add_argument("--state-dir", type=Path, default=Path("/private/tmp"))
    parser.add_argument("--report", type=Path)
    options = parser.parse_args()
    if not __debug__:
        parser.error("Run without -O or PYTHONOPTIMIZE")
    if sys.platform != "darwin":
        parser.error("The live schedule test requires macOS")
    daemon, extension = map(executable, (options.osqueryd, options.extension))
    os.umask(0o077)
    options.state_dir.mkdir(parents=True, exist_ok=True)
    require(shutil.disk_usage(options.state_dir).free >= 2 * 1024**3,
            "Less than 2 GiB free disk space")
    state = Path(tempfile.mkdtemp(prefix="dns-schedule-", dir=options.state_dir))
    require(len(os.fsencode(str(state / "shell.em"))) < 100, "State directory is too long for Unix sockets")
    original = system_snapshot()
    report = {"status": "RUNNING", "raw_dns_values_in_report": False,
              "binary_sha256": hashlib.sha256(Path(daemon).read_bytes()).hexdigest(),
              "extension_sha256": hashlib.sha256(Path(extension).read_bytes()).hexdigest()}
    probe = ScheduleProbe(daemon, extension, state)
    try:
        run_test(probe, report)
    except Exception as error:
        report.update(status="FAIL", error_type=type(error).__name__)
        if isinstance(error, AssertionError):
            report["error"] = str(error)
    finally:
        try:
            probe.close()
            report["own_processes_stopped"] = True
        except Exception as error:
            report.update(status="FAIL", cleanup_error_type=type(error).__name__)
        if report.get("own_processes_stopped"):
            shutil.rmtree(state)
            report["own_state_deleted"] = True
        report["system_service_and_configuration_unchanged"] = system_snapshot() == original
        if not report["system_service_and_configuration_unchanged"]:
            report.update(status="FAIL", error="System service or readable configuration changed")
        if options.report is not None:
            options.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return int(report["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
