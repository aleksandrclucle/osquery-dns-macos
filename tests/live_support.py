# Copyright 2026 DNS Events contributors
# SPDX-License-Identifier: Apache-2.0

"""Warm a live subscription with a separate PID before counting test requests."""
import subprocess
import collections
import sys
import tempfile
import time


def wait_for_answer(sql, timeout=20):
    epoch = int(time.time())
    resolver = subprocess.Popen([sys.executable, "-c",
        "import signal,socket,time\nsignal.signal(signal.SIGTERM,signal.SIG_DFL)\nsignal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGTERM})\nfor _ in range(80):\n socket.getaddrinfo('example.com',443)\n time.sleep(0.25)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, cwd=tempfile.gettempdir())
    try:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            rows = sql("SELECT eid, kind FROM dns_events WHERE time >= %d AND client_pid = %d;" % (epoch, resolver.pid))
            if any(row["kind"] == "answer" for row in rows):
                return {"probe_pid": resolver.pid, "events": len(rows),
                        "event_ids": [row["eid"] for row in rows]}
            if resolver.poll() is not None:
                raise RuntimeError("Readiness resolver ended: " + resolver.stderr.read())
            time.sleep(0.25)
        diagnostic = {"probe_pid": resolver.pid, "seconds": timeout,
                      "probe_exit": resolver.poll(),
                      "received_kinds": dict(collections.Counter(row["kind"] for row in rows))}
        try:
            diagnostic["health"] = sql("SELECT * FROM dns_events_status;")
        except Exception as error:
            diagnostic["health_error"] = str(error)
        raise RuntimeError("No fresh DNS answer during subscription warmup: " + str(diagnostic))
    finally:
        if resolver.poll() is None:
            resolver.terminate()
        try:
            resolver.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            resolver.kill()
            resolver.communicate(timeout=5)
