# DNS events for osquery on macOS

`dns_events.ext` collects mDNSResponder queries and answers through osquery's event framework. Collection runs inside the extension, and events are stored in the host osquery database. The extension follows osqueryd's lifecycle and does not launch a separate `log stream` process.

| Table | Purpose |
|---|---|
| `dns_events` | Queries, answers, removals and no-data results with client PID and process name |
| `dns_events_status` | Collector state, queue usage, storage errors and loss counters |

The source uses a private macOS logging API. It observes mDNSResponder activity, including cached responses, rather than every application's DNS traffic. Its event publisher and subscriber run in the extension and are not listed in the host's `osquery_events` table.

## Build

Requires macOS, Apple Command Line Tools, Python 3.9+, Git, internet access and several GB of free space.

```bash
./scripts/build.sh
```

Output: `build/dns_events.ext`, with an ad-hoc signature. The script downloads the pinned SDK into `.cache/` and runs offline tests. Build options, compatibility and test commands are in [implementation](docs/implementation.md#development).

## Load

Add the absolute path to `dns_events.ext` to your existing osquery extension autoload list. The executable must have safe, root-owned permissions, and events must be enabled with `--disable_events=false`. Use the [osquery extension documentation](https://osquery.readthedocs.io/en/stable/deployment/extensions/) for deployment requirements.

The included [query pack](configs/dns-events.pack.json) collects events every 5 minutes and checks collector status every 15 minutes. Keep event optimization enabled for scheduled collection; see [storage and cursors](docs/implementation.md#storage-and-sql).

## Logging profile

Recent macOS versions can hash or redact domain names and answers in mDNSResponder logs. Install [dns.mobileconfig](configs/dns.mobileconfig) when you need readable domain names. It configures private-data options and Info logging for `com.apple.mDNSResponder` and `com.apple.mdns`; private-value availability still depends on macOS.

Without the profile, collection continues with the values supplied by the OS. Masked rows have `redacted=1`. The profile remains active when osquery stops and is removed separately.

## Example

Query the running daemon's table:

```sql
SELECT * FROM dns_events;
```

With the profile:

```json
{"time":"1791892800","client_pid":"3500","responder_pid":"228","interface_index":"0","expired":"0","correlated":"1","redacted":"0","eid":"0000000001","timestamp":"2026-10-13 12:00:00.000000+0000","kind":"answer","request_id":"42","question_id":"9","api":"DNSServiceQueryRecord","domain":"example.com.","query_type":"A","answer":"192.0.2.1","client_process":"Example App"}
```

Without the profile:

```json
{"time":"1791892800","client_pid":"3500","responder_pid":"228","interface_index":"0","expired":"0","correlated":"1","redacted":"1","eid":"0000000001","timestamp":"2026-10-13 12:00:00.000000+0000","kind":"answer","request_id":"42","question_id":"9","api":"DNSServiceQueryRecord","domain":"<mask.hash: 'a1b2c3d4'>","query_type":"A","answer":"<mask.hash: 'e5f60718'>","client_process":"Example App"}
```

These rows are synthetic examples. For fields, correlation, retention and limitations, see [implementation](docs/implementation.md).

## License

[Apache-2.0](LICENSE). The build uses the osquery SDK under its [Apache-2.0 option](https://github.com/osquery/osquery/blob/master/LICENSE). Dependencies retain their upstream licenses.
