# Implementation

## Log source and visibility

The extension subscribes to macOS Unified Logging through the private `OSLogEventLiveStream` API in LoggingSupport, with Info messages enabled. It accepts log events from `/usr/sbin/mDNSResponder` containing `DNSServiceQueryRecord` or `DNSServiceGetAddrInfo`, then parses the supported START, result and STOP messages. It does not capture network packets or act as a DNS proxy.

Despite its name, [mDNSResponder is the macOS system resolver](https://github.com/apple-oss-distributions/mDNSResponder#mdns-responder-daemon) for both ordinary unicast DNS and multicast DNS/Bonjour. Visibility depends on a request reaching that daemon and producing a supported log message:

- Requests handled by mDNSResponder can be collected, including responses from its cache. A logged result does not necessarily mean a DNS packet was sent.
- Tools with their own resolver can send DNS directly over UDP or TCP and bypass mDNSResponder. Those resolutions are invisible to this extension.
- Application-managed [DoH (DNS over HTTPS)](https://www.rfc-editor.org/rfc/rfc8484.html), [DoT (DNS over TLS)](https://www.rfc-editor.org/rfc/rfc7858.html) and [DoQ (DNS over QUIC)](https://www.rfc-editor.org/rfc/rfc9250.html) are blind spots when they bypass mDNSResponder. The extension does not inspect or decrypt those connections.
- An application's own DNS cache or use of an IP address can avoid a new resolver request entirely, leaving no corresponding event here.

Encrypted DNS handled through the system resolver may still produce local mDNSResponder API logs. Visibility follows the resolver path; the transport protocol alone does not establish whether a request will appear. The logging profile controls logging and private-field disclosure for the configured subsystems. It does not make bypassing resolvers visible.

Only live events are collected. Unified Log history is not scanned, and events before subscription readiness or during reconnection are not recovered. An empty table does not prove that no DNS resolution occurred.

## Event flow

```text
mDNSResponder -> logd -> OSLogEventLiveStream inside dns_events.ext
                     -> bounded queue -> Parser -> DNSPublisher
                     -> DNSSubscriber::addBatch()
                     -> osqueryd event database through SDK RPC
```

Parsing and collection run inside the extension independently of SQL queries. No separate `log stream` process is started.

The parser correlates START and result messages using the responder PID, request ID, and API name. STOP removes the matching context. Results support both `name hash: ...` and `name: ... (hash)` metadata, including an optional `dnssec` result field. The stored domain and client identity come from START; without it, a result has an empty domain, `client_pid=-1`, and `correlated=0`. `->mDNS` and `->mDNSQ` results have an empty `question_id`.

START fields follow a fixed grammar through the client PID. Text such as `client pid:` or `, qtype: ` inside a process name stays part of that name. A repeated `qtype` or `protocols` delimiter is rejected when it begins a second complete START header, since an unescaped domain could otherwise shift the client PID boundary. Unknown field layouts and comma-containing domains are also rejected. A rejected START with a recognized request header clears the previous context for that request ID and increments `unsupported_messages`; subsequent results remain uncorrelated until a valid START arrives. For results with `name hash` metadata, `, type: ` inside RDATA is retained. Results with a printed `name` also retain that text unless it forms a second complete type/RDATA header, which is ambiguous and rejected.

The extension uses real osquery `EventPublisher` and `EventSubscriber` classes. The SQL table `dns_events` advertises the `EVENT_BASED` attribute. Its EventFactory belongs to the extension process, so the core `osquery_events` table does not list its publisher or subscriber. Their state is exposed through `dns_events_status`.

## Storage and SQL

Event rows are stored in the host osqueryd database through the SDK database proxy. For a SELECT, osquery executes SQL and calls the extension table. The extension reads its subscriber's rows through SDK RPC and returns them to osquery. Both processes use CPU and memory; mDNSResponder and logd also perform system logging work.

The standard EventSubscriber manages expiry, string event IDs, and separate cursors for scheduled queries. The extension copies event flags from the host at startup. Its `shouldOptimize()` override uses the host's `events_optimize` value because the SDK otherwise distinguishes an extension from a daemon. The SDK cursor algorithm is unchanged.

Keep the scheduled delivery query as `SELECT * FROM dns_events;`. Adding SQL filters or LIMIT can discard rows after the event cursor has advanced. For diagnostic history, use an explicit `time` constraint, such as `WHERE time > 0`; this avoids advancing the scheduled cursor.

Set `events_expiry` to at least three times the longest DNS schedule interval. In the pinned SDK, `events_max` limits time batches rather than imposing a strict maximum number of DNS rows. Stored events and cursors survive extension restarts, subject to retention and the host database lifecycle.

## Main fields

| Fields | Meaning |
|---|---|
| `time`, `eid` | Storage time and string event ID assigned by osquery |
| `timestamp` | Timestamp of the original log message |
| `kind` | `query`, `answer`, `remove`, or `no_data` |
| `domain`, `query_type`, `answer` | Domain, resource record type, and RDATA |
| `client_pid`, `client_process` | Client identity from START |
| `responder_pid`, `request_id`, `question_id`, `api` | Source and correlation identifiers |
| `interface_index`, `expired` | Result metadata |
| `correlated`, `redacted` | START context available and a recognized privacy placeholder present |

`kind=no_data` preserves `answer='<none>'`. It does not prove NXDOMAIN. Rows represent observed log events, not necessarily unique network requests.

## Profile and coverage

Collection can operate without the supplied logging profile. macOS may then mask domains and addresses using values such as `<private>`, `<mask.hash: ...>`, `<dn:...>` or `<rd:...>`. The extension preserves these values and sets `redacted=1` for recognized placeholders; it does not recover the original data. Client and record metadata can remain visible. Masking behavior depends on the OS and logging configuration.

Both hexadecimal name hashes and opaque `<dn:...>` tokens are supported. A domain such as `example.com. <dn:v4mDGw>` is stored as `example.com.` when its trailing token matches the structured name hash. A trailing `<rd:...>` annotation is removed from valid A/AAAA addresses and simple CNAME/PTR/NS/DNAME names. TXT, composite records and escaped answer names are preserved. Token-only values remain masked with `redacted=1`; readable values with annotations are not classified as masked. Tokens are never decoded.

The optional profile configures only the `com.apple.mDNSResponder` and `com.apple.mdns` logging subsystems. Each receives `Enable-Private-Data=true`, `Privacy-Enable-Level=Sensitive`, and Info enablement and persistence settings under `DEFAULT-OPTIONS`. `PayloadScope=System` sets the installation scope to the device; the payload contains no global `System` logging settings. macOS determines whether private values are available, so applying the profile does not guarantee unmasked output. The profile remains active when osquery stops, and removing the extension does not remove it.

The source uses the private `OSLogEventLiveStream` API in LoggingSupport. Required selectors are checked at runtime, but these checks cannot guarantee ABI or message-format compatibility on every macOS version. Unsupported APIs are reported in status; unsupported messages are counted. Live validation is needed after OS upgrades.

## Bounds and diagnostics

The queue holds at most 8192 messages and 16 MiB of payload. The parser accepts messages up to 8 KiB, RDATA up to 4 KiB, and 4096 correlation contexts with a 10-minute TTL. Writes are batched at up to 128 events or a 500 ms flush interval. These bounds do not cap total RSS because SQL responses materialize rows.

`dns_events_status` reports queue drops, source loss notices, unsupported messages, correlation evictions, write failures, and source restarts. `stream_pid` is the extension PID while its source is active. `stream_running=1` means the subscription was activated; verify a fresh answer to establish that events actually arrive. `last_error` retains the latest recorded error and is not cleared by recovery.

`scheduled_reads` counts table calls without a `time` constraint, including manual queries. `historical_reads` counts calls with a `time` constraint. They describe the read path, not the caller's identity. Status counters reset when the extension process restarts. If `unsupported_messages` rises while `received_events` stays zero, the collector is receiving log messages but their format is not supported by the parser. An `osqueryi` session configured to load this extension with events enabled starts a separate collector; use a connection to the daemon socket when diagnosing the running daemon.

The source reconnects with a delay that grows from 1 to 30 seconds and resets correlation before a new subscription. osqueryd manages the extension lifecycle. On normal shutdown, callbacks are disabled and accepted rows are drained while the host database is still available. A crash, loss of the host, or expiry of the SDK shutdown timeout can prevent the final drain.

## Source map and references

| File | Purpose |
|---|---|
| `src/main.cpp` | Registration, host flag import, and EventFactory lifecycle |
| `src/native_stream.mm` | Private live-log subscription and callback lifetime |
| `src/parser.cpp` | Message parsing and correlation |
| `src/events.cpp` | Queue, publisher, subscriber, SQL adapter, and status |
| `scripts/build.sh` | Build using the pinned osquery SDK |
| `scripts/patch-sdk.py` | Boost MPL compatibility patch for modern Clang |

The build pins osquery 5.23.1 at commit `b7538338fa5bf3baeb11d660e0053b5919ed86e2`. It applies the compile-time workaround from [Boost MPL #77](https://github.com/boostorg/mpl/pull/77); it does not patch the SDK event framework.

Technical references: [osquery EventSubscriber](https://github.com/osquery/osquery/blob/5.23.1/osquery/events/eventsubscriberplugin.cpp), [SDK database proxy](https://github.com/osquery/osquery/blob/5.23.1/osquery/database/database.cpp), [Apple mDNSResponder message source](https://github.com/apple-oss-distributions/mDNSResponder/blob/main/mDNSShared/uds_daemon.c), and [LoggingSupport interface declarations in OverSight](https://github.com/objective-see/OverSight/blob/main/Application/Application/LogMonitor.h).

## Development

The target macOS releases are Sequoia, Tahoe and Golden Gate. Parsing follows the message structure rather than the OS name: offline regression fixtures cover hexadecimal hashes, privacy placeholders and tagged `<dn:...>`/`<rd:...>` values. The collector has been validated live with osquery 5.23.1 on macOS 26.6.2 arm64; the tagged layout is also checked against an affected host sample. Live checks on each target OS build are still needed because the logging API is private. The deployment target of 14.0 is a build setting, not a runtime compatibility guarantee.

The build script accepts `DNS_BUILD_JOBS` to control parallelism, `DNS_CACHE_DIR` for a dedicated SDK cache, and `SDKROOT` to select an installed macOS SDK. Use an SDK compatible with the toolchain; SDK 26.5 was used for the original validation. Build for the target architecture and apply your distribution signing process before deployment. Include the required dependency licenses and notices with binary distributions.

Offline tests require a C++17 compiler, CMake 3.21+ and Python 3.9+. They do not download the SDK or modify osquery:

```bash
cmake -S tests -B build/tests -DCMAKE_BUILD_TYPE=Release
cmake --build build/tests
ctest --test-dir build/tests --output-on-failure
```

With osquery installed and the extension built, run the optional live integration test:

```bash
python3 tests/integration.py --requests 1000
```

It uses an isolated daemon and database to check DNS correlation, independent schedule cursors, extension recovery and persistence. Masked values are accepted by default; `--require-unredacted` requires readable names. See `--help` for binary paths and temporary-state options. Live tests require macOS log access and resolution of `example.com`. They do not install a profile or restart the system service. Diagnostic files are retained in a temporary directory by default and can contain DNS activity.

Set `DNS_ENABLE_LIVE_TESTS=ON` in the test CMake configuration to include the native-source lifecycle test.
