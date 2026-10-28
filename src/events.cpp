// Copyright 2026 DNS Events contributors
// SPDX-License-Identifier: Apache-2.0

#include "events.h"
#include "native_stream.h"
#include <algorithm>
#include <osquery/core/flags.h>
#include <osquery/extensions/interface.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/utils/system/time.h>
#include <thread>
#include <unistd.h>

namespace osquery {
DECLARE_string(extensions_socket);
namespace {
constexpr std::size_t batchSize = 128;
const std::vector<std::string> healthKeys = {
    "stream_running",       "stream_pid",
    "stream_starts",        "stream_restarts",
    "received_events",      "stored_events",
    "write_errors",         "write_drops",
    "loss_notices",         "redacted_events",
    "last_event_time",      "last_commit_time",
    "pending_requests",     "correlation_evictions",
    "unsupported_messages", "uncorrelated_results",
    "subscriber_active",    "scheduled_reads",
    "historical_reads",     "stream_queue_drops",
    "stream_queue_bytes",   "peak_stream_queue_bytes",
    "disable_events",       "events_optimize"};
} // namespace

DNSHealth &dnsHealth() {
  static DNSHealth h;
  return h;
}
dns::HostSettings readHostSettings() {
  ExtensionManagerClient client(FLAGS_extensions_socket, 2);
  const auto options = client.options();
  std::map<std::string, std::string> values;
  for (const auto *name :
       {"disable_events", "events_optimize", "events_expiry", "events_max"}) {
    const auto found = options.find(name);
    if (found == options.end()) {
      throw std::runtime_error("Host event settings are incomplete");
    }
    values.emplace(name, found->second.value);
  }
  const auto settings = dns::parseHostSettings(values);
  dnsHealth().settings(settings);
  return settings;
}
void DNSHealth::settings(const dns::HostSettings &settings) {
  std::lock_guard<std::mutex> lock(mutex);
  counters["disable_events"] = settings.disabled;
  counters["events_optimize"] = settings.optimize;
  counters["events_expiry"] = settings.expiry;
  counters["events_max"] = settings.max_batches;
}
void DNSHealth::increment(const std::string &k, std::uint64_t n) {
  std::lock_guard<std::mutex> l(mutex);
  counters[k] += n;
}
void DNSHealth::set(const std::string &k, std::uint64_t n) {
  std::lock_guard<std::mutex> l(mutex);
  counters[k] = n;
}
void DNSHealth::error(const std::string &e) {
  std::lock_guard<std::mutex> l(mutex);
  last_error = e.substr(0, 512);
}
Row DNSHealth::row() {
  std::lock_guard<std::mutex> l(mutex);
  Row r;
  for (const auto &k : healthKeys) {
    r[k] = std::to_string(counters[k]);
  }
  r["last_error"] = last_error;
  r["events_expiry"] = std::to_string(counters["events_expiry"]);
  r["events_max"] = std::to_string(counters["events_max"]);
  r["framework"] = "osquery EventPublisher/EventSubscriber";
  r["stream_backend"] = "in-process OSLogEventLiveStream";
  return r;
}

Status DNSPublisher::setUp() {
  batch_.reserve(batchSize);
  return Status::success();
}
void DNSPublisher::record(const dns::Input &input) {
  auto row = parser_.parse(input);
  dnsHealth().set("pending_requests", parser_.pending());
  dnsHealth().set("correlation_evictions", parser_.evicted);
  dnsHealth().set("unsupported_messages", parser_.unsupported);
  dnsHealth().set("uncorrelated_results", parser_.uncorrelated);
  if (!row) {
    return;
  }
  dnsHealth().increment("received_events");
  dnsHealth().set("last_event_time", getUnixTime());
  if (row->at("redacted") == "1") {
    dnsHealth().increment("redacted_events");
  }
  batch_.push_back(std::move(*row));
  if (batch_.size() >= batchSize) {
    flush();
  }
}
void DNSPublisher::flush() {
  if (!batch_.empty()) {
    auto ec = createEventContext();
    ec->rows.swap(batch_);
    if (isEnding()) {
      // EventPublisher::fire rejects new publications once shutdown starts.
      // Drain already accepted rows while the subscriber and core DB still
      // exist.
      auto sub = std::dynamic_pointer_cast<DNSSubscriber>(
          EventFactory::getEventSubscriber("dns_events"));
      if (sub) {
        sub->callback(ec, createSubscriptionContext());
      }
    } else {
      fire(ec);
    }
    batch_.reserve(batchSize);
  }
  last_flush_ = dns::Clock::now();
  parser_.prune(last_flush_);
  dnsHealth().set("pending_requests", parser_.pending());
  dnsHealth().set("correlation_evictions", parser_.evicted);
}
void DNSPublisher::enqueue(dns::Input input, bool reset) {
  constexpr std::size_t maxQueueBytes = 16 * 1024 * 1024, maxFrames = 8192;
  std::lock_guard<std::mutex> lock(queue_mutex_);
  if (reset && queue_.size() >= maxFrames) {
    queue_bytes_ -= queue_.front().input.message.size() +
                    queue_.front().input.timestamp.size();
    queue_.pop_front();
    dnsHealth().increment("stream_queue_drops");
  }
  if (queue_.size() >= maxFrames ||
      queue_bytes_ + input.message.size() + input.timestamp.size() >
          maxQueueBytes) {
    dnsHealth().increment("stream_queue_drops");
    return;
  }
  queue_bytes_ += input.message.size() + input.timestamp.size();
  peak_queue_bytes_ = std::max(peak_queue_bytes_, queue_bytes_);
  queue_.push_back({std::move(input), reset});
  dnsHealth().set("stream_queue_bytes", queue_bytes_);
  dnsHealth().set("peak_stream_queue_bytes", peak_queue_bytes_);
  queue_ready_.notify_one();
}

void DNSPublisher::readLoop() {
  dns::NativeLogStream source;
  bool was_active = false;
  bool disabled = true;
  bool configuration_ready = false;
  auto refresh_at = dns::Clock::time_point{};
  while (!isEnding()) {
    const auto now = dns::Clock::now();
    if (now >= refresh_at) {
      try {
        disabled = readHostSettings().disabled;
      } catch (const std::exception &) {
        disabled = true;
        dnsHealth().error("Cannot refresh host event configuration");
      }
      try {
        auto subscriber = std::dynamic_pointer_cast<DNSSubscriber>(
            EventFactory::getEventSubscriber("dns_events"));
        if (subscriber) {
          subscriber->refreshSchedule();
          configuration_ready = subscriber->configurationReady();
        }
      } catch (const std::exception &) {
        dnsHealth().error("Cannot refresh host event schedule");
      }
      refresh_at = dns::Clock::now() + std::chrono::seconds(1);
    }
    if (disabled || !configuration_ready) {
      if (was_active) {
        source.stop();
        enqueue({}, true);
        dnsHealth().set("stream_running", 0);
        dnsHealth().set("stream_pid", 0);
        was_active = false;
      }
      pause(std::chrono::milliseconds(200));
      continue;
    }
    if (!source.active()) {
      if (was_active) {
        source.stop();
        dnsHealth().set("stream_running", 0);
        dnsHealth().set("stream_pid", 0);
        dnsHealth().increment("stream_restarts");
        if (now - source_started_ > std::chrono::minutes(1)) {
          backoff_ = 1;
        }
        retry_at_ = now + std::chrono::seconds(backoff_);
        backoff_ = std::min(30U, backoff_ * 2);
        was_active = false;
      }
      if (now >= retry_at_) {
        // Reset correlation before any callback from the new subscription.
        enqueue({}, true);
        std::string error;
        const bool started = source.start(
            {[this](dns::Input input) { enqueue(std::move(input)); },
             [] { dnsHealth().increment("loss_notices"); },
             [](const std::string &message) { dnsHealth().error(message); }},
            error);
        if (started) {
          source_started_ = now;
          dnsHealth().set("stream_running", 1);
          dnsHealth().set("stream_pid", getpid());
          dnsHealth().increment("stream_starts");
          was_active = true;
        } else {
          dnsHealth().error(error);
          retry_at_ = now + std::chrono::seconds(backoff_);
          backoff_ = std::min(30U, backoff_ * 2);
        }
      }
    }
    pause(std::chrono::milliseconds(200));
  }
  source.stop();
  dnsHealth().set("stream_running", 0);
  dnsHealth().set("stream_pid", 0);
  reader_done_ = true;
  queue_ready_.notify_one();
}

Status DNSPublisher::run() {
  std::thread reader([this] { readLoop(); });
  for (;;) {
    Frame frame;
    bool have_frame = false;
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      queue_ready_.wait_for(lock, std::chrono::milliseconds(250), [this] {
        return !queue_.empty() || reader_done_.load();
      });
      if (!queue_.empty()) {
        frame = std::move(queue_.front());
        queue_.pop_front();
        queue_bytes_ -=
            frame.input.message.size() + frame.input.timestamp.size();
        dnsHealth().set("stream_queue_bytes", queue_bytes_);
        have_frame = true;
      } else if (reader_done_) {
        break;
      }
    }
    if (have_frame) {
      if (frame.reset) {
        flush();
        parser_.reset();
      } else {
        record(frame.input);
      }
    }
    if (dns::Clock::now() - last_flush_ >= std::chrono::milliseconds(500)) {
      flush();
    }
  }
  reader.join();
  flush();
  return Status::success();
}
Status DNSSubscriber::init() {
  subscribe(&DNSSubscriber::callback, createSubscriptionContext());
  dnsHealth().set("subscriber_active", 1);
  return Status::success();
}
Status DNSSubscriber::callback(const ECRef &ec, const SCRef &) {
  const auto count = ec->rows.size();
  auto rows = ec->rows;
  Status status;
  try {
    const dns::HostSettingsScope settings(readHostSettings());
    status = addBatch(rows);
  } catch (const std::exception &) {
    status =
        Status(1, "Cannot refresh host event configuration before storage");
  }
  if (status.ok()) {
    dnsHealth().increment("stored_events", count);
    dnsHealth().set("last_commit_time", getUnixTime());
  } else {
    dnsHealth().increment("write_errors");
    dnsHealth().increment("write_drops", count);
    dnsHealth().error(status.getMessage());
  }
  return status;
}
bool DNSSubscriber::shouldOptimize() const {
  const auto *settings = dns::HostSettingsScope::current();
  return settings != nullptr && settings->optimize;
}
size_t DNSSubscriber::getEventsExpiry() {
  // The SDK opens existing event storage before the asynchronous schedule
  // snapshot is available. Do not expire retained rows using a missing floor.
  const auto *settings = dns::HostSettingsScope::current();
  return settings != nullptr && schedule_ready_
             ? std::max<std::uint64_t>(settings->expiry, min_expiry_)
             : 0;
}
size_t DNSSubscriber::getEventBatchesMax() {
  // Registration precedes host config loading. Even a valid flags snapshot
  // can still contain command-line values that the config will override.
  const auto *settings = dns::HostSettingsScope::current();
  return settings != nullptr && schedule_ready_ ? settings->max_batches : 0;
}

void DNSSubscriber::generateRows(RowYield &yield, QueryContext &context) {
  // The SDK consults shouldOptimize twice during a read. Keep one coherent
  // host snapshot through row generation and the cursor update.
  const dns::HostSettingsScope settings(readHostSettings());
  genTable(yield, context);
}

void DNSSubscriber::refreshSchedule() {
  // Run SQL RPC on the reader thread, outside a table callback: the host can
  // already be waiting for a DNS table response on its SQL connection.
  ExtensionManagerClient client(FLAGS_extensions_socket, 2);
  QueryData rows;
  const auto status = client.query(
      "SELECT i.config_valid, s.name, s.query, s.interval FROM osquery_info i "
      "LEFT JOIN osquery_schedule s ON 1;",
      rows);
  if (!status.ok()) {
    throw std::runtime_error("Cannot read the host event schedule");
  }
  if (rows.empty() || rows.front().at("config_valid") != "1") {
    return;
  }
  decltype(schedule_) schedule;
  for (const auto &row : rows) {
    if (row.at("name").empty() && row.at("query").empty()) {
      continue; // A loaded configuration can have an empty schedule.
    }
    schedule.emplace(row.at("name"),
                     std::make_pair(row.at("query"),
                                    dns::unsignedSetting(row.at("interval"))));
  }
  if (schedule_ready_ && schedule == schedule_) {
    return;
  }

  std::size_t query_count = 0;
  std::uint64_t max_interval = 0;
  for (const auto &entry : schedule) {
    PluginResponse tables;
    const auto table_status = client.call(
        "sql", "sql", {{"action", "tables"}, {"query", entry.second.first}},
        tables);
    if (!table_status.ok()) {
      continue; // Match EventFactory::configUpdate for an invalid query.
    }
    if (std::any_of(tables.begin(), tables.end(), [](const auto &table) {
          const auto name = table.find("t");
          return name != table.end() && name->second == "dns_events";
        })) {
      ++query_count;
      max_interval = std::max(max_interval, entry.second.second);
    }
  }
  if (max_interval > (std::numeric_limits<std::size_t>::max() - 60) / 3) {
    throw std::runtime_error("Host event schedule interval is too large");
  }
  auto min_expiry = max_interval * 3;
  if (query_count > 0) {
    min_expiry += 60 - (min_expiry % 60);
  }
  min_expiry_ = min_expiry;
  schedule_ = std::move(schedule);
  schedule_ready_ = true;
}
TableColumns DNSTable::columns() const {
  TableColumns cols;
  for (const auto *k :
       {"time", "client_pid", "responder_pid", "interface_index", "expired",
        "correlated", "redacted"}) {
    cols.push_back({k, BIGINT_TYPE, ColumnOptions::DEFAULT});
  }
  // Native eids are zero-padded strings; BIGINT would trigger octal conversion.
  for (const auto *k :
       {"eid", "timestamp", "kind", "request_id", "question_id", "api",
        "domain", "query_type", "answer", "client_process"}) {
    cols.push_back({k, TEXT_TYPE, ColumnOptions::DEFAULT});
  }
  return cols;
}
void DNSTable::generator(RowYield &yield, QueryContext &context) {
  if (!EventFactory::exists("dns_events")) {
    LOG(ERROR) << "dns_events subscriber is not ready";
    return;
  }
  const bool history = !context.constraints["time"].getAll().empty();
  dnsHealth().increment(history ? "historical_reads" : "scheduled_reads");
  auto subscriber = std::dynamic_pointer_cast<DNSSubscriber>(
      EventFactory::getEventSubscriber("dns_events"));
  subscriber->generateRows(yield, context);
}
TableRows DNSTable::generate(QueryContext &context) {
  // The extension RPC dispatch calls generate(), even for generator-backed
  // tables. Adapt the native subscriber coroutine to the Thrift response.
  TableRows rows;
  RowGenerator::pull_type source(
      [&](RowYield &yield) { generator(yield, context); });
  while (source) {
    rows.push_back(source.get());
    source();
  }
  return rows;
}
Status DNSTable::call(const PluginRequest &request, PluginResponse &response) {
  try {
    return TablePlugin::call(request, response);
  } catch (const std::exception &) {
    response.clear();
    dnsHealth().error("Cannot read DNS events with current host configuration");
    return Status(1, "Cannot read DNS events with current host configuration");
  }
}
TableColumns DNSStatusTable::columns() const {
  TableColumns cols;
  for (const auto &k : healthKeys) {
    cols.push_back({k, BIGINT_TYPE, ColumnOptions::DEFAULT});
  }
  for (const auto *k : {"events_expiry", "events_max"}) {
    cols.push_back({k, BIGINT_TYPE, ColumnOptions::DEFAULT});
  }
  for (const auto *k : {"last_error", "framework", "stream_backend"}) {
    cols.push_back({k, TEXT_TYPE, ColumnOptions::DEFAULT});
  }
  return cols;
}
TableRows DNSStatusTable::generate(QueryContext &) {
  try {
    readHostSettings();
  } catch (const std::exception &) {
    dnsHealth().error("Cannot refresh host event configuration");
  }
  return tableRowsFromQueryData({dnsHealth().row()});
}
} // namespace osquery
