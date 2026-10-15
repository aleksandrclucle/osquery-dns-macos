// Copyright 2026 DNS Events contributors
// SPDX-License-Identifier: Apache-2.0

#include "events.h"
#include "native_stream.h"
#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/utils/system/time.h>
#include <thread>
#include <unistd.h>

namespace osquery {
DECLARE_bool(events_optimize);
DECLARE_uint64(events_expiry);
DECLARE_uint64(events_max);
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
    "stream_queue_bytes",   "peak_stream_queue_bytes"};
} // namespace

DNSHealth &dnsHealth() {
  static DNSHealth h;
  return h;
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
  r["events_expiry"] = std::to_string(FLAGS_events_expiry);
  r["events_max"] = std::to_string(FLAGS_events_max);
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
  while (!isEnding()) {
    const auto now = dns::Clock::now();
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
  auto status = addBatch(rows);
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
bool DNSSubscriber::shouldOptimize() const { return FLAGS_events_optimize; }
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
  EventFactory::getEventSubscriber("dns_events")->genTable(yield, context);
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
  return tableRowsFromQueryData({dnsHealth().row()});
}
} // namespace osquery
