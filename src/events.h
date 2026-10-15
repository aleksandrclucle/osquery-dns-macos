// Copyright 2026 DNS Events contributors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include "parser.h"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <osquery/events/eventpublisher.h>
#include <osquery/events/eventsubscriber.h>

namespace osquery {
struct DNSSubscriptionContext : SubscriptionContext {};
struct DNSContext : EventContext {
  std::vector<Row> rows;
};

struct DNSHealth {
  std::mutex mutex;
  std::map<std::string, std::uint64_t> counters;
  std::string last_error;
  void increment(const std::string &, std::uint64_t n = 1);
  void set(const std::string &, std::uint64_t);
  void error(const std::string &);
  Row row();
};
DNSHealth &dnsHealth();

class DNSPublisher final
    : public EventPublisher<DNSSubscriptionContext, DNSContext> {
  DECLARE_PUBLISHER("mdns_stream")
public:
  Status setUp() override;
  Status run() override;

private:
  void record(const dns::Input &);
  void flush();
  void readLoop();
  void enqueue(dns::Input, bool reset = false);
  struct Frame {
    dns::Input input;
    bool reset;
  };
  std::mutex queue_mutex_;
  std::condition_variable queue_ready_;
  std::deque<Frame> queue_;
  std::size_t queue_bytes_{0}, peak_queue_bytes_{0};
  std::atomic<bool> reader_done_{false};
  dns::Parser parser_;
  std::vector<Row> batch_;
  dns::Clock::time_point last_flush_{dns::Clock::now()}, retry_at_{},
      source_started_{};
  unsigned int backoff_{1};
};

class DNSSubscriber final : public EventSubscriber<DNSPublisher> {
public:
  Status init() override;
  Status callback(const ECRef &, const SCRef &);
  // ToolType::EXTENSION is not a daemon. Use the core's executing-query
  // context and the native EventSubscriber optimization in this process too.
  bool shouldOptimize() const override;
};

class DNSTable final : public TablePlugin {
public:
  TableColumns columns() const override;
  TableAttributes attributes() const override {
    return TableAttributes::EVENT_BASED;
  }
  bool usesGenerator() const override { return true; }
  void generator(RowYield &, QueryContext &) override;
  TableRows generate(QueryContext &) override;
};
class DNSStatusTable final : public TablePlugin {
public:
  TableColumns columns() const override;
  TableRows generate(QueryContext &) override;
};
} // namespace osquery
