// Copyright 2026 DNS Events contributors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <chrono>
#include <map>
#include <optional>
#include <string>

namespace dns {
using Fields = std::map<std::string, std::string>;
using Clock = std::chrono::steady_clock;
struct Input {
  std::string message, timestamp;
  int responder_pid{0};
};

// Only client API messages are parsed. Wire-level resolver messages do not
// reliably identify the requesting process and are intentionally excluded.
class Parser {
public:
  std::optional<Fields> parse(const Input &,
                              Clock::time_point now = Clock::now());
  void reset();
  void prune(Clock::time_point now);
  std::size_t pending() const { return requests_.size(); }
  std::size_t max_pending{4096};
  std::chrono::seconds ttl{600};
  std::uint64_t unsupported{0}, uncorrelated{0}, evicted{0};

private:
  struct Pending {
    Fields fields;
    Clock::time_point seen;
  };
  std::map<std::string, Pending> requests_;
};
} // namespace dns
