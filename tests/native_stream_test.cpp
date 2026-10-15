// Copyright 2026 DNS Events contributors
// SPDX-License-Identifier: Apache-2.0

// Opt-in live macOS test. Works with masked events; a profile is not required.
#include "native_stream.h"
#include <atomic>
#include <cassert>
#include <chrono>
#include <iostream>
#include <netdb.h>
#include <thread>

int main() {
  std::atomic<unsigned> events{0}, errors{0}, losses{0};
  dns::NativeLogStream stream;
  auto resolve = [] {
    addrinfo *result = nullptr;
    assert(getaddrinfo("example.com", "443", nullptr, &result) == 0);
    freeaddrinfo(result);
  };
  for (unsigned generation = 0; generation < 3; ++generation) {
    const auto before = events.load();
    std::string error;
    assert(stream.start({[&](dns::Input input) {
                           assert(!input.message.empty() &&
                                  !input.timestamp.empty());
                           assert(input.responder_pid > 0);
                           ++events;
                         },
                         [&] { ++losses; },
                         [&](const std::string &message) {
                           std::cerr << message << '\n';
                           ++errors;
                         }},
                        error));
    for (unsigned attempt = 0; attempt < 100 && events == before; ++attempt) {
      resolve();
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    assert(stream.active() && events > before);
    stream.stop();
    assert(!stream.active());
    // The next loop immediately starts a fresh subscription on the same object,
    // while the previous invalidation callback may still be queued.
  }
  auto stopped = events.load();
  resolve();
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  assert(events == stopped && errors == 0 && losses == 0);
  std::cout << "native stream: three subscriptions, no stale invalidation, no "
               "callback after stop PASS\n";
}
