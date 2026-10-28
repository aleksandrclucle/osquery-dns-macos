// Copyright 2026 DNS Events contributors
// SPDX-License-Identifier: Apache-2.0

#include "host_settings.h"
#include <cassert>
#include <functional>
#include <thread>

namespace {
void rejects(const std::function<void()> &function) {
  bool rejected = false;
  try {
    function();
  } catch (const std::exception &) {
    rejected = true;
  }
  assert(rejected);
}
} // namespace

int main() {
  std::map<std::string, std::string> options{{"disable_events", "false"},
                                             {"events_optimize", "true"},
                                             {"events_expiry", "3600"},
                                             {"events_max", "50000"}};
  const auto first = dns::parseHostSettings(options);
  assert(!first.disabled && first.optimize);
  assert(first.expiry == 3600 && first.max_batches == 50000);

  assert(dns::HostSettingsScope::current() == nullptr);
  {
    const dns::HostSettingsScope outer(first);
    assert(dns::HostSettingsScope::current()->optimize);
    {
      auto changed = first;
      changed.optimize = false;
      const dns::HostSettingsScope inner(changed);
      assert(!dns::HostSettingsScope::current()->optimize);
    }
    assert(dns::HostSettingsScope::current()->optimize);
    rejects([&] {
      const dns::HostSettingsScope inner(first);
      throw std::runtime_error("Interrupted read");
    });
    assert(dns::HostSettingsScope::current()->optimize);
    std::thread writer([&] {
      assert(dns::HostSettingsScope::current() == nullptr);
      auto changed = first;
      changed.optimize = false;
      const dns::HostSettingsScope operation(changed);
      assert(!dns::HostSettingsScope::current()->optimize);
    });
    writer.join();
    assert(dns::HostSettingsScope::current()->optimize);
  }
  assert(dns::HostSettingsScope::current() == nullptr);

  options["disable_events"] = "1";
  options["events_optimize"] = "0";
  options["events_expiry"] = "0";
  options["events_max"] = "18446744073709551615";
  const auto second = dns::parseHostSettings(options);
  assert(second.disabled && !second.optimize);
  assert(second.expiry == 0);
  assert(second.max_batches == std::numeric_limits<std::uint64_t>::max());

  for (const auto *value : {"", "-1", "12x", " 3", "18446744073709551616"}) {
    options["events_expiry"] = value;
    rejects([&] { dns::parseHostSettings(options); });
  }
  options["events_expiry"] = "3600";
  options["events_optimize"] = "invalid";
  rejects([&] { dns::parseHostSettings(options); });
  options["events_optimize"] = "true";
  options.erase("events_max");
  rejects([&] { dns::parseHostSettings(options); });
  // Invalid refreshes cannot modify the previously parsed snapshot.
  assert(first.expiry == 3600 && first.max_batches == 50000);
}
