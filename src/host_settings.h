// Copyright 2026 DNS Events contributors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>

namespace dns {

struct HostSettings {
  bool disabled{true};
  bool optimize{true};
  std::uint64_t expiry{3600};
  std::uint64_t max_batches{50000};
};

class HostSettingsScope final {
public:
  explicit HostSettingsScope(HostSettings settings)
      : settings_(settings), previous_(current_) {
    current_ = &settings_;
  }
  ~HostSettingsScope() { current_ = previous_; }
  HostSettingsScope(const HostSettingsScope &) = delete;
  HostSettingsScope &operator=(const HostSettingsScope &) = delete;
  static const HostSettings *current() { return current_; }

private:
  const HostSettings settings_;
  const HostSettings *previous_;
  inline static thread_local const HostSettings *current_{nullptr};
};

inline std::uint64_t unsignedSetting(const std::string &value) {
  if (value.empty()) {
    throw std::runtime_error("Empty unsigned host event setting");
  }
  std::uint64_t number = 0;
  for (const auto character : value) {
    if (character < '0' || character > '9' ||
        number >
            (std::numeric_limits<std::uint64_t>::max() - (character - '0')) /
                10) {
      throw std::runtime_error("Invalid unsigned host event setting");
    }
    number = number * 10 + (character - '0');
  }
  return number;
}

inline bool booleanSetting(const std::string &value) {
  if (value == "true" || value == "1") {
    return true;
  }
  if (value == "false" || value == "0") {
    return false;
  }
  throw std::runtime_error("Invalid boolean host event setting");
}

inline HostSettings
parseHostSettings(const std::map<std::string, std::string> &values) {
  // Parse a complete snapshot before exposing any of its values to readers.
  return {booleanSetting(values.at("disable_events")),
          booleanSetting(values.at("events_optimize")),
          unsignedSetting(values.at("events_expiry")),
          unsignedSetting(values.at("events_max"))};
}

} // namespace dns
