// Copyright 2026 DNS Events contributors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include "parser.h"
#include <functional>
#include <memory>

namespace dns {
// Live events are decoded in this process. There is no CLI helper or history
// scan. The implementation checks the private macOS API before activating it.
class NativeLogStream {
public:
  struct Callbacks {
    std::function<void(Input)> input;
    std::function<void()> loss;
    std::function<void(const std::string &)> error;
  };
  NativeLogStream();
  ~NativeLogStream();
  bool start(Callbacks callbacks, std::string &error);
  void stop();
  bool active() const;
  NativeLogStream(const NativeLogStream &) = delete;
  NativeLogStream &operator=(const NativeLogStream &) = delete;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
} // namespace dns
