// Copyright 2026 DNS Events contributors
// SPDX-License-Identifier: Apache-2.0

#include "events.h"
#include <osquery/core/system.h>
#include <osquery/events/events.h>
#include <osquery/extensions/interface.h>
#include <osquery/sdk/sdk.h>

namespace osquery {
// Only the SQL tables are broadcast. EventFactory lives inside this extension;
// persistence calls are forwarded by the SDK to the host's database plugin.
namespace {
const registries::PI<DNSPublisher> publisher("event_publisher", "mdns_stream",
                                             true);
const registries::PI<DNSSubscriber> subscriber("event_subscriber", "dns_events",
                                               true);
} // namespace
REGISTER_EXTERNAL(DNSTable, "table", "dns_events");
REGISTER_EXTERNAL(DNSStatusTable, "table", "dns_events_status");
DECLARE_string(extensions_socket);
} // namespace osquery

int main(int argc, char *argv[]) {
  using namespace osquery;
  Initializer runner(argc, argv, ToolType::EXTENSION);
  // The SDK reports its build version; no unverified host minimum is declared.
  auto status = startExtension("dns_events", "0.3.2");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    return runner.shutdown(status.getCode());
  }
  try {
    ExtensionManagerClient client(FLAGS_extensions_socket);
    const auto options = client.options();
    // The SDK copies config/logger plugin selection, but not event flags.
    for (const auto *name :
         {"disable_events", "events_optimize", "events_expiry", "events_max"}) {
      const auto it = options.find(name);
      if (it != options.end()) {
        Flag::updateValue(name, it->second.value);
      }
    }
    // Do not call Config::update here: in an extension it writes back to core.
    // Events use the core's flags and database without owning its
    // config/schedule.
    attachEvents();
    EventFactory::delay();
    runner.waitForShutdown();
    // SDK shutdown bounds cleanup with its alarm and stops incoming RPC before
    // draining event publishers. The host database remains available to them.
    return runner.shutdown(0);
  } catch (const std::exception &e) {
    LOG(ERROR) << e.what();
    return runner.shutdown(1);
  }
}
