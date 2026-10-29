// Copyright 2026 DNS Events contributors
// SPDX-License-Identifier: Apache-2.0

#include "events.h"
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/events/events.h>
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
} // namespace osquery

int main(int argc, char *argv[]) {
  using namespace osquery;
  Initializer runner(argc, argv, ToolType::EXTENSION);
  // The SDK reports its build version; no unverified host minimum is declared.
  auto status = startExtension("dns_events", "0.3.4");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    return runner.shutdown(status.getCode());
  }
  try {
    readHostSettings();
    // Keep the local factory alive so a later host configuration can enable
    // collection. The publisher controls its source using the host setting.
    Flag::updateValue("disable_events", "false");
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
