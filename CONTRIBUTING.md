# Contributing

Run the [offline tests](docs/implementation.md#development) before proposing a change. Parser changes should include synthetic fixtures for supported, masked and malformed input. Do not commit DNS captures, device identifiers, profiles from an organization, build artifacts or SDK caches.

For source or lifecycle changes, also run the opt-in live tests on macOS. Include the OS version, architecture, osquery version and whether private logging was enabled. Remove personal domains, IP addresses, PIDs and paths from reports before sharing them.

Changes should preserve bounded queues, observable failures, scheduled-query cursors and clean shutdown. Update the documentation when changing behavior or installation steps. All project documentation is in English.

Contributions are provided under the project's Apache-2.0 license. Dependencies keep their upstream licenses.
