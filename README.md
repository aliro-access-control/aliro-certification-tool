<!--
 *
 * Copyright (c) 2024-2026 Aliro Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
-->

# Aliro Certification Tool

A Test Harness and tooling designed to simplify development, testing, and certification of Aliro devices, guided by the Connectivity Standards Alliance Aliro Working Group.

The tool reuses the CSA Matter Test Harness frontend, backend, and reverse-proxy stack, with Aliro-specific test cases and hardware actuation layered on top in `test_collections/aliro/`. It runs on a Raspberry Pi 4 with an NXP NFC EVK and (optionally) a Murata BLE/UWB EVK, and is operated through a web browser on the same LAN.

## Documentation

| Document                                          | What's inside                                                                                  |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| **[SETUP.md](docs/SETUP.md)**                          | First-time setup: hardware, SD-card flashing, assembly, install, and first start.              |
| **[USER_MANUAL.md](docs/USER_MANUAL.md)**              | Operating guide: GUI walkthrough, test parameters, updating, troubleshooting.                  |
| **[ARCHITECTURE.md](docs/ARCHITECTURE.md)**            | Internal design: deployment stack, actuator layering, test collections, hardware integration.  |
| **[CONTRIBUTION.md](CONTRIBUTION.md)**            | How to propose changes, the Tiger Team review process, and PR requirements.                    |
| **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)**      | Community guidelines.                                                                          |
| **[LICENSE](LICENSE)**                            | Apache 2.0 license terms.                                                                      |

## Version Matrix

| Component                  | Version                                       |
| -------------------------- | --------------------------------------------- |
| Tool release tag           | `aliro-sve-v1.0`                              |
| Aliro Specification        | 1.0                                           |
| Aliro CSG TT Test Plan     | 1.0 (for Aliro 1.0)                           |
| Host OS                    | Ubuntu Server 22.04.x LTS (64-bit)            |
| Host hardware              | Raspberry Pi 4 Model B (8 GB recommended)     |
| Supported NFC HAT          | NXP OM27160B1EVK (SPI) / OM27160A1EVK (I2C) — Raspberry Pi GPIO HAT |
| Supported BLE/UWB module   | Murata LBUA0VG2BP-EVK-P — USB-attached        |

## Quick Start

The full procedure is in **[SETUP.md](docs/SETUP.md)**. At a glance:

1. Flash Ubuntu Server 22.04 onto a 16 GB+ micro SD card with Raspberry Pi Imager, set hostname / username / password, and enable SSH. See [§3](docs/SETUP.md#3-installing-ubuntu-on-sd-card).
2. Seat the NXP NFC HAT on the Pi's GPIO header (and optionally connect the Murata BLE/UWB USB module), then boot. See [§4](docs/SETUP.md#4-assembling-the-raspberry-pi).
3. SSH into the Pi, add its SSH key to your GitHub account, then clone and run the auto-installer:
   ```sh
   git clone git@github.com:aliro-access-control/aliro-certification-tool.git
   cd aliro-certification-tool
   ./scripts/pi-setup/auto-install.sh
   ```
   See [§6](docs/SETUP.md#6-installing-the-aliro-test-harness).
4. After reboot, initialise the submodules, then set up and start the Test Harness:
   ```sh
   cd ~/aliro-certification-tool
   git submodule update --init --recursive
   cd test_collections/aliro && ./setup.sh
   cd ~/aliro-certification-tool && ./scripts/start.sh
   ```
   See [§7](docs/SETUP.md#7-starting-the-aliro-test-harness).
5. Open `http://<pi-ip-address>` in a browser on the same LAN, create a project, and run a test suite. See [USER_MANUAL.md §3](docs/USER_MANUAL.md#3-using-the-test-harness).

## Goals

The Aliro Test Harness is designed around the same principles as the upstream CSA Matter tooling:

- **Proven** — built on existing, well-tested components where possible.
- **Robust** — reliable enough for use in certification labs.
- **Low cost** — runs on a commodity Raspberry Pi 4 with off-the-shelf NFC and BLE/UWB EVKs.
- **Flexible** — adaptable to different network and deployment environments.
- **Easy to use** — operated through a single web UI, with no command-line interaction during a test run.
- **Open** — design and processes are open to all CSA members.

## Related Repositories

- [Aliro Actuator](https://github.com/aliro-access-control/aliro-actuator) — firmware and protocol implementation that runs on the BLE/UWB and NFC front-end boards.

## Minimum Hardware Requirements

- SD card 16 GB or more.
- Raspberry Pi 4 with at least 4 GB RAM (8 GB recommended).
- NXP NFC HAT — OM27160B1EVK (SPI) **or** OM27160A1EVK (I2C). Sits on the Pi's 40-pin GPIO header.
- Murata LBUA0VG2BP-EVK-P BLE/UWB module (USB-attached) — only for BLE/UWB transport testing.

## License

Released under the [Apache 2.0 License](LICENSE).
