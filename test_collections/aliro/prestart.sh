#! /usr/bin/env bash

#
# Copyright (c) 2023 Aliro Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -ex
COLLECTION_PATH=$(realpath $(dirname "$0"))

# This file is executed on Test Harness launch.
# Can be used to install dependencies or make configurations specific to the Aliro test collection.
# Install PN7160 NFC configuration
cp $COLLECTION_PATH/support/aliro_actuator/third_party/nxp_nfc/linux_libnfc-nci/conf/*.conf /usr/local/etc/

# Install PN7160 NFC drivers
cd $COLLECTION_PATH/support/aliro_actuator/third_party/nxp_nfc/linux_libnfc-nci
make install

# Install ACWG Actuator python dependencies
cd $COLLECTION_PATH/support/aliro_actuator
poetry install --no-root
