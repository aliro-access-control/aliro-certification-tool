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

# Assign default value to NXP_TRANSPORT if it was not provided and do uppercase
NXP_TRANSPORT=${NXP_TRANSPORT:="I2C"}
NXP_TRANSPORT=${NXP_TRANSPORT^^}

if ! [[ "$NXP_TRANSPORT" = "SPI" || "$NXP_TRANSPORT" = "I2C" ]]; then
  echo "Error: NXP_TRANSPORT must be 'SPI' or 'I2C'." >&2
  exit 1
fi


# This file is executed on Test Harness Setup.
# Can be used to build dependencies or make configurations specific to the Aliro test collection.

cd $COLLECTION_PATH/support/aliro_actuator
NXP_TRANSPORT=${NXP_TRANSPORT} ./scripts/install_nfc.sh
