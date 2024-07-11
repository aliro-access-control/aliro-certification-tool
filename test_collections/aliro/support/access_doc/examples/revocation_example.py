#
# Copyright (c) 2024 Aliro Authors
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
#

import datetime
import os
import sys

# Get the directory in which this file is located.
current_file_dir_path = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))

# Get the directory in which the source code is located.
source_dir_path = os.path.abspath(os.path.join(current_file_dir_path, '..'))

# Append the parent path to the system paths, so the code in the directory
# above may be imported.
sys.path.append(source_dir_path)

from revocation_data import RevocationData
from revocation_data import RevocationChangeMode
from revocation_entry import RevocationEntry
from revocation_extension import RevocationExtension
from extension_data_example import ExtensionDataExample

from utility import Utility

from mdl.device_response_builder import DeviceResponseBuilder

# Setup the root revocation data object.
revocation_data = RevocationData()
revocation_data.version = 1
revocation_data.change_mode = RevocationChangeMode.OVERWRITE

# Setup a revocation entry.
entry1 = RevocationEntry()
entry1.public_key_hash = bytearray(range(1, 33))
entry1.id.extend([0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF])
entry1.expiry_time = Utility.time_val_to_seconds(datetime.datetime.now(datetime.timezone.utc)) + 90 * 24 * 3600

# Setup a revocation entry.
entry2 = RevocationEntry()
entry2.public_key_hash = bytearray(range(100, 132))
entry2.id.extend(range(0xAB, 0xBB))
entry2.expiry_time = Utility.time_val_to_seconds(datetime.datetime.now(datetime.timezone.utc)) + 7 * 24 * 3600

# Setup a revocation entry to remove.
entry3 = RevocationEntry()
entry3.public_key_hash = bytearray(range(200, 232))
entry3.id.extend(range(0xCB, 0xDB))

# Setup a revocation entry to remove.
entry4 = RevocationEntry()
entry4.public_key_hash = bytearray(range(40, 72))
entry4.id.extend(range(0x30, 0x36))

# Append the revocation entries.
revocation_data.entries.append(entry1)
revocation_data.entries.append(entry2)

# Append the revocation entries to remove.
revocation_data.entries_to_remove.append(entry3)
revocation_data.entries_to_remove.append(entry4)

# Setup a revocation extension.
vendorRegisteredId = 0xABCDEF
revocation_extension = RevocationExtension()
revocation_extension.id = 321
revocation_extension.version = 9
revocation_extension.data = ExtensionDataExample()
revocation_extension.data.value1 = 1
revocation_extension.data.value2 = 2
revocation_data.revocation_extensions[vendorRegisteredId] = [revocation_extension]

# Output the Revocation Data in JSON, CBOR, and TLV.
print("\nRevocation Data Element")
print("json: " + revocation_data.to_json() + "\n")
cbor = revocation_data.to_cbor()
print("cbor: " + Utility.bytes_to_hex_str(cbor) + "\n")
tlv = revocation_data.to_tlv()
print("tlv: " + Utility.bytes_to_hex_str(tlv) + "\n")

# Build a Device Response containing the Revocation Data Element.
device_response = DeviceResponseBuilder.build(None, [revocation_data])

print("Device Response")
cbor = device_response.to_cbor()
if (cbor is not None):
    print("cbor: " + Utility.bytes_to_hex_str(cbor) + "\n")
