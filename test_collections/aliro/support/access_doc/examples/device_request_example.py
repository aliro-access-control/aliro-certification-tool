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

import os
import sys

# Get the directory in which this file is located.
current_file_dir_path = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))

# Get the directory in which the source code is located.
source_dir_path = os.path.abspath(os.path.join(current_file_dir_path, '..'))

# Append the parent path to the system paths, so the code in the directory
# above may be imported.
sys.path.append(source_dir_path)

# Change the working directory to the directory above the 'examples' directory.
os.chdir(source_dir_path)

from request.device_request_builder import RequestElement
from request.device_request_builder import DeviceRequestBuilder
from utility import Utility

access_request = RequestElement(data_element_id='b1.f2', intent_to_retain=False)
revocation_request = RequestElement(data_element_id='b2', intent_to_retain=True)

device_request = DeviceRequestBuilder.build([access_request], [revocation_request])

print("\nDevice Request")
cbor = device_request.to_cbor()
if (cbor is not None):
    print("cbor: " + Utility.bytes_to_hex_str(cbor) + "\n")
