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

import cbor2

################################################################################
class Sig_structure(object):

    ############################################################################
    def __init__(self) -> None:
        self.context = 'Signature1'
        self.body_protected = bytearray()
        self.external_aad = bytearray()
        self.payload = None

    ############################################################################
    def to_list(self) -> list:
        '''Convert the Sig_structure to a list.'''
        sig_list = []

        # Encode the Context.
        sig_list.append(self.context)

        # Encode the Body Protected.
        sig_list.append(self.body_protected)

        # Encode the External AAD.
        sig_list.append(self.external_aad)

        # Encode the Data.
        sig_list.append(self.payload)

        return sig_list

    ############################################################################
    def to_cbor(self) -> bytes:
        '''Convert the Sig_structure to CBOR.'''
        sig_list = self.to_list()
        if sig_list is None:
            return None
        return cbor2.dumps(sig_list)
