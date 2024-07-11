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
import copy
import json

from mobile_security_object import MobileSecurityObject
from utility import Utility

################################################################################
class IssuerSigned(object):
    '''Aliro Issuer Signed'''

    NAMESPACES_LABEL = "1"
    '''The label for the Namespaces field.'''

    ISSUER_AUTH_LABEL = "2"
    '''The label for the Issuer Auth field.'''

    ############################################################################
    def __init__(self) -> None:
        self.__namespaces : dict[str, bytearray]
        self.__issuer_auth : MobileSecurityObject = MobileSecurityObject()

    ############################################################################
    @property
    def namespaces(self) ->  dict[str, bytearray]:
        '''Get the namespaces.'''
        return self.__namespaces

    ############################################################################
    @property
    def issuer_auth(self) -> MobileSecurityObject:
        '''Get the Issuer Auth field.'''
        return self.__issuer_auth

    @issuer_auth.setter
    def issuer_auth(self, val : MobileSecurityObject) -> None:
        '''Set the Issuer Auth field.'''
        assert(isinstance(val, MobileSecurityObject))
        self.__issuer_auth = val

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the IssuerSigned contains valid fields,
           otherwise returns False.'''

        # Verify the Namespaces field.
        if (len(self.__namespaces) == 0):
            return False

        # Verify the Issuer Auth field.
        if not self.__issuer_auth.is_valid():
            return False

        return True

    ############################################################################
    def to_dict(self) -> dict:
        '''Convert the IssuerSigned to a dictionary.'''
        if not self.is_valid():
            return None

        issuer_signed_dict = {}

        # Encode the Namespaces field.
        issuer_signed_dict[IssuerSigned.NAMESPACES_LABEL] = copy.deepcopy(self.__namespaces)

        # Encode the Issuer Auth field.
        issuer_signed_dict[IssuerSigned.ISSUER_AUTH_LABEL] = self.__issuer_auth.to_dict()

        return issuer_signed_dict

    ############################################################################
    def to_cbor(self) -> bytes:
        '''Convert the IssuerSigned to CBOR.'''
        issuer_signed_dict = self.to_dict()
        if issuer_signed_dict is None:
            return None
        return cbor2.dumps(issuer_signed_dict)

    ############################################################################
    def to_json(self) -> str:
        '''Convert the IssuerSigned to JSON.'''
        issuer_signed_dict = self.to_dict()
        if issuer_signed_dict is None:
            return None
        Utility.collection_bytes_to_hex_str(issuer_signed_dict)
        return json.dumps(issuer_signed_dict)

    ############################################################################
    def to_tlv(self) -> bytearray:
        '''Convert the IssuerSigned to TLV.'''
        issuer_signed_dict = self.to_dict()
        if issuer_signed_dict is None:
            return None
        return Utility.dict_to_tlv(issuer_signed_dict)
