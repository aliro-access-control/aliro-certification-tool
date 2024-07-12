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
import json

from .cose_sign1 import COSE_Sign1
from utility import Utility

################################################################################
class IssuerSigned(object):
    '''Aliro Issuer Signed.'''

    NAMESPACES_LABEL = "1"
    '''The label for the Namespaces field.'''

    ISSUER_AUTH_LABEL = "2"
    '''The label for the Issuer Auth field.'''

    ############################################################################
    def __init__(self) -> None:
        self.__namespaces : dict[str, list[bytearray]] = {} # Where bytearray is IssuerSignedItemBytes
        self.__issuer_auth : COSE_Sign1 = COSE_Sign1()

    ############################################################################
    @property
    def namespaces(self) -> dict[str, list[bytearray]]: # Where bytearray is IssuerSignedItemBytes
        '''Get the namespaces.'''
        return self.__namespaces

    ############################################################################
    @property
    def issuer_auth(self) -> COSE_Sign1:
        '''Get the Issuer Auth field.'''
        return self.__issuer_auth

    @issuer_auth.setter
    def issuer_auth(self, val : COSE_Sign1) -> None:
        '''Set the Issuer Auth field.'''
        assert(isinstance(val, COSE_Sign1))
        self.__issuer_auth = val

    ############################################################################
    def set(self, namespace : str, issuer_signed_item : bytes | bytearray):
        assert(isinstance(namespace, str))
        assert(isinstance(issuer_signed_item, (bytes, bytearray)))
        if namespace in self.__namespaces:
            self.__namespaces[namespace].append(bytearray(issuer_signed_item))
        else:
            self.__namespaces[namespace] = [bytearray(issuer_signed_item)]

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
        namespaces_dict = {}
        for namespace, issuer_signed_items in self.__namespaces.items():
            issuer_signed_items_list = []
            for issuer_signed_item in issuer_signed_items:
                issuer_signed_items_list.append(issuer_signed_item)
            if (len(issuer_signed_items_list) > 0):
                namespaces_dict[namespace] = issuer_signed_items_list
        if (len(namespaces_dict) > 0):
            issuer_signed_dict[IssuerSigned.NAMESPACES_LABEL] = namespaces_dict

        # Encode the Issuer Auth field.
        issuer_signed_dict[IssuerSigned.ISSUER_AUTH_LABEL] = self.__issuer_auth.to_list()

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
