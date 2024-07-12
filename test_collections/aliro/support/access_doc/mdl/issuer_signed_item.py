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
import secrets

from access_data import AccessData
from revocation_data import RevocationData
from utility import Utility

################################################################################
class IssuerSignedItem(object):
    '''Aliro Signed Item.'''

    DIGEST_ID_LABEL = "1"
    '''The label for the Digest ID field.'''

    RANDOM_LABEL = "2"
    '''The label for the Random field.'''

    ELEMENT_IDENTIFIER_LABEL = "3"
    '''The label for the Element Identifier field.'''

    ELEMENT_VALUE_LABEL = "4"
    '''The label for the Element Value field.'''

    ############################################################################
    def __init__(self) -> None:
        self.__digest_id : int = 0
        self.__random : bytearray = bytearray(secrets.token_bytes(16))
        self.__element_identifier : str = ""
        self.__element_value : AccessData | RevocationData = None

    ############################################################################
    @property
    def digest_id(self) -> int:
        '''Get the Digest ID for issuer data authentication.'''
        return self.__digest_id

    @digest_id.setter
    def digest_id(self, val : int) -> None:
        '''Set the Digest ID for issuer data authentication.'''
        assert(isinstance(val, int))
        if (val < 0):
            val = 0
        self.__digest_id = int(val)

    ############################################################################
    @property
    def random(self) -> bytearray:
        '''Get the Random value for issuer data authentication.'''
        return self.__random

    @random.setter
    def random(self, val : bytes | bytearray) -> None:
        '''Set the Random value for issuer data authentication.'''
        assert(isinstance(val, (bytes, bytearray)))
        self.__random = bytearray(val)

    ############################################################################
    @property
    def element_identifier(self) -> str:
        '''Get the Element Identifier.'''
        return self.__element_identifier

    @element_identifier.setter
    def element_identifier(self, val : str) -> None:
        '''Set the Element Identifier.'''
        assert(isinstance(val, str))
        self.__element_identifier = str(val)

    ############################################################################
    @property
    def element_value(self) -> AccessData | RevocationData:
        '''Get the Element Value.'''
        return self.__element_value

    @element_value.setter
    def element_value(self, val : AccessData | RevocationData) -> None:
        '''Set the Element Value.'''
        assert(isinstance(val, (AccessData | RevocationData)))
        self.__element_value = val

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the IssuerSignedItem contains valid fields,
           otherwise returns False.'''

        # Verify the Digest ID field.
        if (not isinstance(self.__digest_id, int)):
            return False

        # Verify the Random field.
        if (len(self.__random) == 0):
            return False

        # Verify the Element Identifier field.
        if (len(self.__element_identifier) == 0):
            return False

        # Verify the Element Value field.
        if (self.__element_value is None):
            return False

        return True

    ############################################################################
    def to_dict(self) -> dict:
        '''Convert the IssuerSignedItem to a dictionary.'''
        if not self.is_valid():
            return None

        issuer_signed_item_dict = {}

        # Encode the Digest ID field.
        issuer_signed_item_dict[IssuerSignedItem.DIGEST_ID_LABEL] = int(self.__digest_id)

        # Encode the Random field.
        issuer_signed_item_dict[IssuerSignedItem.RANDOM_LABEL] = bytearray(self.__random)

        # Encode the Element Identifier field.
        issuer_signed_item_dict[IssuerSignedItem.ELEMENT_IDENTIFIER_LABEL] = str(self.__element_identifier)

        # Encode the optional Element Value field.
        issuer_signed_item_dict[IssuerSignedItem.ELEMENT_VALUE_LABEL] = self.__element_value.to_dict()

        return issuer_signed_item_dict

    ############################################################################
    def to_cbor(self, cbor_tag : bytes | bytearray = None) -> bytes:
        '''Convert the IssuerSignedItem to CBOR.'''
        issuer_signed_item_dict = self.to_dict()
        if issuer_signed_item_dict is None:
            return None
        cbor = cbor2.dumps(issuer_signed_item_dict)
        if (cbor_tag is not None) and (len(cbor_tag) > 0):
            ba = bytearray(cbor_tag)
            ba.extend(cbor2.dumps(cbor))
            cbor = ba
        return cbor

    ############################################################################
    def to_json(self) -> str:
        '''Convert the IssuerSignedItem to JSON.'''
        issuer_signed_item_dict = self.to_dict()
        if issuer_signed_item_dict is None:
            return None
        Utility.collection_bytes_to_hex_str(issuer_signed_item_dict)
        return json.dumps(issuer_signed_item_dict)

    ############################################################################
    def to_tlv(self) -> bytearray:
        '''Convert the IssuerSignedItem to TLV.'''
        issuer_signed_item_dict = self.to_dict()
        if issuer_signed_item_dict is None:
            return None
        return Utility.dict_to_tlv(issuer_signed_item_dict)
