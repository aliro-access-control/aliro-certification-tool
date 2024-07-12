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

from utility import Utility

################################################################################
class COSE_Sign1(object):

    KEY_ID_LABEL = 4
    '''The label for the Key ID (kid) field.'''

    X5CHAIN_CERTIFICATE_LABEL = 33
    '''The label for the x5 certification chain field.'''

    PROTECTED_DEFAULT = bytearray([0xA1, 0x01, 0x26])
    '''The default protected field value.'''

    ############################################################################
    def __init__(self) -> None:
        self.__protected : bytearray = COSE_Sign1.PROTECTED_DEFAULT
        self.__key_id : bytearray = bytearray()
        self.__x5chain = None
        self.__payload : bytearray = bytearray()
        self.__signature : bytearray = bytearray()

    ############################################################################
    @property
    def protected(self) -> bytearray:
        '''
        Get the protected field. Contains parameters about the current layer
        that are to be cryptographically protected.
        '''
        return self.__protected

    @protected.setter
    def protected(self, val : bytes | bytearray) -> None:
        '''
        Set the protected field. Contains parameters about the current layer
        that are to be cryptographically protected.
        '''
        assert(isinstance(val, (bytes | bytearray)))
        self.__protected = bytearray(val)

    ############################################################################
    @property
    def key_id(self) -> bytearray:
        '''Get the Key ID (kid).'''
        return self.__key_id

    @key_id.setter
    def key_id(self, val : bytes | bytearray) -> None:
        '''Set the Key ID (kid).'''
        assert(isinstance(val, (bytes | bytearray)))
        self.__key_id = bytearray(val)

    ############################################################################
    @property
    def x5chain(self) -> int:
        '''Get the x5 certificate chain.'''
        return self.__x5chain

    @x5chain.setter
    def x5chain(self, val : int) -> None:
        '''Set the x5 certificate chain.'''
        assert(isinstance(val, int))
        self.__x5chain = int(val)

    ############################################################################
    @property
    def payload(self) -> bytearray:
        '''Get the payload.'''
        return self.__payload

    @payload.setter
    def payload(self, val : bytes | bytearray) -> None:
        '''Set the payload.'''
        assert(isinstance(val, (bytes | bytearray)))
        self.__payload = bytearray(val)

    ############################################################################
    @property
    def signature(self) -> bytearray:
        '''Get the signature.'''
        return self.__signature

    @signature.setter
    def signature(self, val : bytes | bytearray) -> None:
        '''Set the signature.'''
        assert(isinstance(val, (bytes | bytearray)))
        self.__signature = bytearray(val)

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the COSE_Sign1 contains valid fields,
           otherwise returns False.'''

        # Verify the Protected field.
        if (len(self.__protected) == 0):
            return False

        # Verify either the Key ID field or the x5 certificate chain field is present.
        if ((self.__key_id is None) or (len(self.__key_id) == 0)) and ((self.__x5chain is None) or (len(self.__x5chain) == 0)):
            return False

        # Verify the Key ID field.
        if (self.__key_id is not None) and (len(self.__key_id) > 0) and (len(self.__key_id) != 8):
            return False

        # Verify the x5 certificate chain field.
        if (self.__x5chain is not None) and (len(self.__x5chain) == 0):
            return False

        # Verify the Payload field.
        if (len(self.__payload) == 0):
            return False

        # Verify the Signature field.
        if (len(self.__payload) == 0):
            return False

        return True

    ############################################################################
    def to_list(self) -> list:
        '''Convert the COSE_Sign1 to a list.'''
        if not self.is_valid():
            return None

        COSE_Sign1_list = []

        # Encode the Protected field.
        COSE_Sign1_list.append(bytearray(self.__protected))

        # Encode the Unprotected field.
        unprotected_dict = {}
        if (self.__key_id is not None) and (len(self.__key_id) > 0):
            unprotected_dict[COSE_Sign1.KEY_ID_LABEL] = bytearray(self.__key_id)
        if (self.__x5chain is not None) and (len(self.__x5chain) > 0):
            unprotected_dict[COSE_Sign1.X5CHAIN_CERTIFICATE_LABEL] = bytearray(self.__x5chain)
        COSE_Sign1_list.append(unprotected_dict)

        # Encode Payload field.
        COSE_Sign1_list.append(bytearray(self.__payload))

        # Encode the Signature field.
        COSE_Sign1_list.append(bytearray(self.__signature))

        return COSE_Sign1_list

    ############################################################################
    def to_cbor(self) -> bytes:
        '''Convert the COSE_Sign1 to CBOR.'''
        COSE_Sign1_list = self.to_list()
        if COSE_Sign1_list is None:
            return None
        return cbor2.dumps(COSE_Sign1_list)

    ############################################################################
    def to_json(self) -> str:
        '''Convert the COSE_Sign1 to JSON.'''
        COSE_Sign1_list = self.to_list()
        if COSE_Sign1_list is None:
            return None
        Utility.collection_bytes_to_hex_str(COSE_Sign1_list)
        return json.dumps(COSE_Sign1_list)

    ############################################################################
    def to_tlv(self) -> bytearray:
        '''Convert the COSE_Sign1 to TLV.'''
        COSE_Sign1_list = self.to_list()
        if COSE_Sign1_list is None:
            return None
        return Utility.list_to_tlv(COSE_Sign1_list)
