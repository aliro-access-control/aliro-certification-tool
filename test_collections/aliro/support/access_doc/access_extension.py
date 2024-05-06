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

from enum import IntFlag

from extension_data import ExtensionData
from utility import Utility

################################################################################
class CriticalityBits(IntFlag):
    CRITICAL = 1 << 0

################################################################################
class AccessExtension(object):
    '''Aliro Access Extension.'''

    CRITICALITY_LABEL = 0,
    '''The label for the required Criticality field.'''

    EXTENSION_ID_LABEL = 1
    '''The label for the required Extension ID field.'''

    VERSION_LABEL = 2
    '''The label for the required Version field.'''

    DATA_LABEL = 3
    '''The label for the required Data field.'''

    ############################################################################
    def __init__(self):
        self.__criticality : int = 0
        self.__id : int = 0
        self.__version : int = 0
        self.__data : ExtensionData = None
        return

    ############################################################################
    @property
    def is_critical(self) -> bool:
        '''Get the Criticality.'''
        return ((self.__criticality & CriticalityBits.CRITICAL) != 0)

    @is_critical.setter
    def is_critical(self, val : bool) -> None:
        '''Set the Criticality.'''
        assert(isinstance(val, bool))
        if (val):
            self.__criticality |= CriticalityBits.CRITICAL
        else:
            self.__criticality &= ~(int(CriticalityBits.CRITICAL))

    ############################################################################
    @property
    def id(self) -> int:
        '''Get the Extension's ID.'''
        return self.__id

    @id.setter
    def id(self, val : int) -> None:
        '''Set the Extension's ID.'''
        assert(isinstance(val, int))
        assert(val >= 0)
        self.__id = val

    ############################################################################
    @property
    def version(self) -> int:
        '''Get the Extension's Version.'''
        return self.__version

    @version.setter
    def version(self, val : int) -> None:
        '''Set the Extension's Version.'''
        assert(isinstance(val, int))
        assert(val >= 0)
        self.__version = val

    ############################################################################
    @property
    def data(self) -> ExtensionData:
        '''Get the Extension's Data.'''
        return self.__data

    @data.setter
    def data(self, val : ExtensionData) -> None:
        '''Set the Extension's Data.'''
        assert(isinstance(val, ExtensionData))
        self.__data = val

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the AccessExtension contains valid fields,
           otherwise returns False.'''
        # Verify the Criticality.
        if (type(self.criticality) is not int) or ((self.criticality & ~(int(CriticalityBits.CRITICAL))) != 0):
            return False

        # Verify the ID.
        if (type(self.id) is not int) or (self.id < 0):
            return False

        # Verify the Version.
        if (type(self.version) is not int) or (self.version < 0):
            return False

        # Verify the Data.
        if (self.data is None) or (not self.data.is_valid()):
            return False

        # The access extension is valid.
        return True

    ############################################################################
    def to_dict(self) -> dict:
        '''Convert the AccessExtension to a dictionary.'''
        if not self.is_valid():
            return None

        access_extension_dict = {}

        # Encode the Criticality.
        access_extension_dict[AccessExtension.CRITICALITY_LABEL] = self.__criticality

        # Encode the Extension ID.
        access_extension_dict[AccessExtension.EXTENSION_ID_LABEL] = self.id

        # Encode the Version.
        access_extension_dict[AccessExtension.VERSION_LABEL] = self.version

        # Encode the Data.
        access_extension_dict[AccessExtension.DATA_LABEL] = self.data.to_dict()

        return access_extension_dict

    ############################################################################
    def to_cbor(self) -> bytes:
        '''Convert the AccessExtension to CBOR.'''
        access_extension_dict = self.to_dict()
        if access_extension_dict is None:
            return None
        return cbor2.dumps(access_extension_dict)

    ############################################################################
    def to_json(self) -> str:
        '''Convert the AccessExtension to JSON.'''
        access_extension_dict = self.to_dict()
        if access_extension_dict is None:
            return None
        Utility.collection_bytes_to_hex_str(access_extension_dict)
        return json.dumps(access_extension_dict)

    ############################################################################
    def to_tlv(self) -> bytearray:
        '''Convert the AccessExtension to TLV.'''
        if not self.is_valid():
            return None

        ba = bytearray()

        # Encode the Criticality.
        criticality_bytes = Utility.uint_to_bytes(self.__criticality)
        ba.append(AccessExtension.CRITICALITY_LABEL)
        ba.append(len(criticality_bytes))
        ba.extend(criticality_bytes)

        # Encode the Extension ID.
        extension_id_bytes = Utility.uint_to_bytes(self.id)
        ba.append(AccessExtension.EXTENSION_ID_LABEL)
        ba.append(len(extension_id_bytes))
        ba.extend(extension_id_bytes)

        # Encode the Version.
        version_bytes = Utility.uint_to_bytes(self.version)
        ba.append(AccessExtension.VERSION_LABEL)
        ba.append(len(version_bytes))
        ba.extend(version_bytes)

        # Encode the Data.
        data_tlv = self.data.to_tlv()
        ba.append(AccessExtension.DATA_LABEL)
        ba.append(len(data_tlv))
        ba.extend(data_tlv)

        return ba
