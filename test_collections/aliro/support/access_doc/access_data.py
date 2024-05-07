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

from access_rule import AccessRule
from access_extension import AccessExtension
from non_access_extension import NonAccessExtension
from schedule import Schedule
from utility import Utility

class AccessData(object):
    '''Aliro Access Data Element.'''

    VERSION_LABEL = 0
    '''The label for the required Version field.'''

    ID_LABEL = 1
    '''The label for the optional ID field.'''

    ACCESS_RULES_LABEL = 2
    '''The label for the optional Access Rules field.'''

    SCHEDULES_LABEL = 3
    '''The label for the optional Schedules field.'''

    READER_RULE_IDS_LABEL = 4
    '''The label for the optional Reader Rule IDs field.'''

    NON_ACCESS_EXTENSIONS_LABEL = 5
    '''The label for the optional Non-Access Extensions field.'''

    ACCESS_EXTENSIONS_LABEL = 6
    '''The label for the optional Access Extensions field.'''


    ID_LENGTH_MIN = 0
    '''The minimum ID Length.'''

    ID_LENGTH_MAX = 16
    '''The maximum ID Length.'''


    READER_RULE_ID_MIN = 0
    '''The minimum Reader Rule ID.'''

    READER_RULE_ID_MAX = 0xFFFF
    '''The maximum Reader Rule ID.'''

    ############################################################################
    def __init__(self):
        self.__version : int = 0
        self.__id = bytearray()
        self.__access_rules : list[AccessRule] = []
        self.__schedules : list[Schedule] = []
        self.__reader_rule_ids : list[int] = []
        self.__non_access_extensions : dict[int, list[NonAccessExtension]] = {}
        self.__access_extensions : dict[int, list[AccessExtension]] = {}
        return

    ############################################################################
    @property
    def version(self) -> int:
        '''Get the Version.'''
        return self.__version

    @version.setter
    def version(self, val : int) -> None:
        '''Set the Version.'''
        assert(isinstance(val, int))
        assert(val >= 0)
        self.__version = val

    ############################################################################
    @property
    def id(self) -> bytearray:
        '''Get the ID as an array of bytes.'''
        return self.__id

    @id.setter
    def id(self, val : bytes | bytearray) -> None:
        '''Set the ID as an array of bytes.'''
        assert(isinstance(val, (bytes, bytearray)))
        self.__id = bytearray(val)

    ############################################################################
    @property
    def access_rules(self) -> list[AccessRule]:
        '''Get the list of Access Rules.'''
        return self.__access_rules

    ############################################################################
    @property
    def schedules(self) -> list[Schedule]:
        '''Get the list of Schedules.'''
        return self.__schedules

    ############################################################################
    @property
    def reader_rule_ids(self) -> list[int]:
        '''Get the list of Reader Rules IDs.'''
        return self.__reader_rule_ids

    ############################################################################
    @property
    def non_access_extensions(self) -> dict[int, list[NonAccessExtension]]:
        '''Get the list of Non-Access Extensions.'''
        return self.__non_access_extensions

    ############################################################################
    @property
    def access_extensions(self) -> dict[int, list[AccessExtension]]:
        '''Get the list of Access Extensions.'''
        return self.__access_extensions

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the AccessData contains valid fields,
           otherwise returns False.'''
        # Verify the version.
        if (type(self.version) is not int) or (self.version < 0):
            return False

        # Verify the ID.
        if (self.id is not None):
            if (len(self.id) < AccessData.ID_LENGTH_MIN) or (len(self.id) > AccessData.ID_LENGTH_MAX):
                return False

        # Verify the access rules.
        if (self.access_rules is not None):
            for access_rule in self.access_rules:
                if not access_rule.is_valid():
                    return False

        # Verify the schedules.
        if (self.schedules is not None):
            for schedule in self.schedules:
                if not schedule.is_valid():
                    return False

        # Verify the access rules' schedule IDs.
        if (self.access_rules is not None):
            for access_rule in self.access_rules:
                if (self.schedules is None) and (len(access_rule.allow_schedule_ids) > 0):
                    return False
                if (self.schedules is None) and (len(access_rule.deny_schedule_ids) > 0):
                    return False
                for schedule_id in access_rule.allow_schedule_ids:
                    if schedule_id >= len(self.schedules):
                        return False
                for schedule_id in access_rule.deny_schedule_ids:
                    if schedule_id >= len(self.schedules):
                        return False

        # Verify the reader rule IDs.
        if (self.reader_rule_ids is not None):
            for reader_rule_id in self.reader_rule_ids:
                if (type(reader_rule_id) is not int) or (reader_rule_id < AccessData.READER_RULE_ID_MIN) or (reader_rule_id > AccessData.READER_RULE_ID_MAX):
                    return False

        # Verify the non-access extensions.
        if (self.non_access_extensions is not None):
            for vendor_registered_id, extensions in self.non_access_extensions.items():
                for non_access_extension in extensions:
                    if (vendor_registered_id == 0) or (not non_access_extension.is_valid()):
                        return False

        # Verify the access extensions.
        if (self.access_extensions is not None):
            for vendor_registered_id, extensions in self.access_extensions.items():
                for access_extension in extensions:
                    if (vendor_registered_id == 0) or (not access_extension.is_valid()):
                        return False

        # The access data is valid.
        return True

    ############################################################################
    def to_dict(self) -> dict:
        '''Convert the AccessData to a dictionary.'''
        if not self.is_valid():
            return None

        access_data_dict = {}

        # Encode the Version.
        access_data_dict[AccessData.VERSION_LABEL] = int(self.version)

        # Encode the ID.
        if (self.id is not None) and (len(self.id) > 0):
            access_data_dict[AccessData.ID_LABEL] = bytearray(self.id)

        # Encode the Access Rules.
        if (self.access_rules is not None) and (len(self.access_rules) > 0):
            access_rules_list = []
            for access_rule in self.access_rules:
                access_rules_list.append(access_rule.to_dict())
            access_data_dict[AccessData.ACCESS_RULES_LABEL] = access_rules_list

        # Encode the Schedules.
        if (self.schedules is not None) and (len(self.schedules) > 0):
            schedules_list = []
            for schedule in self.schedules:
                schedules_list.append(schedule.to_dict())
            access_data_dict[AccessData.SCHEDULES_LABEL] = schedules_list

        # Encode the Reader Rule IDs.
        if (self.reader_rule_ids is not None) and (len(self.reader_rule_ids) > 0):
            access_data_dict[AccessData.READER_RULE_IDS_LABEL] = list(self.reader_rule_ids)

        # Encode the Non-Access Extensions.
        if (self.non_access_extensions is not None) and (len(self.non_access_extensions) > 0):
            non_access_extensions_dict = {}
            for vendor_registered_id, extensions in self.non_access_extensions.items():
                non_access_extensions_list = []
                for non_access_extension in extensions:
                    non_access_extensions_list.append(non_access_extension.to_dict())
                if (len(non_access_extensions_list) > 0):
                    non_access_extensions_dict[vendor_registered_id] = non_access_extensions_list
            access_data_dict[AccessData.NON_ACCESS_EXTENSIONS_LABEL] = non_access_extensions_dict

        # Encode the Access Extensions.
        if (self.access_extensions is not None) and (len(self.access_extensions) > 0):
            access_extensions_dict = {}
            for vendor_registered_id, extensions in self.access_extensions.items():
                access_extensions_list = []
                for access_extension in extensions:
                    access_extensions_list.append(access_extension.to_dict())
                if (len(access_extensions_list) > 0):
                    access_extensions_dict[vendor_registered_id] = access_extensions_list
            access_data_dict[AccessData.ACCESS_EXTENSIONS_LABEL] = access_extensions_dict

        return access_data_dict

    ############################################################################
    def to_cbor(self) -> bytes:
        '''Convert the AccessData to CBOR.'''
        access_data_dict = self.to_dict()
        if access_data_dict is None:
            return None
        return cbor2.dumps(access_data_dict)

    ############################################################################
    def to_json(self) -> str:
        '''Convert the AccessData to JSON.'''
        access_data_dict = self.to_dict()
        if access_data_dict is None:
            return None
        Utility.collection_bytes_to_hex_str(access_data_dict)
        return json.dumps(access_data_dict)

    ############################################################################
    def to_tlv(self) -> bytearray:
        '''Convert the AccessData to TLV.'''
        access_data_dict = self.to_dict()
        if access_data_dict is None:
            return None
        return Utility.dict_to_tlv(access_data_dict)
