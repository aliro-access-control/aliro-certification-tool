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

from enum import IntFlag

from extension_data import ExtensionData

################################################################################
class MultipleUsersFlagBits(IntFlag):
    '''Multiple Users Bit Flags.'''

    MULTIPLE_USERS_REQUIRED = 1 << 0
    '''
    When set, then the Reader shall require multiple users to present valid
    valid credentials to grant access.
    '''

################################################################################
class MultipleUsersExtensionData(ExtensionData):
    '''Multiple Users Extension Data.'''

    FLAGS_LABEL = 0
    '''The label for the required Flags field.'''

    TIMEOUT_SECONDS_LABEL = 1
    '''The label for the Timeout Seconds field.'''


    TIMEOUT_SECONDS_MIN = 10
    '''The minimum timeout in seconds.'''

    TIMEOUT_SECONDS_MAX = 60
    '''The maximum timeout in seconds.'''

    TIMEOUT_SECONDS_DEFAULT = 30
    '''The default timeout in seconds.'''

    ############################################################################
    def __init__(self) -> None:
        self.__flags : int = 0
        self.__timeout_seconds : int = MultipleUsersExtensionData.TIMEOUT_SECONDS_DEFAULT
        return

    ############################################################################
    @property
    def flags(self) -> int:
        '''Get the bit flags.'''
        return self.__flags

    @flags.setter
    def flags(self, val : int | MultipleUsersFlagBits) -> None:
        '''Set the bit flags.'''
        assert(isinstance(val, (int, MultipleUsersFlagBits)))
        # Limit flags to a single byte.
        self.__flags = int(val) & 0xFF

    ############################################################################
    @property
    def timeout_seconds(self) -> int:
        '''Get the timeout in seconds.'''
        return self.__timeout_seconds

    @timeout_seconds.setter
    def timeout_seconds(self, val : int) -> None:
        '''Set the timeout in seconds.'''
        assert(isinstance(val, int))
        if (val < MultipleUsersExtensionData.TIMEOUT_SECONDS_MIN):
            self.__timeout_seconds = int(MultipleUsersExtensionData.TIMEOUT_SECONDS_MIN)
        elif (val > MultipleUsersExtensionData.TIMEOUT_SECONDS_MAX):
            self.__timeout_seconds = int(MultipleUsersExtensionData.TIMEOUT_SECONDS_MAX)
        else:
            self.__timeout_seconds = int(val)

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the MultipleUsersExtensionData contains valid fields,
           otherwise returns False.'''
        # Verify the Flags.
        if ((self.flags is None) or \
            (not isinstance(self.flags, (int, MultipleUsersFlagBits))) or \
            ((self.flags & (~(int(MultipleUsersFlagBits.MULTIPLE_USERS_REQUIRED)))) != 0)):
            return False

        # Verify the Timeout in Seconds.
        if ((self.timeout_seconds is None) or \
            (not isinstance(self.timeout_seconds, int))) or \
            (self.timeout_seconds < MultipleUsersExtensionData.TIMEOUT_SECONDS_MIN) or \
            (self.timeout_seconds > MultipleUsersExtensionData.TIMEOUT_SECONDS_MAX):
            return False

        return True

    ############################################################################
    def to_dict(self) -> dict:
        '''Convert the MultipleUsersExtensionData to a dictionary.'''
        if not self.is_valid():
            return False

        extension_data_dict = {}

        # Encode the Flags.
        extension_data_dict[MultipleUsersExtensionData.FLAGS_LABEL] = int(self.flags)

        # Encode the Timeout in Seconds.
        extension_data_dict[MultipleUsersExtensionData.TIMEOUT_SECONDS_LABEL] = int(self.timeout_seconds)

        return extension_data_dict
