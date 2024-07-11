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

import copy
import typing

################################################################################
class KeyInfo(object):

    ############################################################################
    def __init__(self) -> None:
        self.__info : dict[int, typing.Any] = {}

    ############################################################################
    @property
    def info(self) -> dict[int, typing.Any]:
        '''Get the key information.'''
        return self.__info

    ############################################################################
    def update(self, id : int, value : typing.Any):
        assert(isinstance(id, int))
        self.__info.update(id, value)

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the KeyInfo contains valid fields,
           otherwise returns False.'''
        # Verify the info field.
        if (type(self.__info) is not dict):
            return False
        return True

    ############################################################################
    def to_dict(self) -> dict:
        '''Convert the KeyInfo to a dictionary.'''
        if not self.is_valid():
            return None
        return copy.deepcopy(self.__info)
