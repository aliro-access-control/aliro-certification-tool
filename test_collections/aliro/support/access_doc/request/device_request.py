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

from .doc_request import DocRequest

################################################################################
class DeviceRequest(object):
    '''Aliro Device Request.'''

    VERSION_LABEL = "1"
    '''The label for the Version field.'''

    DOC_REQUESTS_LABEL = "2"
    '''The label for the Doc Requests field.'''


    VERSION_DEFAULT = "1.0"
    '''The default data structure version.'''

    ############################################################################
    def __init__(self) -> None:
        self.__version : str = DeviceRequest.VERSION_DEFAULT
        self.__doc_requests : list[DocRequest] = []

    ############################################################################
    @property
    def version(self) -> str:
        '''Get the Version.'''
        return self.__version

    @version.setter
    def version(self, val : str) -> None:
        '''Set the Version.'''
        assert(isinstance(val, str))
        self.__version = str(val)

    ############################################################################
    @property
    def doc_requests(self) -> list[DocRequest]:
        '''Get the Doc Requests.'''
        return self.__doc_requests

    @doc_requests.setter
    def doc_requests(self, val : list[DocRequest]) -> None:
        '''Set the Doc Requests.'''
        assert(isinstance(val, list))
        for item in val:
            assert(isinstance(item, DocRequest))
        self.__doc_requests = val

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the DeviceRequest contains valid fields,
           otherwise returns False.'''

        # Verify the Version field.
        if (len(self.__version) == 0):
            return False

        # Verify the Doc Requests are valid.
        for doc_request in self.__doc_requests:
            if not isinstance(doc_request, DocRequest):
                return False
            if not doc_request.is_valid():
                return False

        return True

    ############################################################################
    def to_dict(self) -> dict:
        '''Convert the DeviceRequest to a dictionary.'''
        if not self.is_valid():
            return None

        device_request_dict = {}

        # Encode the Version.
        device_request_dict[DeviceRequest.VERSION_LABEL] = str(self.__version)

        # Encode the Doc Requests.
        doc_requests_list = []
        for doc_request in self.__doc_requests:
            doc_requests_list.append(doc_request.to_dict())
        device_request_dict[DeviceRequest.DOC_REQUESTS_LABEL] = doc_requests_list

        return device_request_dict

    ############################################################################
    def to_cbor(self) -> bytes:
        '''Convert the DeviceRequest to CBOR.'''
        device_request_dict = self.to_dict()
        if device_request_dict is None:
            return None
        return cbor2.dumps(device_request_dict)
