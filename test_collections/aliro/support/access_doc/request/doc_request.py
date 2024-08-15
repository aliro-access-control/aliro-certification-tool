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

from .items_request import ItemsRequest

################################################################################
class DocRequest(object):
    '''Aliro Doc Request within a Device Request.'''

    ITEMS_REQUEST_LABEL = "1"
    '''The label for the Items Request field.'''

    ############################################################################
    def __init__(self) -> None:
        self.__items_request : ItemsRequest = ItemsRequest()

    ############################################################################
    @property
    def items_request(self) -> ItemsRequest:
        '''Get the Item Request.'''
        return self.__items_request

    @items_request.setter
    def items_request(self, val : ItemsRequest) -> None:
        '''Set the Item Request.'''
        assert(isinstance(val, ItemsRequest))
        self.__items_request = val

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the DocRequest contains valid fields,
           otherwise returns False.'''

        # Verify the Items Request is valid.
        if not isinstance(self.__items_request, ItemsRequest):
            return False
        if not self.__items_request.is_valid():
            return False

        return True

    ############################################################################
    def to_dict(self) -> dict:
        '''Convert the DocRequest to a dictionary.'''
        if not self.is_valid():
            return None

        doc_request_dict = {}

        # Encode the Item Request.
        cbor_tag_encoded_cbor = 24
        doc_request_dict[DocRequest.ITEMS_REQUEST_LABEL] = cbor2.dumps(cbor2.CBORTag(cbor_tag_encoded_cbor, self.__items_request.to_cbor()))

        return doc_request_dict

    ############################################################################
    def to_cbor(self) -> bytes:
        '''Convert the DocRequest to CBOR.'''
        doc_request_dict = self.to_dict()
        if doc_request_dict is None:
            return None
        return cbor2.dumps(doc_request_dict)
