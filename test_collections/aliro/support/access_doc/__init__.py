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

"""Access Document package for Aliro Certification Tool.

This package provides utilities for working with Aliro access documents,
including Mobile Driver's License (MDL) functionality.
"""

from .utility import Utility

# Version
__version__ = "0.1.0"

# Expose submodules for convenient access
# Note: Submodules should be imported explicitly when needed:
#   from access_doc.mdl import DeviceResponse
#   from access_doc.aliro.access import AccessData

__all__ = [
    "Utility",
    "__version__",
]
