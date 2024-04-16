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
from app.schemas.test_environment_config import TestEnvironmentConfig


class TestEnvironmentConfigAliro(TestEnvironmentConfig):
    __test__ = False  # Needed to indicate to PyTest that this is not a "test"

    def validate_model(self, dict_model: dict) -> None:
        valid_test_parameters = [
            "dut_reader_public_key",
            "dut_reader_group_identifier",
            "dut_reader_group_sub_identifier",
        ]
        if dict_model:
            test_parameters = dict_model.get("test_parameters")

            if not test_parameters:
                raise

            # Check if the informed fields in test_parameters are valid
            for field, _ in test_parameters.items():
                if field not in valid_test_parameters:
                    raise
            
             # All test_parameters fields are mandatory
            for field in valid_test_parameters:
                if field not in test_parameters:
                    raise
