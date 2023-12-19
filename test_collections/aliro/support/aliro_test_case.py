#
# Copyright (c) 2023 Aliro Authors
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

from typing import Any

from aliro_actuator.trust_framework.endpoint import Endpoint
from aliro_actuator.trust_framework.key import KeyPair, PublicKey

from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestCase


class AliroTestParameterError(Exception):
    """Error that will be raised when failing to read test parameters."""


class AliroTestCase(TestCase):
    """Base class for Aliro test cases.

    Class include helpers to get string and byte values from test parameters in project
    config.
    """

    def string_from_config(self, parameter_name: str) -> str:
        """Get a specific string value from test parameters.

        Args:
            parameter_name (str): key for value in test_parameters

        Raises:
            AliroTestParameterError: Raised if no value is found for parameter_name. Or
            Value is not a string.

        Returns:
            str: value from test_parameters
        """
        config_str = self.test_parameters.get(parameter_name)
        if config_str is None:
            raise AliroTestParameterError(
                f"Test Parameter '{parameter_name}' must be set in Project config."
            )

        if not isinstance(config_str, str):
            raise AliroTestParameterError(
                f"Test Parameter '{parameter_name}' must be a string."
            )

        return config_str

    def bytes_from_config(self, parameter_name: str) -> bytes:
        """Get a specific bytes value from test parameters. Value must be a valid hex
        string.

        Args:
            parameter_name (str): key for value in test_parameters

        Raises:
            AliroTestParameterError: Raised if no value is not a valid hex string.

        Returns:
            bytes: hex parsed value from string in test_parameters
        """
        config_str = self.string_from_config(parameter_name)

        try:
            value = bytes.fromhex(config_str)
        except ValueError as e:
            raise AliroTestParameterError(
                f"Test Parameter '{parameter_name}' must be in valid hex format. "
                f"Value: '{config_str}'. Error: {e}"
            )

        return value


class AliroReaderTestCase(AliroTestCase):
    """Base test case class for Aliro test cases testing readers.

    Reader test cases require information about the reader:
    - Public Key
    - group identifier
    - sub group identifier.

    These can be set in the test_paramters as part of the project configuration.

    This base class will handle the loading and parsing of these values, so they can be
    used in the test script.
    """

    @classmethod
    def default_test_parameters(self) -> dict[str, Any]:
        """Default test paramters for reader test cases.

        NOTE: these values match the Reader example in Aliro Actuator.

        Returns:
            dict[str, Any]: default test parameters.
        """
        return {
            "dut_reader_public_key": "-----BEGIN PUBLIC KEY-----\n"
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOSjzIgGdR1eJO95qD+XhPj5Te5yg\n"
            "9UnAvS9A95BgJSoKTykRkhV6lctusgJ1lCjADNg0mYxdDqsZLuiHPF007g==\n"
            "-----END PUBLIC KEY-----\n",
            "dut_reader_group_identifier": "00113344667799AA00113344667799AA",
            "dut_reader_subgroup_identifier": "113344667799AA00113344667799AA00",
        }

    def reader_endpoint(self) -> Endpoint:
        """Load DUT reader test parameters, and build an Endpoint to be used in when
        initializing a UserDevice in reader test cases.

        Returns:
            Endpoint: Reader endpoint.
        """

        logger.info("Generating User Device Key Pair")
        user_device_keypair = KeyPair()

        # Reader Device UT
        logger.info("Loading DUT Reader info from test_parameters in project config.")

        reader_public_key_str = self.string_from_config("dut_reader_public_key")
        logger.info(f"Using Reader Public Key: {reader_public_key_str}")

        reader_group_identifier = self.bytes_from_config("dut_reader_group_identifier")
        logger.info(f"Using Reader Group Identifier: {reader_group_identifier.hex()}")

        reader_sub_group_identifier = self.bytes_from_config(
            "dut_reader_group_identifier"
        )
        logger.info(
            f"Using Reader Sub-Group Identifier: {reader_sub_group_identifier.hex()}"
        )

        return Endpoint(
            user_device_keypair,
            PublicKey(reader_public_key_str),
            [reader_group_identifier + reader_sub_group_identifier],
        )


class AliroUserDeviceTestCase(AliroTestCase):
    @classmethod
    def default_test_parameters(self) -> dict[str, Any]:
        """Default test paramters for user device test cases.

        NOTE: these values match the User Device example in Aliro Actuator.

        Returns:
            dict[str, Any]: default test parameters.
        """
        return {
            "th_reader_private_key": "-----BEGIN EC PRIVATE KEY-----\n"
            "MHcCAQEEIIrv3/jVtHqpo+26x6NF7SIhAhUS/VWr3juO4PIIlSaToAoGCCqGSM49\n"
            "AwEHoUQDQgAEOSjzIgGdR1eJO95qD+XhPj5Te5yg9UnAvS9A95BgJSoKTykRkhV6\n"
            "lctusgJ1lCjADNg0mYxdDqsZLuiHPF007g==\n"
            "-----END EC PRIVATE KEY-----",
            "th_reader_public_key": "-----BEGIN PUBLIC KEY-----\n"
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOSjzIgGdR1eJO95qD+XhPj5Te5yg\n"
            "9UnAvS9A95BgJSoKTykRkhV6lctusgJ1lCjADNg0mYxdDqsZLuiHPF007g==\n"
            "-----END PUBLIC KEY-----\n",
            "th_reader_group_identifier": "00113344667799AA00113344667799AA",
            "th_reader_sub_group_identifier": "113344667799AA00113344667799AA00",
        }

    def th_reader_keypair(self) -> KeyPair:
        """Load TH Reader keys from test parameters.
        When testing a UserDevice, the TH will be the Reader. Keys for this reader
        will be configurable in test_paramters of project configuration.

        Returns:
            KeyPair: Key pair for TH reader.
        """
        reader_private_key = self.string_from_config("th_reader_private_key")
        logger.info(f"TH Using Reader Private Key: \n{reader_private_key}")

        reader_public_key = self.string_from_config("th_reader_public_key")
        logger.info(f"TH Using Reader Public Key: \n{reader_public_key}")

        return KeyPair(private_key=reader_private_key, public_key=reader_public_key)

    def th_group_identifier(self) -> bytes:
        """Load TH Reader group identifier from test parameters.
        When testing a UserDevice, the TH will be the Reader. The group identifier
        for this reader will be configurable in test_paramters of project configuration.

        Returns:
            bytes: group identifier
        """
        return self.bytes_from_config("th_reader_group_identifier")

    def th_sub_group_identifier(self) -> bytes:
        """Load TH Reader sub-group identifier from test parameters.
        When testing a UserDevice, the TH will be the Reader. The sub-group identifier
        for this reader will be configurable in test_paramters of project configuration.

        Returns:
            bytes: sub-group identifier
        """
        return self.bytes_from_config("th_reader_sub_group_identifier")
