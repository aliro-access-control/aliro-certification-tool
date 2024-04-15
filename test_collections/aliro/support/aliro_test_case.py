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

from aliro_actuator.access_protocol.reader import ReaderStorage
from aliro_actuator.trust_framework.access_credential import AccessCredential
from aliro_actuator.trust_framework.key import KeyPair, PrivateKey, PublicKey
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

    def public_key_from_config(self, parameter_name: str) -> PublicKey:
        """Get a test parameter as a PublicKey. Must be an Elliptic Curve Public Key.
        Parameter value must be an encoding in either
         - hex string (DER format) or
         - pem string.

        Args:
            parameter_name (str): key for value in test_parameters

        Raises:
            AliroTestParameterError: Raised if value is not a string.
            ValueError:
                - If the PEM data's structure could not be decoded successfully.
                - If the hex DER data has invalid length.
            cryptography.exceptions.UnsupportedAlgorithm: If the serialized key type
                is not supported by the OpenSSL version cryptography is using.
            aliro_actuator.trust_framework.errors.InvalidKeyFormatError: If key is not
            an Elliptic Curve Public Key.

        Returns:
            PublicKey: Parsed and decoded key.
        """
        try:
            config_bytes = self.bytes_from_config(parameter_name)
            return PublicKey(config_bytes)
        except AliroTestParameterError:
            # This can happen due to test parameter
            # - not being a string
            # - not being a valid hex string
            #
            # We fall back to parse this as a PEM string.
            pass

        config_str = self.string_from_config(parameter_name)
        return PublicKey(config_str)

    def private_key_from_config(
        self, parameter_name: str, public_key: PublicKey | None = None
    ) -> PrivateKey:
        """Get a test parameter as a PrivateKey. Must be an Elliptic Curve Private Key,
        without passcode.

        Parameter value must be an encoding in either
         - hex string (DER format, PKCS8 encoding, 138bytes or 32 bytes)
         - pem string.

        When key is encoded as a 32 byte hex string, the Public key is required to
        derive the full private key.

        Args:
            parameter_name (str): key for value in test_parameters
            public_key (PublicKey, optional): Required when private_key is encoded as
            32 byte hex string.

        Raises:
            AliroTestParameterError:
            - Raised if value is not a string.
            - If the hex string is 32 bytes and no public_key is provided
            ValueError: If the PEM data could not be decrypted or if its structure could
                not be decoded successfully.
            TypeError: If the key was encrypted with a password.
            cryptography.exceptions.UnsupportedAlgorithm: If the serialized key type is
            not supported by the OpenSSL version cryptography is using.
            aliro_actuator.trust_framework.errors.InvalidKeyFormatError:
                - If key is not an Elliptic Curve Private Key.
                - If the hex string is not 138 or 32 bytes

        Returns:
            PrivateKey: Parsed and decoded key.
        """
        try:
            private_key_bytes = self.bytes_from_config(parameter_name)

            if len(private_key_bytes) == 32:
                # 32 byte private key requires public key to build full private key
                if public_key is None:
                    raise AliroTestParameterError(
                        "Public Key must be present when parsing, "
                        "32byte hex encoded DER private key."
                    )
                return PrivateKey(private_key_bytes, public_key.as_bytes())

            else:
                return PrivateKey(private_key_bytes)
        except AliroTestParameterError:
            # This can happen due to test parameter
            # - not being a string
            # - not being a valid hex string
            #
            # We fall back to parse this as a PEM string.
            pass

        config_str = self.string_from_config(parameter_name)
        return PrivateKey(config_str)


class AliroReaderTestCase(AliroTestCase):
    """Base test case class for Aliro test cases testing readers.

    Reader test cases require information about the reader:
    - Public Key
    - group identifier
    - sub group identifier.

    These can be set in the test_parameters as part of the project configuration.

    This base class will handle the loading and parsing of these values, so they can be
    used in the test script.
    """

    # Test Parameter keys
    READER_PUBLIC_KEY_KEY = "dut_reader_public_key"
    READER_GROUP_ID_KEY = "dut_reader_group_identifier"
    READER_SUB_GROUP_ID_KEY = "dut_reader_group_sub_identifier"
    READER_GROUP_RESOLVING_KEY = "dut_reader_group_resolving_key"
    ENDPOINT_PRIVATE_KEY_KEY = "th_endpoint_private_key"
    ENDPOINT_PUBLIC_KEY_KEY = "th_endpoint_public_key"

    @classmethod
    def default_test_parameters(self) -> dict[str, Any]:
        """Default test parameters for reader test cases.

        NOTE: these values match the Reader example in Aliro Actuator.

        Returns:
            dict[str, Any]: default test parameters.
        """
        return {
            self.READER_PUBLIC_KEY_KEY: "043928f322019d4757893bde6a0fe5e13e3e537b9ca0"
            "f549c0bd2f40f79060252a0a4f291192157a95cb6eb202759428c00cd834998c5d0eab19"
            "2ee8873c5d34ee",
            self.READER_GROUP_ID_KEY: "00113344667799AA00113344667799AA",
            self.READER_SUB_GROUP_ID_KEY: "113344667799AA00113344667799AA00",
            self.ENDPOINT_PRIVATE_KEY_KEY: "f6f601cac64e2d4e47e9b2d1d0408680cef95e4e8"
            "4b5ecee64d3401773bf9426",
            self.ENDPOINT_PUBLIC_KEY_KEY: "04742df736d0fc9be978c45b00e8fdf7cea684ea10"
            "5ae574c1505a2c24ab6198e3125b7f1b7e1d134c55ece69681ba8ecc18a3836dc5199c75"
            "9f31e8ccf17e3efa",
            self.READER_GROUP_RESOLVING_KEY: "00000000000000000000000000000000",
        }

    def reader_access_credential(self) -> AccessCredential:
        """Load DUT reader test parameters, and build an AccessCredential to be used
        when initializing a UserDevice in reader test cases.

        Returns:
            AccessCredential: Reader access credential.
        """

        # Reader Device UT
        logger.info("Loading DUT Reader info from test_parameters in project config.")

        # User Device Key Pair
        logger.info("Generating User Device Key Pair")
        logger.info(f"Loading public key from '{self.ENDPOINT_PUBLIC_KEY_KEY}'")
        access_credential_public_key = self.public_key_from_config(
            self.ENDPOINT_PUBLIC_KEY_KEY
        )
        logger.info(
            f"TH Using User Device Public Key(hex): \n{access_credential_public_key.as_bytes().hex()}"
        )
        logger.info(
            f"TH Using User Device Public Key(pem): \n{access_credential_public_key.as_pem()}"
        )

        logger.info(f"Loading private key from '{self.ENDPOINT_PRIVATE_KEY_KEY}'")
        access_credential_private_key = self.private_key_from_config(
            self.ENDPOINT_PRIVATE_KEY_KEY, public_key=access_credential_public_key
        )
        logger.info(
            f"TH Using User Device Private Key(hex): \n{access_credential_private_key.as_bytes().hex()}"
        )
        logger.info(
            f"TH Using User Device Private Key(pem): \n{access_credential_private_key.as_pem()}"
        )
        user_device_key_pair = KeyPair(
            access_credential_private_key, access_credential_public_key
        )

        # Public Key
        logger.info(f"Loading public key from '{self.READER_PUBLIC_KEY_KEY}'")
        reader_public_key = self.public_key_from_config(self.READER_PUBLIC_KEY_KEY)
        logger.info(
            f"Using Reader Public Key(hex): \n{reader_public_key.as_bytes().hex()}"
        )
        logger.info(f"Using Reader Public Key(PEM): \n{reader_public_key.as_pem()}")

        # Group Identifier
        logger.info(
            f"Loading Reader group identifier from '{self.READER_GROUP_ID_KEY}'"
        )
        reader_group_identifier = self.bytes_from_config(self.READER_GROUP_ID_KEY)
        logger.info(f"Using Reader Group Identifier: {reader_group_identifier.hex()}")

        # Sub-Group Identifier
        logger.info(
            f"Loading Reader sub-group identifier from '{self.READER_SUB_GROUP_ID_KEY}'"
        )
        reader_sub_group_identifier = self.bytes_from_config(
            self.READER_SUB_GROUP_ID_KEY
        )
        logger.info(
            f"Using Reader Sub-Group Identifier: {reader_sub_group_identifier.hex()}"
        )

        return AccessCredential(
            user_device_key_pair=user_device_key_pair,
            reader_id_key_list=[(reader_group_identifier, reader_public_key)],
        )

    def reader_group_resolving_key(self) -> bytes:
        """Load TH Reader group resolving key from test parameters.
        When testing a UserDevice, the TH will be the Reader. The group resolving key
        for this reader will be configurable in test_paramters of project configuration.

        Returns:
            bytes: group resolving key
        """
        logger.info(
            f"Loading Reader group resolving key from '{self.READER_GROUP_RESOLVING_KEY}'"
        )
        group_resolving_key = self.bytes_from_config(self.READER_GROUP_RESOLVING_KEY)
        logger.info(
            f"Using Reader group resolving key(hex): {group_resolving_key.hex()}"
        )
        return group_resolving_key


class AliroUserDeviceTestCase(AliroTestCase):
    """Base test case class for Aliro test cases testing User Devices.

    User Device test cases will simulate a reader, using this information:
    - KeyPair (Private and Public keys)
    - group identifier
    - sub group identifier.

    These can be set in the test_paramters as part of the project configuration.

    This base class will handle the loading and parsing of these values, so they can be
    used in the test script.
    """

    # Test Parameter keys
    READER_PRIVATE_KEY_KEY = "th_reader_private_key"
    READER_PUBLIC_KEY_KEY = "th_reader_public_key"
    READER_GROUP_ID_KEY = "th_reader_group_identifier"
    READER_SUB_GROUP_ID_KEY = "th_reader_sub_group_identifier"
    READER_GROUP_RESOLVING_KEY = "th_reader_group_resolving_key"
    READER_SPSM = "th_reader_spsm"
    READER_CACHE_ACCESS_CREDENTIAl = "th_reader_cache_access_credential"
    READER_CACHE_KPERSISTENT = "th_reader_cache_kpersistent"
    READER_CACHE_SIGNALING_BITMAP = "th_reader_cache_signaling_bitmap"
    READER_CACHE_CREDENTIAL_SIGNED_TIMESTAMP = (
        "th_reader_cache_revocation_signed_timestamp"
    )
    READER_CACHE_REVOCATION_SIGNED_TIMESTAMP = (
        "th_reader_cache_credential_signed_timestamp"
    )

    @classmethod
    def default_test_parameters(self) -> dict[str, Any]:
        """Default test paramters for user device test cases.

        NOTE: these values match the User Device example in Aliro Actuator.

        Returns:
            dict[str, Any]: default test parameters.
        """
        return {
            self.READER_PRIVATE_KEY_KEY: "8aefdff8d5b47aa9a3edbac7a345ed2221021512fd55"
            "abde3b8ee0f208952693",
            self.READER_PUBLIC_KEY_KEY: "043928f322019d4757893bde6a0fe5e13e3e537b9ca0f5"
            "49c0bd2f40f79060252a0a4f291192157a95cb6eb202759428c00cd834998c5d0eab192ee8"
            "873c5d34ee",
            self.READER_GROUP_ID_KEY: "00113344667799AA00113344667799AA",
            self.READER_SUB_GROUP_ID_KEY: "113344667799AA00113344667799AA00",
            self.READER_GROUP_RESOLVING_KEY: "00000000000000000000000000000000",
            self.READER_SPSM: "0080",
            self.READER_CACHE_ACCESS_CREDENTIAl: "04742df736d0fc9be978c45b00e8fdf7cea"
            "684ea105ae574c1505a2c24ab6198e3125b7f1b7e1d134c55ece69681ba8ecc18a3836dc"
            "5199c759f31e8ccf17e3efa",
            self.READER_CACHE_KPERSISTENT: "dc7199dd338189299525734777701fa21cddb6e02"
            "7e6c9a95e32281ba9db4b6f",
            self.READER_CACHE_SIGNALING_BITMAP: "0000",
            self.READER_CACHE_CREDENTIAL_SIGNED_TIMESTAMP: None,
            self.READER_CACHE_REVOCATION_SIGNED_TIMESTAMP: None,
        }

    def th_reader_keypair(self) -> KeyPair:
        """Load TH Reader keys from test parameters.
        When testing a UserDevice, the TH will be the Reader. Keys for this reader
        will be configurable in test_paramters of project configuration.

        Returns:
            KeyPair: Key pair for TH reader.
        """
        logger.info("Loading key pair for Test Harness use on simulated Reader.")

        # Public Key
        logger.info(f"Loading public key from '{self.READER_PUBLIC_KEY_KEY}'")
        reader_public_key = self.public_key_from_config(self.READER_PUBLIC_KEY_KEY)
        logger.info(
            f"TH Using Reader Public Key(hex): \n{reader_public_key.as_bytes().hex()}"
        )
        logger.info(f"TH Using Reader Public Key(pem): \n{reader_public_key.as_pem()}")

        # Private Key
        logger.info(f"Loading private key from '{self.READER_PRIVATE_KEY_KEY}'")
        reader_private_key = self.private_key_from_config(
            self.READER_PRIVATE_KEY_KEY, public_key=reader_public_key
        )
        logger.info(
            f"TH Using Reader Private Key(hex): \n{reader_private_key.as_bytes().hex()}"
        )
        logger.info(
            f"TH Using Reader Private Key(pem): \n{reader_private_key.as_pem()}"
        )

        return KeyPair(
            private_key=reader_private_key,
            public_key=reader_public_key,
        )

    def th_group_identifier(self) -> bytes:
        """Load TH Reader group identifier from test parameters.
        When testing a UserDevice, the TH will be the Reader. The group identifier
        for this reader will be configurable in test_paramters of project configuration.

        Returns:
            bytes: group identifier
        """
        logger.info(
            f"Loading Reader group identifier from '{self.READER_GROUP_ID_KEY}'"
        )
        group_id = self.bytes_from_config(self.READER_GROUP_ID_KEY)
        logger.info(f"Using Reader group identifier(hex): {group_id.hex()}")
        return group_id

    def th_sub_group_identifier(self) -> bytes:
        """Load TH Reader sub-group identifier from test parameters.
        When testing a UserDevice, the TH will be the Reader. The sub-group identifier
        for this reader will be configurable in test_paramters of project configuration.

        Returns:
            bytes: sub-group identifier
        """
        logger.info(
            f"Loading Reader sub-group identifier from '{self.READER_SUB_GROUP_ID_KEY}'"
        )
        sub_group_id = self.bytes_from_config(self.READER_SUB_GROUP_ID_KEY)
        logger.info(f"Using Reader sub-group identifier(hex): {sub_group_id.hex()}")
        return sub_group_id

    def th_group_resolving_key(self) -> bytes:
        """Load TH Reader group resolving key from test parameters.
        When testing a UserDevice, the TH will be the Reader. The group resolving key
        for this reader will be configurable in test_paramters of project configuration.

        Returns:
            bytes: group resolving key
        """
        logger.info(
            f"Loading Reader group resolving key from '{self.READER_GROUP_RESOLVING_KEY}'"
        )
        group_resolving_key = self.bytes_from_config(self.READER_GROUP_RESOLVING_KEY)
        logger.info(
            f"Using Reader group resolving key(hex): {group_resolving_key.hex()}"
        )
        return group_resolving_key

    def th_spsm(self) -> bytes:
        """Load TH Reader spsm from test parameters.
        When testing a UserDevice, the TH will be the Reader. The spsm
        for this reader will be configurable in test_paramters of project configuration.

        Returns:
            bytes: spsm
        """
        logger.info(f"Loading Reader spsm from '{self.READER_SPSM}'")
        spsm = self.bytes_from_config(self.READER_SPSM)
        logger.info(f"Using Reader spsm(hex): {spsm.hex()}")
        return spsm

    def th_readerstorage(self) -> bytes:
        """Load TH Reader storage from test parameters.
        When testing a UserDevice, the TH will be the Reader. The reader storage
        for this reader will be configurable in test_paramters of project configuration.

        Returns:
            ReaderStorage: reader_storage
        """
        logger.info(
            f"Loading Reader cache access credential from '{self.READER_CACHE_ACCESS_CREDENTIAl}'"
        )
        reader_cache_access_credential = self.public_key_from_config(
            self.READER_CACHE_ACCESS_CREDENTIAl
        )
        logger.info(
            f"Using Reader cache access credential(hex): {reader_cache_access_credential.as_bytes().hex()}"
        )

        logger.info(
            f"Loading Reader cache kpersistent from '{self.READER_CACHE_KPERSISTENT}'"
        )
        kpersistent = self.bytes_from_config(self.READER_CACHE_KPERSISTENT)
        logger.info(f"Using Reader kpersistent(hex): {kpersistent.hex()}")

        logger.info(
            f"Loading Reader cache signaling bitmap from '{self.READER_CACHE_SIGNALING_BITMAP}'"
        )
        signaling_bitmap = self.bytes_from_config(self.READER_CACHE_SIGNALING_BITMAP)
        logger.info(f"Using Reader signaling bitmap(hex): {signaling_bitmap.hex()}")

        reader_storage = ReaderStorage()
        reader_storage.add_kpersistent(
            reader_cache_access_credential, kpersistent, signaling_bitmap
        )

        return reader_storage
