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

from typing import Any, Awaitable, Callable

from aliro_actuator.trust_framework.access_credential import AccessCredential
from aliro_actuator.trust_framework.key import KeyPair, PrivateKey, PublicKey
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestCase


class AliroTestParameterError(Exception):
    """Error that will be raised when failing to read test parameters."""


def log_errors(func: Callable[[Any], Awaitable[Any]]):
    async def wrapper(*args, **kwargs):
        try:
            await func(*args, **kwargs)
        except Exception as error:
            logger.error(
                "Error occurred during script: {}: {}".format(
                    error.__class__.__name__, repr(error)
                )
            )
            raise error

    return wrapper


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
    ISSUER_GROUP_ID_KEY = "dut_reader_issuer_group_identifier"
    READER_SUB_GROUP_ID_KEY = "dut_reader_group_sub_identifier"
    READER_GROUP_RESOLVING_KEY = "dut_reader_group_resolving_key"
    ACCESS_CREDENTIAL_PRIVATE_KEY_KEY = "th_access_credential_private_key"
    ACCESS_CREDENTIAL_PUBLIC_KEY_KEY = "th_access_credential_public_key"
    READER_ISSUER_PUBLIC_KEY_KEY = "dut_reader_issuer_public_key"
    CREDENTIAL_ISSUER_PRIVATE_KEY_KEY = "th_credential_issuer_private_key"
    CREDENTIAL_ISSUER_PUBLIC_KEY_KEY = "th_credential_issuer_public_key"
    CREDENTIAL_ISSUER_CA_PRIVATE_KEY_KEY = "th_credential_issuer_ca_private_key"
    CREDENTIAL_ISSUER_CA_PUBLIC_KEY_KEY = "th_credential_issuer_ca_public_key"
    ACCESS_ELEMENT_ID_KEY = "dut_access_element_id"

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
            self.ISSUER_GROUP_ID_KEY: "00113344667799AA00113344667799AB",
            self.READER_SUB_GROUP_ID_KEY: "113344667799AA00113344667799AA00",
            self.ACCESS_CREDENTIAL_PRIVATE_KEY_KEY: "f6f601cac64e2d4e47e9b2d1d0408680cef95e4e8"
            "4b5ecee64d3401773bf9426",
            self.ACCESS_CREDENTIAL_PUBLIC_KEY_KEY: "04742df736d0fc9be978c45b00e8fdf7cea684ea10"
            "5ae574c1505a2c24ab6198e3125b7f1b7e1d134c55ece69681ba8ecc18a3836dc5199c75"
            "9f31e8ccf17e3efa",
            self.READER_GROUP_RESOLVING_KEY: "00000000000000000000000000000000",
            self.READER_ISSUER_PUBLIC_KEY_KEY: "043928f322019d4757893bde6a0fe5e13e3e5"
                                               "37b9ca0f549c0bd2f40f79060252a0a4f291192157a95cb6eb202759428c00cd834998c5"
                                               "d0eab192ee8873c5d34ee",
            self.CREDENTIAL_ISSUER_PRIVATE_KEY_KEY: "004111DBF98EC0FAE70D37218E1BE8B752D5016F2912A5A226F48EBB2D515058",
            self.CREDENTIAL_ISSUER_PUBLIC_KEY_KEY: "047BA31938492E3F5E97BC91806B5835B5D9E426609139006711E5FB7A670EE4E1"
                                                   "2FC9F25396C013CC20166029D761A105DEA5E071E84A9E499920524CE2301137",
            self.CREDENTIAL_ISSUER_CA_PRIVATE_KEY_KEY: "004111DBF98EC0FAE70D37218E1BE8B752D5016F2912A5A226F48EBB2D515058",
            self.CREDENTIAL_ISSUER_CA_PUBLIC_KEY_KEY: "047BA31938492E3F5E97BC91806B5835B5D9E426609139006711E5FB7A670EE4E1"
                                                   "2FC9F25396C013CC20166029D761A105DEA5E071E84A9E499920524CE2301137",
            self.ACCESS_ELEMENT_ID_KEY: "floor1",
        }

    def reader_access_credential(self, *, add_issuer_public_key: bool = False, use_random_ud_keypair: bool = False) -> AccessCredential:
        """Load DUT reader test parameters, and build an AccessCredential to be used
        when initializing a UserDevice in reader test cases.

        Returns:
            AccessCredential: Reader access credential.
        """

        # Reader Device UT
        logger.info("Loading DUT Reader info from test_parameters in project config.")

        # User Device Key Pair
        if use_random_ud_keypair:
            logger.info("Generating User Device Key Pair")
            user_device_key_pair = KeyPair()
        else:
            logger.info(
                f"Loading public key from '{self.ACCESS_CREDENTIAL_PUBLIC_KEY_KEY}'"
            )
            access_credential_public_key = self.public_key_from_config(
                self.ACCESS_CREDENTIAL_PUBLIC_KEY_KEY
            )

            logger.info(
                f"Loading private key from '{self.ACCESS_CREDENTIAL_PRIVATE_KEY_KEY}'"
            )
            access_credential_private_key = self.private_key_from_config(
                self.ACCESS_CREDENTIAL_PRIVATE_KEY_KEY,
                public_key=access_credential_public_key,
            )

            user_device_key_pair = KeyPair(
                access_credential_private_key, access_credential_public_key
            )

        logger.info(
            f"TH Using Access Credential Public Key(hex): \n{user_device_key_pair.get_public_key().as_bytes().hex()}"
        )
        logger.info(
            f"TH Using Access Credential Public Key(pem): \n{user_device_key_pair.get_public_key().as_pem()}"
        )

        logger.info(
            f"TH Using Access Credential Private Key(hex): \n{user_device_key_pair.get_private_key().as_bytes().hex()}"
        )
        logger.info(
            f"TH Using Access Credential Private Key(pem): \n{user_device_key_pair.get_private_key().as_pem()}"
        )


        # Public Key
        if add_issuer_public_key:
            logger.info(f"Loading issuer public key from '{self.READER_ISSUER_PUBLIC_KEY_KEY}'")
            issuer_reader_public_key = self.public_key_from_config(self.READER_ISSUER_PUBLIC_KEY_KEY)
            logger.info(f"Loading issuer group identifier from '{self.ISSUER_GROUP_ID_KEY}'")
            issuer_group_identifier_issuer = self.bytes_from_config(self.ISSUER_GROUP_ID_KEY)
            logger.info(f"Using Issuer Group Identifier: {issuer_group_identifier_issuer.hex()}")

        logger.info(f"Loading public key from '{self.READER_PUBLIC_KEY_KEY}'")
        reader_public_key = self.public_key_from_config(self.READER_PUBLIC_KEY_KEY)

        logger.info(
            f"Using Reader group Public Key(hex): \n{reader_public_key.as_bytes().hex()}"
        )
        logger.info(f"Using Reader group Public Key(PEM): \n{reader_public_key.as_pem()}")

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

        if 'issuer_reader_public_key' in locals():
            return AccessCredential(
                access_credential_key_pair=user_device_key_pair,
                reader_id_key_list=[
                    (reader_group_identifier, reader_public_key),
                    (issuer_group_identifier_issuer, issuer_reader_public_key),
                ],
            )
        else:
            return AccessCredential(
                access_credential_key_pair=user_device_key_pair,
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

    def access_document_data(self) -> tuple[KeyPair, KeyPair, str]:
        """Fetch info for building or validating an access document

        Returns:
            tuple:
                KeyPair: credential issuer keypair
                KeyPair: credential issuer CA keypair
                str: access element id
        """
        # Issuer
        logger.info(
            f"Loading credential issuer public key from '{self.CREDENTIAL_ISSUER_PUBLIC_KEY_KEY}'"
        )
        issuer_public_key = self.public_key_from_config(
            self.CREDENTIAL_ISSUER_PUBLIC_KEY_KEY
        )
        logger.info(
            f"Loading credential issuer private key from '{self.CREDENTIAL_ISSUER_PRIVATE_KEY_KEY}'"
        )
        issuer_private_key = self.private_key_from_config(
            self.CREDENTIAL_ISSUER_PRIVATE_KEY_KEY,
            public_key=issuer_public_key,
        )
        logger.info(
            f"TH Using Credential Issuer Private Key(hex): \n{issuer_private_key.as_bytes().hex()}"
        )
        logger.info(
            f"TH Using Credential Issuer Private Key(pem): \n{issuer_private_key.as_pem()}"
        )
        issuer_key_pair = KeyPair(
            issuer_private_key, issuer_public_key
        )

        # Issuer CA
        logger.info(
            f"Loading credential issuer ca public key from '{self.CREDENTIAL_ISSUER_CA_PUBLIC_KEY_KEY}'"
        )
        issuer_ca_public_key = self.public_key_from_config(
            self.CREDENTIAL_ISSUER_CA_PUBLIC_KEY_KEY
        )
        logger.info(
            f"Loading credential issuer ca private key from '{self.CREDENTIAL_ISSUER_CA_PRIVATE_KEY_KEY}'"
        )
        issuer_ca_private_key = self.private_key_from_config(
            self.CREDENTIAL_ISSUER_CA_PRIVATE_KEY_KEY,
            public_key=issuer_ca_public_key,
        )
        logger.info(
            f"TH Using Credential Issuer CA Private Key(hex): \n{issuer_ca_private_key.as_bytes().hex()}"
        )
        logger.info(
            f"TH Using Credential Issuer CA Private Key(pem): \n{issuer_ca_private_key.as_pem()}"
        )
        issuer_ca_key_pair = KeyPair(
            issuer_ca_private_key, issuer_ca_public_key
        )

        logger.info(
            f"Loading Access Element ID from '{self.ACCESS_ELEMENT_ID_KEY}'"
        )
        element_id = self.string_from_config(self.ACCESS_ELEMENT_ID_KEY)
        logger.info(
            f"Using Access Element ID: {element_id}"
        )

        return issuer_key_pair, issuer_ca_key_pair, element_id


class AliroUserDeviceTestCase(AliroTestCase):
    """Base test case class for Aliro test cases testing User Devices.

    User Device test cases will simulate a reader, using this information:
    - KeyPair (Private and Public keys)
    - group identifier
    - sub group identifier
    - reader certificate (uncompressed x509)

    These can be set in the test_paramters as part of the project configuration.

    This base class will handle the loading and parsing of these values, so they can be
    used in the test script.
    """

    # Test Parameter keys
    READER_PRIVATE_KEY_KEY = "th_reader_private_key"
    READER_PUBLIC_KEY_KEY = "th_reader_public_key"
    READER_GROUP_ID_KEY = "th_reader_group_identifier"
    READER_SUB_GROUP_ID_KEY = "th_reader_sub_group_identifier"
    READER_CERTIFICATE_KEY = "th_reader_certificate"
    READER_CERTIFICATE_KEY_CHAINING = "th_reader_certificate_chaining"
    READER_GROUP_RESOLVING_KEY = "th_reader_group_resolving_key"
    READER_SPSM = "th_reader_spsm"
    ACCESS_CREDENTIAL_PUBLIC_KEY_KEY = "th_access_credential_public_key"
    READER_ISSUER_PUBLIC_KEY_KEY = "th_reader_issuer_public_key"
    CREDENTIAL_ISSUER_PUBLIC_KEY_KEY = "dut_credential_issuer_public_key"
    ACCESS_ELEMENT_ID_KEY = "th_access_element_id"

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
            self.READER_CERTIFICATE_KEY: "308201513081f9a003020102020101300a06082a8648c"
            "e3d0403023011310f300d06035504030c06697373756572301e170d3230303130313030303"
            "030305a170d3439303130313030303030305a30123110300e06035504030c077375626a656"
            "3743059301306072a8648ce3d020106082a8648ce3d030107034200043928f322019d47578"
            "93bde6a0fe5e13e3e537b9ca0f549c0bd2f40f79060252a0a4f291192157a95cb6eb202759"
            "428c00cd834998c5d0eab192ee8873c5d34eea341303f301f0603551d23041830168014231"
            "8e55671f08eae212142a817720fb817ee93bf300c0603551d130101ff04023000300e06035"
            "51d0f0101ff040403020780300a06082a8648ce3d04030203470030440220606ddd0351bb4"
            "7c6acccb8b94d83fe5dd18cfa1a2bbd757ccbf7ad9e1e0ba4ca02204e36051d9f93ff34e3a"
            "d14ae5ead738e2e92a78ef4f9d384be863535484d5151",
            self.READER_CERTIFICATE_KEY_CHAINING: "3082019a3082013fa0030201020214010451"
            "3ad4f33e92f21aa45b0001004b35602245300a06082a8648ce3d040302302b312930270603"
            "5504030c20616c69726f2d746573742d766572792d6c6f6e676e616d65642d697373756572"
            "301e170d3234303130313030303030305a170d3430303130313030303030305a302b312930"
            "2706035504030c20616c69726f2d746573742d73696d696c61726c796c6f6e672d6861726e"
            "6573733059301306072a8648ce3d020106082a8648ce3d030107034200043928f322019d47"
            "57893bde6a0fe5e13e3e537b9ca0f549c0bd2f40f79060252a0a4f291192157a95cb6eb202"
            "759428c00cd834998c5d0eab192ee8873c5d34eea341303f301f0603551d23041830168014"
            "7fc93128a61c0cedf94e11732dbe46017c431901300c0603551d130101ff04023000300e06"
            "03551d0f0101ff040403020780300a06082a8648ce3d0403020349003046022100ea06af2b"
            "9b912feaff200291c0eabc9e85213d3beacee5a626f6c10a5fb49e4c022100db4d3ef63089"
            "4871e8775fe351f31e94d5ca1b4754e134bcedca890afcced544",
            self.READER_GROUP_RESOLVING_KEY: "00000000000000000000000000000000",
            self.READER_SPSM: "0080",
            self.ACCESS_CREDENTIAL_PUBLIC_KEY_KEY: "044dc6e1f1b0e879b487063d7e24e26e4c7"
            "5854a140fab5c5a6d4d8a582909d75f360de1dd16e6f113299d44900243901f2041fd82661"
            "ad6742128fe3b7a02c35d",
            self.READER_ISSUER_PUBLIC_KEY_KEY: "043928f322019d4757893bde6a0fe5e13e3e5"
            "37b9ca0f549c0bd2f40f79060252a0a4f291192157a95cb6eb202759428c00cd834998c5"
            "d0eab192ee8873c5d34ee",
            self.CREDENTIAL_ISSUER_PUBLIC_KEY_KEY: "047BA31938492E3F5E97BC91806B5835B5D9E426609139006711E5FB7A670EE4E1"
                                                   "2FC9F25396C013CC20166029D761A105DEA5E071E84A9E499920524CE2301137",
            self.ACCESS_ELEMENT_ID_KEY: "floor1",
        }

    def th_reader_keypair(self) -> KeyPair:
        """Load TH Reader keys from test parameters.
        When testing a UserDevice, the TH will be the Reader. Keys for this reader
        will be configurable in test_parameters of project configuration.

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
        for this reader will be configurable in test_parameters of project configuration.

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
        for this reader will be configurable in test_parameters of project configuration.

        Returns:
            bytes: sub-group identifier
        """
        logger.info(
            f"Loading Reader sub-group identifier from '{self.READER_SUB_GROUP_ID_KEY}'"
        )
        sub_group_id = self.bytes_from_config(self.READER_SUB_GROUP_ID_KEY)
        logger.info(f"Using Reader sub-group identifier(hex): {sub_group_id.hex()}")
        return sub_group_id

    def th_reader_certificate(self) -> bytes:
        """Load TH Reader certificate from test parameters.
        When testing a UserDevice, the TH will be the Reader. The certificate for this
        reader will be configurable in test_parameters of project configuration.

        Returns:
            Certificate
        """
        logger.info(f"Loading certificate from '{self.READER_CERTIFICATE_KEY}'")
        cert = self.bytes_from_config(self.READER_CERTIFICATE_KEY)
        logger.info(f"Using Reader certificate(hex): {cert.hex()}")
        return cert
    
    def th_reader_certificate_chaining(self) -> bytes:
        """Load TH Reader certificate for chaining from test parameters.
        When testing a UserDevice, the TH will be the Reader. The certificate for this
        reader will be configurable in test_parameters of project configuration.

        Returns:
            Certificate
        """
        logger.info(f"Loading certificate from '{self.READER_CERTIFICATE_KEY_CHAINING}'")
        cert = self.bytes_from_config(self.READER_CERTIFICATE_KEY_CHAINING)
        logger.info(f"Using Reader certificate(hex): {cert.hex()}")
        return cert

    def th_group_resolving_key(self) -> bytes:
        """Load TH Reader group resolving key from test parameters.
        When testing a UserDevice, the TH will be the Reader. The group resolving key
        for this reader will be configurable in test_parameters of project configuration.

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
        for this reader will be configurable in test_parameters of project configuration.

        Returns:
            bytes: spsm
        """
        logger.info(f"Loading Reader spsm from '{self.READER_SPSM}'")
        spsm = self.bytes_from_config(self.READER_SPSM)
        logger.info(f"Using Reader spsm(hex): {spsm.hex()}")
        return spsm

    def th_access_credential_public_key(self) -> PublicKey:
        """Load TH access credential public key from test parameters.
        When testing a UserDevice, the TH will be the Reader. Keys for this reader
        will be configurable in test_parameters of project configuration.

        Returns:
            PublicKey: access credential public key for TH reader. This key will be
            used to generate the key slot list.
        """
        logger.info("Loading public key for Test Harness use on simulated Reader.")

        # Public Key
        logger.info(
            f"Loading access credential public key from "
            f"'{self.ACCESS_CREDENTIAL_PUBLIC_KEY_KEY}'"
        )
        access_credential_public_key = self.public_key_from_config(
            self.ACCESS_CREDENTIAL_PUBLIC_KEY_KEY
        )
        logger.info(
            f"TH Using access credential Public Key(hex): \n"
            f"{access_credential_public_key.as_bytes().hex()}"
        )
        logger.info(
            f"TH Using access credential Public Key(pem): \n"
            f"{access_credential_public_key.as_pem()}"
        )

        return access_credential_public_key

    def th_reader_issuer_public_key(self) -> PublicKey:
        """Load TH Reader issuer public key from test parameters.
        When testing a UserDevice, the TH will be the Reader. Keys for this reader
        will be configurable in test_parameters of project configuration.

        Returns:
            PublicKey: Reader issuer public key for TH reader.
        """
        logger.info(
            "Loading Reader issuer public key for Test Harness use on simulated Reader."
        )

        # Public Key
        logger.info(f"Loading public key from '{self.READER_ISSUER_PUBLIC_KEY_KEY}'")
        reader_public_key = self.public_key_from_config(
            self.READER_ISSUER_PUBLIC_KEY_KEY
        )
        logger.info(
            f"TH Using Reader Issuer Public Key(hex): \n"
            f"{reader_public_key.as_bytes().hex()}"
        )
        logger.info(
            f"TH Using Reader Issuer Public Key(pem): \n{reader_public_key.as_pem()}"
        )

        return reader_public_key

    def th_access_document_data(self) -> tuple[KeyPair, str]:
        """Fetch info for validating an access document

        Returns:
            tuple:
                PublicKey: credential issuer public key
                str: access element id
        """
        logger.info(
            f"Loading credential issuer public key from '{self.CREDENTIAL_ISSUER_PUBLIC_KEY_KEY}'"
        )
        issuer_public_key = self.public_key_from_config(
            self.CREDENTIAL_ISSUER_PUBLIC_KEY_KEY
        )

        logger.info(
            f"Loading Access Element ID from '{self.ACCESS_ELEMENT_ID_KEY}'"
        )
        element_id = self.string_from_config(self.ACCESS_ELEMENT_ID_KEY)
        logger.info(
            f"Using Access Element ID: {element_id}"
        )

        return issuer_public_key, element_id