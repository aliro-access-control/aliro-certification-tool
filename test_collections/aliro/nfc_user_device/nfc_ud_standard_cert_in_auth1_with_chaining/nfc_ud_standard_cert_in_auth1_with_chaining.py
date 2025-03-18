from binascii import hexlify

from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    ReaderStatus,
    Transaction,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidResponseError,
    InvalidStatusError,
)
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.trust_framework.certificate import Certificate
from aliro_actuator.trust_framework.key import KeyPair, PublicKey
from aliro_actuator.trust_framework.key_slot import get_key_slot
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors


class NFC_UD_STANDARD_CERT_IN_AUTH1_WITH_CHAINING(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_UD_STANDARD_CERT_IN_AUTH1_WITH_CHAINING",
        "version": "0.0.1",
        "title": "NFC_UD_STANDARD_CERT_IN_AUTH1_WITH_CHAINING",
        "description": """Verify conformance of User Device UT in AUTH1 command.""",
    }

    reader_ePuBK = bytes.fromhex(
        "049696afe33de58b7d3253d1cba86d14147c16d455e8"
        "a27373b38d454af21b70e75e13ebc6d55743ba6a6ffc"
        "4ed37a55515a9346fdae311f60be30421fa6dc61c5"
    )
    reader_ePrivK = bytes.fromhex(
        "3c0f74114cd2a021e8066efbaa31dbb97ef0054272192606fd96633a04f66214"
    )
    transaction_identifier = bytes.fromhex("4165A83667AD0AF5AB115247424822E0")

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "",  # PICS in preparation
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Initialization"),
            TestStep("Step2: Set to polling mode"),
            TestStep("Step3: Transaction initiation"),
            TestStep("Step4: Send/Receive AUTH0 command/response"),
            TestStep("Step5: Send/Receive AUTH1 command/response"),
            TestStep("Step6: Send/Receive EXCHANGE command/response"),
        ]

    async def setup(self) -> None:
        logger.info("NFC_UD_STANDARD_CERT_IN_AUTH1_WITH_CHAINING setup")
        group_id = self.th_group_identifier()
        key = self.th_reader_keypair()
        cert = self.th_reader_certificate_chaining()
        self.reader_issuer_public_key = self.th_reader_issuer_public_key()
        self.endpoint_key = self.th_access_credential_public_key()

        # Initialize Aliro NFC Reader
        self.reader = Reader(
            transport_protocol=TransportProtocol.NFC,
            reader_group_identifier=self.group_id,
            reader_key=key,
            reader_cert=cert,
            transaction_identifier_list=[self.transaction_identifier],
            ephemeral_key_list=[KeyPair(self.reader_ePrivK, self.reader_ePuBK)],
            reader_system_issuer_ca=self.reader_issuer_public_key,
            key_slot_list=[self.endpoint_key],
        )

    @log_errors
    async def execute(self) -> None:
        # Test step 1
        # Done in setup
        prompt = "Add reader_group_identifier: {}\n".format(hexlify(self.group_id))
        prompt += "with reader_group_identifier_key: \n{}\n".format(
            hexlify(self.reader_issuer_public_key.as_bytes())
        )
        prompt += "to the Access Credential of the user device\n"
        prompt += "Using Access Credential public key:\n"
        prompt += "{}\n".format(hexlify(self.endpoint_key.as_bytes()))
        prompt += "with keyslot: {}\n".format(hexlify(get_key_slot(self.endpoint_key)))
        prompt += (
            "(Access Credential public key can be set with the {} "
            "test parameter)\n".format(self.ACCESS_CREDENTIAL_PUBLIC_KEY_KEY)
        )
        await self.send_prompt_request(
            OptionsSelectPromptRequest(prompt=prompt, options={"OK": 1})
        )
        self.next_step()

        # Test step 2
        # Display pop-up to put the User Device UT on the TH
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Tap User Device on the Test Harness NFC", options={"OK": 1}
            )
        )
        self.next_step()

        # Test step 3
        try:
            await self.reader.transaction_initiation()  # including select
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 4
        try:
            await self.reader.handle_auth0(
                transaction_type=Transaction.STANDARD,
                authentication_policy=AuthenticationPolicy.USER_DEVICE,
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 5
        try:
            await self.reader.handle_auth1(
                expected_response=Auth1Response.KEY_SLOT, certificate=True
            )
        except InvalidStatusError as error:
            logger.info(
                "Error status returned: 0x{:04x}, as expected".format(error.status)
            )
            pass
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        else:
            self.mark_step_failure("No error status returned")
            return
        self.next_step()
        
        # Test step 6
        try:
            await self.reader.handle_exchange(
                False, reader_status=ReaderStatus.READER_STATE_UNSECURED
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("NFC_UD_STANDARD_CERT_IN_AUTH1_WITH_CHAINING Cleanup")
        await self.reader.transaction_termination()
