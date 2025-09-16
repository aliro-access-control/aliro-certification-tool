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
from aliro_actuator.access_protocol.reader import Reader, ReaderMode
from aliro_actuator.trust_framework.certificate import Certificate
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors

import random

class NFC_UD_NEG_STANDARD_CERT_IN_LOAD_CERT_WITH_CHAINING_INCORRECT_FORMAT(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_UD_NEG_STANDARD_CERT_IN_LOAD_CERT_WITH_CHAINING_INCORRECT_FORMAT",
        "version": "0.0.1",
        "title": "NFC_UD_NEG_STANDARD_CERT_IN_LOAD_CERT_WITH_CHAINING_INCORRECT_FORMAT",
        "description": """Expedited Standard Phase with Reader Certificate in LOAD_CERT with APDU Chaining.""",
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
            TestStep("Step5: Send/Receive LOAD_CERT command/response")
        ]

    async def setup(self) -> None:
        logger.info("This is a test case setup")
        # load parameters from project config
        group_id = self.th_group_identifier()
        sub_group_id = self.th_sub_group_identifier()
        key = self.th_reader_keypair()
        cert = bytes.fromhex(
            "308201513081f9a003020102020101300a06082a8648ce3d0403023011310f300d06035504"
            "030c06697373756572301e170d3230303130313030303030305a170d343930313031303030"
            "3030305a30123110300e06035504030c077375626a6563743059301306072a8648ce3d0201"
            "06082a8648ce3d0301070342000457a25ca8690e0409aa2a094a88f3894e136399efe35b7f"
            "25d2991c7ad206239867d99e3f243afd6cec35c21bdee6521af12435e8c4ff9296d1ca970e"
            "6ca77b50a341303f301f0603551d230418301680147fc93128a61c0cedf94e11732dbe4601"
            "7c431901300c0603551d130101ff04023000300e0603551d0f0101ff040403020780300a06"
            "082a8648ce3d040302034700304402207c387cfebd826878541f2202316338446509b6a222"
            "5c748571137c9303fb685e02204678b2021fc6623a0796a630d4c2b840ed86e9bbea7043ab"
            "cb4a766b881a457d"
        )
        reader_issuer_public_key = self.th_reader_issuer_public_key()

        # Initialize Aliro NFC Reader
        self.reader = Reader(
            transport_protocol=TransportProtocol.NFC,
            reader_group_identifier=group_id,
            reader_group_sub_identifier=sub_group_id,
            reader_key=key,
            reader_cert=cert,
            transaction_identifier_list=[self.transaction_identifier],
            ephemeral_key_list=[KeyPair(self.reader_ePrivK, self.reader_ePuBK)],
            reader_system_issuer_ca=reader_issuer_public_key,
            mode=ReaderMode.READER,
        )

    @log_errors
    async def execute(self) -> None:
        # Test step 1
        # Done in setup
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
        authentication_policy = random.randint(
            AuthenticationPolicy.USER_DEVICE, 
            AuthenticationPolicy.FORCE_USER_AUTHENTICATION
        )
        try:
            await self.reader.handle_auth0(
                transaction_type=Transaction.STANDARD,
                authentication_policy=AuthenticationPolicy(authentication_policy),
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 5
        compressed_cert = bytearray(self.reader.reader_cert.encode_compressed())
        logger.debug("compressed cert: {!r}".format(hexlify(compressed_cert)))
        compressed_cert[6] = 0xFF
        compressed_cert[5] = 0xFF
        logger.debug(
            "compressed cert with encoding error: {!r}".format(
                hexlify(compressed_cert)
            )
        )

        try:
            await self.reader.command_load_cert(bytes(compressed_cert))
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        except InvalidStatusError:
            self.next_step()
            return  # success!

        self.mark_step_failure("Expected non-successful return status, but got success")

    async def cleanup(self) -> None:
        logger.info("NFC_UD_NEG_STANDARD_CERT_IN_LOAD_CERT_WITH_CHAINING_INCORRECT_FORMAT Cleanup")
        await self.reader.transaction_termination()
