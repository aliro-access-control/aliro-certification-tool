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
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors


class UD_NFC_AUTH1_11(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "UD-NFC-AUTH1-1.1",
        "version": "0.0.1",
        "title": "UD-NFC-AUTH1-1.1",
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
            TestStep("Step5: Send/Receive LOAD_CERT command/response"),
            TestStep("Step6: Send/Receive AUTH1 command/response"),
        ]

    async def setup(self) -> None:
        logger.info("UD_NFC_AUTH1_11 setup")
        self.group_id = bytes.fromhex("00113344667799AA00113344667799AA")
        key = KeyPair(
            bytes.fromhex(
                "359449fb6b51ced37d8f516b175a9a210b1b1dcdbd15915e49296b5e802c2d40"
            ),
            bytes.fromhex(
                "0457a25ca8690e0409aa2a094a88f3894e136399efe35b7f25d2991c7ad206239867d9"
                "9e3f243afd6cec35c21bdee6521af12435e8c4ff9296d1ca970e6ca77b50"
            ),
        )
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
        self.reader_issuer_public_key = PublicKey(
            bytes.fromhex(
                "043928f322019d4757893bde6a0fe5e13e3e537b9ca0f549c0bd2f40f79060252a0a4f"
                "291192157a95cb6eb202759428c00cd834998c5d0eab192ee8873c5d34ee"
            )
        )
        endpoint_key = self.th_access_credential_public_key()

        # Initialize Aliro NFC Reader
        self.reader = Reader(
            transport_protocol=TransportProtocol.NFC,
            reader_group_identifier=self.group_id,
            reader_key=key,
            reader_cert=cert,
            transaction_identifier_list=[self.transaction_identifier],
            ephemeral_key_list=[KeyPair(self.reader_ePrivK, self.reader_ePuBK)],
            reader_system_issuer_ca=self.reader_issuer_public_key,
            key_slot_list=[endpoint_key],
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
            compressed_cert = bytearray(self.reader.reader_cert.encode_compressed())
            logger.debug("compressed cert: {!r}".format(hexlify(compressed_cert)))
            compressed_cert[6] = 0xFF
            compressed_cert[5] = 0xFF
            logger.debug(
                "compressed cert with encoding error: {!r}".format(
                    hexlify(compressed_cert)
                )
            )
            await self.reader.command_load_cert(bytes(compressed_cert))
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 6
        try:
            await self.reader.handle_auth1(expected_response=Auth1Response.KEY_SLOT)
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

    async def cleanup(self) -> None:
        logger.info("UD_NFC_AUTH1_11 Cleanup")
        await self.reader.transaction_termination()
