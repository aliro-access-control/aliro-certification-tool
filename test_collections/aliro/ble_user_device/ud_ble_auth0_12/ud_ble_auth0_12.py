from binascii import hexlify

from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    ReaderStatus,
    Transaction,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    PROTOCOL_VERSION,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidResponseError,
    InvalidStatusError,
)
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.trust_framework.key import KeyPair, PublicKey
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors


class UD_BLE_AUTH0_12(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "UD-BLE-AUTH0-1.2",
        "version": "0.0.1",
        "title": "UD-BLE-AUTH0-1.2",
        "description": """Verify conformance of User Device UT in AUTH0 command.""",
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
            TestStep("Step2: Transaction initiation"),
            TestStep("Step3: Send/Receive AUTH0 command/response"),
            TestStep("Step4: Send/Receive AUTH0 command/response"),
            TestStep("Step5: Send/Receive AUTH0 command/response"),
        ]

    async def setup(self) -> None:
        logger.info("UD_BLE_AUTH0_12 setup")
        # load parameters from project config
        self.group_id = self.th_group_identifier()
        self.sub_group_id = self.th_sub_group_identifier()
        key = self.th_reader_keypair()

        # Initialize Aliro BLE Reader
        self.reader = Reader(
            transport_protocol=TransportProtocol.BLE_UWB,
            reader_group_identifier=self.group_id,
            reader_group_sub_identifier=self.sub_group_id,
            reader_key=key,
            transaction_identifier_list=[self.transaction_identifier],
            ephemeral_key_list=[KeyPair(self.reader_ePrivK, self.reader_ePuBK)],
        )

    @log_errors
    async def execute(self) -> None:
        # from test_plan regular key pair #2 + set innappropriate public key type
        reader_epubkey_invalid_1 = bytes.fromhex(
            "02"
            "A6E979B0F9244E8656CB4A5CFEDAA742ED43AF6612DB5CFD8950A1850EA488C3"
            "14C9C12B497BD260C4A2FE1CD8CCF84D45D290456E7622CCD441ACE78CC7DE34"
        )

        # from test_plan regular key pair #2 + modify x-component length
        reader_epubkey_invalid_2 = bytes.fromhex(
            "04"
            "A6E979B0F9244E8656CB4A5CFEDAA742ED43AF6612DB5CFD8950A1850EA488C3C9"
            "14C9C12B497BD260C4A2FE1CD8CCF84D45D290456E7622CCD441ACE78CC7DE34"
        )

        # from test_plan regular key pair #2 + modify y-component length
        reader_epubkey_invalid_3 = bytes.fromhex(
            "04"
            "A6E979B0F9244E8656CB4A5CFEDAA742ED43AF6612DB5CFD8950A1850EA488C3"
            "14C9C12B497BD260C4A2FE1CD8CCF84D45D290456E7622CCD441ACE78CC7DE34C9"
        )
        
        # Test step 1
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Reset murata board by pressing switch SW1\n"
                "and start user device scanning",
                options={"OK": 1},
            )
        )
        self.next_step()

        # Test step 2
        try:
            await self.reader.transaction_initiation()  # including select
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 3
        # Verify Tag 0x86 contains a valid public key (start with 0x04)
        try:
            await self.reader.command_auth0(
                transaction=Transaction.STANDARD,
                authentication_policy=AuthenticationPolicy.USER_DEVICE,
                protocol_version=PROTOCOL_VERSION,
                reader_epubk=reader_epubkey_invalid_1,
                transaction_identifier=self.reader.session.transaction_identifier,
                reader_identifier=self.reader.reader_group_identifier
                + self.reader.reader_group_sub_identifier,
            )
            self.mark_step_failure(
                "Invalid reader ephemeral key send, but it was accepted as a valid "
                "key"
            )
            return
        except InvalidStatusError as error:
            logger.info(
                "Received error status (as expected), status received: 0x{:04x}".format(
                    error.status
                )
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()
        
        # Test step 4
        # Verify Tag 0x86 contains a valid public key (32 byte x)
        try:
            await self.reader.command_auth0(
                transaction=Transaction.STANDARD,
                authentication_policy=AuthenticationPolicy.USER_DEVICE,
                protocol_version=PROTOCOL_VERSION,
                reader_epubk=reader_epubkey_invalid_2,
                transaction_identifier=self.reader.session.transaction_identifier,
                reader_identifier=self.reader.reader_group_identifier
                + self.reader.reader_group_sub_identifier,
            )
            self.mark_step_failure(
                "Invalid reader ephemeral key send, but it was accepted as a valid "
                "key"
            )
            return
        except InvalidStatusError as error:
            logger.info(
                "Received error status (as expected), status received: 0x{:04x}".format(
                    error.status
                )
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()
        
        # Test step 6
        # Verify Tag 0x86 contains a valid public key (32 byte y)
        try:
            await self.reader.command_auth0(
                transaction=Transaction.STANDARD,
                authentication_policy=AuthenticationPolicy.USER_DEVICE,
                protocol_version=PROTOCOL_VERSION,
                reader_epubk=reader_epubkey_invalid_3,
                transaction_identifier=self.reader.session.transaction_identifier,
                reader_identifier=self.reader.reader_group_identifier
                + self.reader.reader_group_sub_identifier,
            )
            self.mark_step_failure(
                "Invalid reader ephemeral key send, but it was accepted as a valid "
                "key"
            )
            return
        except InvalidStatusError as error:
            logger.info(
                "Received error status (as expected), status received: 0x{:04x}".format(
                    error.status
                )
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("UD_BLE_AUTH0_12 Cleanup")
        await self.reader.transaction_termination()
