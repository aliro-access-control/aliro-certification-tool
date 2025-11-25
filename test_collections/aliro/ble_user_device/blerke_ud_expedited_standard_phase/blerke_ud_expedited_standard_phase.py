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
)
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.transport_protocol import Mode
from aliro_actuator.transport_protocol.ble_message_format import (
    OperationSourceInformation_Values,
    ReaderStatusInformation_Values,
    UnsolicitedReaderStatusReporting_Values,
)
from aliro_actuator.trust_framework.certificate import Certificate
from aliro_actuator.trust_framework.key import KeyPair, PublicKey
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors


class BLERKE_UD_EXPEDITED_STANDARD_PHASE(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLERKE_UD_EXPEDITED_STANDARD_PHASE",
        "version": "0.0.1",
        "title": "BLERKE_UD_EXPEDITED_STANDARD_PHASE",
        "description": """Verify conformance of User Device UT in RKE command.""",
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
                "UD",
                "BLERKE",
                "UD47"
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Initialization"),
            TestStep("Step2: Execute Access Protocol Routine"),
            TestStep("Step3: Receive RKE request"),
            TestStep("Step4: Send Reader Status Changed"),
        ]

    async def setup(self) -> None:
        logger.info("BLERKE_UD_EXPEDITED_STANDARD_PHASE setup")
        group_id = self.th_group_identifier()
        sub_group_id = self.th_sub_group_identifier()
        key = self.th_reader_keypair()
        spsm = self.th_spsm()
        group_resolving_key = self.th_group_resolving_key()
        self.reader = Reader(
            transport_protocol=TransportProtocol.BLE_UWB,
            reader_group_identifier=group_id,
            reader_group_sub_identifier=sub_group_id,
            reader_key=key,
            spsm=spsm,
            group_resolving_key=group_resolving_key,
            ephemeral_key_list=[KeyPair(self.reader_ePrivK, self.reader_ePuBK)],
            enable_uwb=False,
        )

    @log_errors
    async def execute(self) -> None:
        # Test step 1
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Reset murata board by pressing switch SW1\n"
                "and start user device scanning",
                options={"OK": 1},
            )
        )
        self.next_step()
        
        # Test step 1
        try:
            logger.info("Setting up connection")
            await self.reader.transport_protocol.initialization(
                Mode.READER,
                reader_group_identifier=self.reader.reader_group_identifier,
                reader_group_sub_identifier=self.reader.reader_group_sub_identifier,
                group_resolving_key=self.reader.group_resolving_key,
                spsm=self.reader.spsm,
                timeout=self.reader.timeout,
                advertisement_version=self.reader.advertisement_version,
                enable_uwb=self.reader.enable_uwb,
                BLE_UWB_supported = False,
                BLE_only_supported = True,
            )
            await self.reader.transport_protocol.wait_for_connection()
            logger.info("Connection established")

            self.reader.start_new_session()
            # Setup UWB session id
            logger.info(f"Transaction ID: {self.reader.session.transaction_identifier}")
            if self.reader.enable_uwb:
                await self.reader.transport_protocol.driver.session_init(
                    session_id=self.reader.session.transaction_identifier[-4:]
                )
            await self.reader.wait_for_initiate_access_protocol_notification(rke=True)
            logger.info("Transaction Initiation Done")
            await self.reader.expedited_transaction_standard(
                authentication_policy=AuthenticationPolicy.USER_DEVICE_SECURE_ACTION
            )
            await self.reader.reader_status_access_protocol_completed(
                UnsolicitedReaderStatusReporting_Values.SEND_TO_EACH_CONNECTED,
                ReaderStatusInformation_Values.SECURED,
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()
        
        # Test step 2
        try:
            await self.reader.handle_rke_request()
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()
        
        if self.reader.rke_action == 0:
            reader_status = ReaderStatusInformation_Values.SECURED
        else:
            reader_status = ReaderStatusInformation_Values.UNSECURED
        
        # Test step 3: Reader sends AP message: Status changed
        try:
            await self.reader.reader_status_status_changed(
                OperationSourceInformation_Values.UNSPECIFIED,
                reader_status,
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("BLERKE_UD_EXPEDITED_STANDARD_PHASE Cleanup")
        await self.reader.transaction_termination()
