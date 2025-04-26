from binascii import hexlify

from aliro_actuator.access_protocol.apdu import INS
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.user_device import UserDevice, RkeAction
from aliro_actuator.transport_protocol.ble_message_format import (
    Notification_ID,
    OperationSourceInformation_Values,
    ReaderStatusInformation_Values,
    UnsolicitedReaderStatusReporting_Values,
)
from aliro_actuator.transport_protocol.errors import NoDeviceConnectedError
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class BLEUWB_RDR_NEG_FAILED_L2CAP(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLEUWB_RDR_NEG_FAILED_L2CAP",
        "version": "0.0.1",
        "title": "BLEUWB_RDR_NEG_FAILED_L2CAP",
        "description": """Verify conformance of Reader in BLE discovery.""",
    }

    endpoint_ePuBK = bytes.fromhex(
        "045d75ab60136a2c54ff27b799ee157f3f3329435c0d"
        "f608de904c920ac29f72bd4274c2edc810a93e240bf5"
        "d6394a92c9766b690b2bf5128ae70d6e29257ea786"
    )  # from Test Vector
    endpoint_ePrivK = bytes.fromhex(
        "70637ee9b40cee568567c69589276888edca7128bb13fb531f9c4f502d8cc65e"
    )  # from Test Vector

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "",  # PICS in preparation
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Setup connection"),
            TestStep("Step2: Send initiate access protocol"),
            TestStep("Step3: Receive disconnect event"),
        ]

    async def setup(self) -> None:
        logger.info("This is a test case setup")
        self.access_credential = self.reader_access_credential(add_issuer_public_key=True)
        group_resolving_key = self.reader_group_resolving_key()
        self.userdevice = UserDevice(
            transport_protocol=TransportProtocol.BLE_UWB,
            access_credentials=[self.access_credential],
            mailbox=0x20,
            group_resolving_key=group_resolving_key,
            ephemeral_key_list=[KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK)],
        )

    @log_errors
    async def execute(self) -> None:
        # Test step 1
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Reset murata board by pressing switch SW1",
                options={"OK": 1},
            )
        )
        try:
            await self.send_prompt_request(
                OptionsSelectPromptRequest(
                    prompt="Set Reader Device Under Test in BLE advertising mode",
                    options={"OK": 1},
                )
            )
            await self.userdevice.setup_connection()
            self.userdevice.start_new_session()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 2
        try:
            etspv_bytes_imm = version.to_bytes(2, 'big')
            type = CSA_APPLICATION_TYPE
            proprietary_tlv: list[tuple[int, bytes | list]] = [
                (Select.TYPE_TAG, type.to_bytes(2, "big")),
                (Select.ETSPV_TAG, etspv_bytes_imm),
            ]

            proprietary = TLV(proprietary_tlv)
            
            proprietary_list: list[tuple[int, bytes | list]] = [
                (Select.PROPRIETARY_TAG, proprietary.to_bytes())
            ]
            proprietary_tlv = TLV(proprietary_list)
            message = BleMessage.create_initiate_access_protocol(proprietary_tlv.to_bytes())
            await self.transport_protocol.send_message(message)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 3
        try:
            cmds = await self.userdevice.wait_for_command(
                expected_command=INS.AUTH0
            )
            self.mark_step_failure("Wrong protocol version was accepted.")
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            logger.info(error_str)
            pass
        self.next_step()


    async def cleanup(self) -> None:
        logger.info("BLEUWB_RDR_NEG_FAILED_L2CAP Cleanup")
        try:
            await self.userdevice.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass
