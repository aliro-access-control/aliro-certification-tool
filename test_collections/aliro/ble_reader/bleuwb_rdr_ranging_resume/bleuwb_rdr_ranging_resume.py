from binascii import hexlify
from enum import IntEnum
from aliro_actuator.access_protocol.apdu import INS
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.user_device import UserDevice
from aliro_actuator.transport_protocol.ble_message_format import (
    Notification_ID,
    UWB_RangingService_ID,
)
from aliro_actuator.access_protocol.errors import UnexpectedBLEMessageError
from aliro_actuator.transport_protocol.errors import NoDeviceConnectedError
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroReaderTestCase, log_errors
import time

class ProtocolType(IntEnum):
    AP = 0x00
    UWB_RANGING_SERVICE = 0x01
    NOTIFICATION = 0x02
    SUPPLEMENTARY_SERVICE = 0x03
    THIRD_PARTY_APP = 0x04

class BLEUWB_RDR_RANGING_RESUME(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLEUWB_RDR_RANGING_RESUME",
        "version": "0.0.1",
        "title": "BLEUWB_RDR_RANGING_RESUME",
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
            TestStep("Step0: Prerequisites"),
            TestStep("Step1: User Device sends AP message: Timesync"),
            TestStep("Step2: User Device sends AP message: Initiate Ranging"),
            TestStep("Step3: Reader sends AP message: RSS-M1"),
            TestStep("Step4: User Device sends AP message: RSS-M2"),
            TestStep("Step5: Reader sends AP message: RSS-M3"),
            TestStep("Step6: User Device sends AP message: RSS-M4"),
            TestStep("Step7: Reader acquires UWB ranging result"),
            TestStep("Step8: UserDevice sends Ranging Message ID carrying Ranging Session Suspended Attribute ID"),
            TestStep("Step9: UserDevice sends Ranging Message ID carrying Initiate Ranging Session Resume Attribute ID after 1 second"),
            TestStep("Step10: UserDevice Re-sends same Ranging Message ID carrying Initiate Ranging Session Resume Attribute ID"),
            TestStep("Step11: UserDevice send Ranging Session Resume Response"),
            
        ]

    def print_uwb_configuration(self, uwb_config: dict) -> None:
        logger.info("UWB Configuration is:")
        logger.info("-" * 50)
        for key, value in uwb_config.items():
            logger.info(f"{key:<12}: {value}")
        logger.info("-" * 50)

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
        # Done in setup
        issuer_group_id = self.access_credential.reader_id_key_list[1][0]
        prompt = "In case LOAD_CERT is used set correct group ID"
        prompt += "Set the reader_group_identifier of the reader device to: {}\n".format(hexlify(issuer_group_id))
        prompt += "to the Access Credential of the reader device\n"

        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt=prompt,
                options={"OK": 1},
            )
        )

        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Reset murata board by pressing switch SW1",
                options={"OK": 1},
            )
        )
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Set Reader Device Under Test in BLE advertising mode",
                options={"OK": 1},
            )
        )

        # Test step 0: Prerequisites
        try:
            await self.userdevice.single_transaction(False)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 1: User Device sends AP message: Timesync
        try:
            await self.userdevice.send_timesync()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 2: User Device sends AP message: Initiate Ranging
        try:
            await self.userdevice.send_initiate_ranging()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 3: Reader sends AP message: RSS-M1
        # Test step 4: User Device sends AP message: RSS-M2
        try:
            message = await self.userdevice.wait_for_ble_message(
                self.userdevice.session.get_ble_encryption()
            )
            await self.userdevice.handle_ranging_setup_m1(message)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()
        self.next_step()

        # Test step 5: Reader sends AP message: RSS-M3
        # Test step 6: User Device sends AP message: RSS-M4
        try:
            message = await self.userdevice.wait_for_ble_message(
                self.userdevice.session.get_ble_encryption()
            )
            await self.userdevice.handle_ranging_setup_m3(message)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()
        self.next_step()

        # Test step 7: Reader acquires UWB ranging result
        # only reader
        try:
            await self.userdevice.transport_protocol.start_ranging()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        # Print UWB configuration
        try:
            uwb_configuration = (
                await self.userdevice.transport_protocol.get_uwb_configuration()
            )
            self.print_uwb_configuration(uwb_configuration)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 8: UserDevice sends Ranging Message ID carrying Ranging Session Suspended Attribute ID
        try:
            await self.userdevice.send_ranging_message_suspended()
            message = await self.userdevice.wait_for_ble_message()
            message = await self.userdevice.wait_for_ble_message()
            await self.userdevice.send_ranging_session_suspend_response()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 9: UserDevice sends Ranging Message ID carrying Initiate Ranging Session Resume Attribute ID after 1 second
        time.sleep(1)
        try:
            await self.userdevice.send_ranging_message_resume()
            message = await self.userdevice.wait_for_ble_message()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        #check message contains correct header id and attribute for resume request
        if message.header != ProtocolType.UWB_RANGING_SERVICE or message.id != UWB_RangingService_ID.RANGING_SESSION_RESUME_REQUEST:
            #message.parse_payload(self.userdevice.session.get_ble_encryption())
            raise UnexpectedBLEMessageError(
                "Received unexpected ble message while waiting for "
                "AP command message",
                message.header,
                message.id,
            )
        self.next_step()

        # Test step 10: UserDevice Re-sends same Ranging Message ID carrying Initiate Ranging Session Resume Attribute ID
        try:
            await self.userdevice.send_ranging_message_resume()
            message = await self.userdevice.wait_for_ble_message()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        #check message contains correct header id and attribute for resume request
        if message.header != ProtocolType.UWB_RANGING_SERVICE or message.id != UWB_RangingService_ID.RANGING_SESSION_RESUME_REQUEST:
            #message.parse_payload(self.userdevice.session.get_ble_encryption())
            raise UnexpectedBLEMessageError(
                "Received unexpected ble message while waiting for "
                "AP command message",
                message.header,
                message.id,
            )
        self.next_step()

        # Test step 11: UserDevice send Ranging Session Resume Response 
        try:
            await self.userdevice.send_ranging_session_resume_response()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        
    async def cleanup(self) -> None:
        logger.info("BLEUWB_RDR_RANGING_RESUME Cleanup")
        try:
            await self.userdevice.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass
