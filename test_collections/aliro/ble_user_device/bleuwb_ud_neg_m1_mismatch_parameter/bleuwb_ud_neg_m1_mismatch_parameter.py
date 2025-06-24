from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    Transaction,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.transport_protocol.ble_message_format import (
    BleMessage,
    BleAttribute,
    ProtocolType,
    UWB_RangingService_ID,
    UWB_AttributeID,
    OperationSourceInformation_Values,
    ReaderStatusInformation_Values,
    UnsolicitedReaderStatusReporting_Values,
    Notification_ID,
    GeneralError_Values,
)
from aliro_actuator.transport_protocol.errors import NoDeviceConnectedError
from aliro_actuator.trust_framework.key import KeyPair
from aliro_actuator.access_protocol.encryption import EncryptionEngine
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors


class BLEUWB_UD_NEG_M1_MISMATCH_PARAMETER(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLEUWB_UD_NEG_M1_MISMATCH_PARAMETER",
        "version": "0.0.1",
        "title": "BLEUWB_UD_NEG_M1_MISMATCH_PARAMETER",
        "description": """Verify conformance of User Device UT in BLE discovery.""",
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
    group_resolving_key = 16 * bytes.fromhex("00")

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
            TestStep("Step3: Reader sends AP message: RSS-M1 without UWB_CONFIG_ID"),
            TestStep("Step4: User Device sends event General error wrong parameters"),
        ]

    def print_uwb_configuration(self, uwb_config: dict) -> None:
        logger.info("UWB Configuration is:")
        logger.info("-" * 50)
        for key, value in uwb_config.items():
            logger.info(f"{key:<12}: {value}")
        logger.info("-" * 50)

    def create_ranging_session_setup_m1(
        self,
        uwb_configuration_id: int | None = None,
        pulse_shape_combination: int | None = None,
        channel_bitmask: int | None = None,
        uwb_session_id: int | None = None,
        vendor_specific: int | None = None,
        ble_encryption: EncryptionEngine | None = None,
    ) -> BleMessage:
        if uwb_configuration_id is not None: 
            data = uwb_configuration_id.to_bytes(2, "big")
            uwb_configuration_id_attr = BleAttribute(
                UWB_AttributeID.UWB_CONFIGURATION_IDENTIFIER, data
            )
        if pulse_shape_combination is not None:
            data = pulse_shape_combination.to_bytes(3, "big")
            pulse_shape_combination_attr = BleAttribute(
                UWB_AttributeID.PULSE_SHAPE_COMBO, data
            )
        if channel_bitmask is not None:
            data = channel_bitmask.to_bytes(1, "big")
            channel_bitmask_attr = BleAttribute(UWB_AttributeID.CHANNEL_BITMASK, data)
        if uwb_session_id is not None:
            data = uwb_session_id.to_bytes(4, "big")
            uwb_session_id_attr = BleAttribute(UWB_AttributeID.UWB_SESSION_IDENTIFIER, data)

        # vendor specific information
        data = vendor_specific.to_bytes(3, "big")
        vendor_specific_attr = BleAttribute(UWB_AttributeID.VENDOR_SPECIFIC, data)
        payload = bytearray()
        if uwb_configuration_id is not None:
            payload.extend(uwb_configuration_id_attr.to_bytes())
        if pulse_shape_combination is not None:
            payload.extend(pulse_shape_combination_attr.to_bytes())
        if channel_bitmask is not None:
            payload.extend(channel_bitmask_attr.to_bytes())
        if uwb_session_id is not None:
            payload.extend(uwb_session_id_attr.to_bytes())
        if vendor_specific is not None:
            payload.extend(vendor_specific_attr.to_bytes())
        message = BleMessage(
            ProtocolType.UWB_RANGING_SERVICE,
            UWB_RangingService_ID.RANGING_SESSION_SETUP_M1,
            payload,
        )
        message._encrypt(ble_encryption)
        return message

    async def setup(self) -> None:
        logger.info("This is a test case setup")
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
        )

    @log_errors
    async def execute(self) -> None:
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Reset murata board by pressing switch SW1",
                options={"OK": 1},
            )
        )
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Start user device scanning", options={"OK": 1}
            )
        )

        # Test step 0: Prerequisites
        try:
            await self.reader.transaction_initiation()
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
        # Test step 1: User Device sends AP message: Timesync
        try:
            message = await self.reader.wait_for_ble_message(
                self.reader.session.get_ble_encryption()
            )
            self.reader.handle_timesync(message)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Test step 2: User Device sends AP message: Initiate Ranging
        try:
            message = await self.reader.wait_for_ble_message(
                self.reader.session.get_ble_encryption()
            )
            message.parse_payload(self.reader.session.get_ble_encryption())
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Test step 3: Reader sends AP message: RSS-M1
        try:
            logger.info("Sending ranging session setup M1 ble message")

            # uwb_configuration_id = self.transport_protocol.get_uwb_config_id_support()
            pulse_shape_combination = (
                self.reader.transport_protocol.get_pulse_shape_combination_support()
            )
            channel_bitmask = self.reader.transport_protocol.get_channel_bitmask()
            uwb_session_id = self.reader.transport_protocol.get_uwb_session_id()
            vendor_specific = 0xFF

            message = self.create_ranging_session_setup_m1(
                # Don't pass UWB Config ID
                pulse_shape_combination = pulse_shape_combination,
                channel_bitmask = channel_bitmask,
                uwb_session_id = uwb_session_id,
                vendor_specific = vendor_specific,
                ble_encryption = self.reader.session.get_ble_encryption(),
            )
            await self.reader.transport_protocol.send_message(message)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)

        self.next_step()
        # Step4: User Device sends event General error wrong parameters
        try:
            message_event = await self.reader.wait_for_ble_message(
                self.reader.session.get_ble_encryption()
            )
            message_event.parse_payload(self.reader.session.get_ble_encryption())
            if message_event.id != Notification_ID.EVENT or message_event.reason_code != GeneralError_Values.WRONG_PARAMETERS:
                self.mark_step_failure("Unexpected message received")
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

    async def cleanup(self) -> None:
        logger.info("BLEUWB_UD_RANGING_SUSPEND Cleanup")
        try:
            await self.reader.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass
