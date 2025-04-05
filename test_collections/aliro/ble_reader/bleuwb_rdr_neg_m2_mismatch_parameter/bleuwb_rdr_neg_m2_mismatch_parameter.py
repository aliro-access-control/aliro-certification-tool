from binascii import hexlify

from aliro_actuator.access_protocol.apdu import INS
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.encryption import EncryptionEngine
from aliro_actuator.access_protocol.user_device import UserDevice
from aliro_actuator.transport_protocol.ble_message_format import (
    BleAttribute,
    BleMessage,
    GeneralError_Values,
    Notification_ID,
    UWB_AttributeID,
    ProtocolType,
    UWB_RangingService_ID,
)
from aliro_actuator.hw_driver.murata_driver.uwb_driver import (
    Channel,
)
from aliro_actuator.transport_protocol.errors import NoDeviceConnectedError
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class BLEUWB_RDR_NEG_M2_MISMATCH_PARAMETER(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLEUWB_RDR_NEG_M2_MISMATCH_PARAMETER",
        "version": "0.0.1",
        "title": "BLEUWB_RDR_NEG_M2_MISMATCH_PARAMETER",
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
            TestStep("Step3: Send UWB RSS-M2 without uwb_config_id"),
            TestStep("Step4: Reader sends event General error wrong parameters"),
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

    def create_ranging_session_setup_m2(
        self,
        selected_pulse_shape_combination: int,
        channel_bitmask: int,
        sync_code_index_bitmask: int,
        ran_multiplier: int,
        slot_bitmask: int,
        hopping_conf_bitmask: int,
        vendor_specific: int,
        ble_encryption: EncryptionEngine | None = None,
    ) -> BleMessage:
        data = selected_pulse_shape_combination.to_bytes(1, "big")
        selected_pulse_shape_combination_attr = BleAttribute(
            UWB_AttributeID.PULSE_SHAPE_COMBO, data
        )
        data = channel_bitmask.to_bytes(1, "big")
        channel_bitmask_attr = BleAttribute(UWB_AttributeID.CHANNEL_BITMASK, data)
        data = sync_code_index_bitmask.to_bytes(4, "big")
        sync_code_index_bitmask_attr = BleAttribute(
            UWB_AttributeID.SYNC_CODE_INDEX_BITMASK, data
        )
        data = ran_multiplier.to_bytes(1, "big")
        ran_multiplier_attr = BleAttribute(UWB_AttributeID.RAN_MULTIPLIER, data)
        data = slot_bitmask.to_bytes(1, "big")
        slot_bitmask_attr = BleAttribute(UWB_AttributeID.SLOT_BITMASK, data)
        data = hopping_conf_bitmask.to_bytes(1, "big")
        hopping_conf_bitmask_attr = BleAttribute(
            UWB_AttributeID.HOPPING_CONFIGURATION_BITMASK, data
        )

        # vendor specific information
        data = vendor_specific.to_bytes(3, "big")
        vendor_specific_attr = BleAttribute(UWB_AttributeID.VENDOR_SPECIFIC, data)

        payload = bytearray()
        payload.extend(selected_pulse_shape_combination_attr.to_bytes())
        payload.extend(channel_bitmask_attr.to_bytes())
        payload.extend(sync_code_index_bitmask_attr.to_bytes())
        payload.extend(ran_multiplier_attr.to_bytes())
        payload.extend(slot_bitmask_attr.to_bytes())
        payload.extend(hopping_conf_bitmask_attr.to_bytes())
        payload.extend(vendor_specific_attr.to_bytes())
        message = BleMessage(
            ProtocolType.UWB_RANGING_SERVICE,
            UWB_RangingService_ID.RANGING_SESSION_SETUP_M2,
            payload,
        )
        message._encrypt(ble_encryption)
        return message

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

        # Step0: Prerequisites
        try:
            await self.userdevice.single_transaction(False)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Step1: User Device sends AP message: Timesync
        try:
            await self.userdevice.send_timesync()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # User Device sends AP message: Initiate Ranging
        try:
            await self.userdevice.send_initiate_ranging()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Step3: Send UWB RSS-M2 without uwb_config_id
        try:
            message = await self.userdevice.wait_for_ble_message(
                self.userdevice.session.get_ble_encryption()
            )
            message.parse_payload(self.userdevice.session.get_ble_encryption())
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        # Configure selected configuration ID
        self.userdevice.selected_config_id = self.userdevice.select_config_id(
            message.uwb_configuration_id.value,
            self.userdevice.transport_protocol.get_uwb_config_id_support().to_bytes(2, "big")
        )
        if self.userdevice.selected_config_id is not None:
            await self.userdevice.transport_protocol.set_uwb_config_id(self.userdevice.selected_config_id)

        # Configure selected pulse shape combo for the user device
        self.userdevice.selected_pulse_shape_combination = self.userdevice.select_pulseshape_combo(
            message.pulse_shape_combo.value,
            self.userdevice.transport_protocol.get_pulse_shape_combination_support().to_bytes(
                3, "big"
            ),
        )
        if self.userdevice.selected_pulse_shape_combination is not None:
            await self.userdevice.transport_protocol.set_pulse_shape_combination(
                self.userdevice.selected_pulse_shape_combination
            )
        else:
            self.mark_step_failure("Invalid Pulse shape combo")
            return

        await self.userdevice.transport_protocol.set_channel_bitmask(
            int.from_bytes(message.channel_bitmask.value, "big")
        )
        received_session_id = int.from_bytes(message.uwb_session_id.value, "big")
        uwb_session_id = self.userdevice.transport_protocol.get_uwb_session_id()
        if received_session_id != uwb_session_id:
            raise InvalidUWBSessionId

        logger.info("Sending ranging session setup M2 ble message")

        uwb_configuration_id = await self.userdevice.transport_protocol.get_uwb_config_id()
        logger.info(f"uwb_config_id = {uwb_configuration_id}")
        channel_bitmask = Channel.CHANNEL_9
        sync_code_index_bitmask = self.userdevice.transport_protocol.get_sync_code_bitmask()
        ran_multiplier = await self.userdevice.transport_protocol.get_ran_multiplier()
        slot_bitmask = self.userdevice.transport_protocol.get_slot_bitmask()
        hopping_conf_bitmask = self.userdevice.transport_protocol.get_hopping_config_bitmask()
        vendor_specific = 0xFF

        message = self.create_ranging_session_setup_m2(
            self.userdevice.selected_pulse_shape_combination,
            channel_bitmask,
            sync_code_index_bitmask,
            ran_multiplier,
            slot_bitmask,
            hopping_conf_bitmask,
            vendor_specific,
            self.userdevice.session.get_ble_encryption(),
        )
        try:
            await self.userdevice.transport_protocol.send_message(message, timeout=self.userdevice.timeout)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Step4: Reader sends event General error wrong parameters
        try:
            message_event = await self.userdevice.wait_for_ble_message(
                self.userdevice.session.get_ble_encryption()
            )
            message_event.parse_payload(self.userdevice.session.get_ble_encryption())
            if message_event.id != Notification_ID.EVENT or message_event.reason_code != GeneralError_Values.WRONG_PARAMETERS:
                self.mark_step_failure("Unexpected message received")
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return


    async def cleanup(self) -> None:
        logger.info("BLEUWB_RDR_RANGING_SUSPEND Cleanup")
        try:
            await self.userdevice.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass