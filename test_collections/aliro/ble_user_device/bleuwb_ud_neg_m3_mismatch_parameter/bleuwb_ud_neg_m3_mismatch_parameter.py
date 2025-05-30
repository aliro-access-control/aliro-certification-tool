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


class BLEUWB_UD_NEG_M3_MISMATCH_PARAMETER(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLEUWB_UD_NEG_M3_MISMATCH_PARAMETER",
        "version": "0.0.1",
        "title": "BLEUWB_UD_NEG_M3_MISMATCH_PARAMETER",
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
            TestStep("Step3: Reader sends AP message: RSS-M1"),
            TestStep("Step4: Reader sends AP message: RSS-M3 without RAN Multiplier"),
            TestStep("Step5: User Device sends event General error wrong parameters"),
        ]

    def print_uwb_configuration(self, uwb_config: dict) -> None:
        logger.info("UWB Configuration is:")
        logger.info("-" * 50)
        for key, value in uwb_config.items():
            logger.info(f"{key:<12}: {value}")
        logger.info("-" * 50)

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

    def create_ranging_session_setup_m3(
        self,
        ran_multiplier: int | None = None,
        num_chaps_per_slot: int | None = None,
        number_responder_nodes: int | None = None,
        number_slots_per_round: int | None = None,
        sync_code_index_bitmask: int | None = None,
        hopping_conf_bitmask: int | None = None,
        mac_mode: int | None = None,
        vendor_specific: int | None = None,
        ble_encryption: EncryptionEngine | None = None,
    ) -> BleMessage:
        if ran_multiplier is not None:
            data = ran_multiplier.to_bytes(1, "big")
            ran_multiplier_attr = BleAttribute(UWB_AttributeID.RAN_MULTIPLIER, data)
        if num_chaps_per_slot is not None:
            data = num_chaps_per_slot.to_bytes(1, "big")
            num_chaps_per_slot_attr = BleAttribute(
                UWB_AttributeID.NUMBER_CHAPS_PER_SLOT, data
            )
        if number_responder_nodes is not None:
            data = number_responder_nodes.to_bytes(1, "big")
            number_responder_nodes_attr = BleAttribute(
                UWB_AttributeID.NUMBER_RESPONDERS_NODES, data
            )
        if number_slots_per_round is not None:
            data = number_slots_per_round.to_bytes(1, "big")
            number_slots_per_round_attr = BleAttribute(
                UWB_AttributeID.NUMBER_SLOTS_PER_ROUND, data
            )
        if sync_code_index_bitmask is not None:
            data = sync_code_index_bitmask.to_bytes(4, "big")
            sync_code_index_bitmask_attr = BleAttribute(
                UWB_AttributeID.SYNC_CODE_INDEX_BITMASK, data
            )
        if hopping_conf_bitmask is not None:
            data = hopping_conf_bitmask.to_bytes(1, "big")
            hopping_conf_bitmask_attr = BleAttribute(
                UWB_AttributeID.HOPPING_CONFIGURATION_BITMASK, data
            )
        if mac_mode is not None:
            data = mac_mode.to_bytes(1, "big")
            mac_mode_attr = BleAttribute(UWB_AttributeID.MAC_MODE, data)

        # vendor specific information
        if vendor_specific is not None:
            data = vendor_specific.to_bytes(3, "big")
            vendor_specific_attr = BleAttribute(UWB_AttributeID.VENDOR_SPECIFIC, data)

        payload = bytearray()
        if ran_multiplier is not None: 
            payload.extend(ran_multiplier_attr.to_bytes())
        if num_chaps_per_slot_attr is not None: 
            payload.extend(num_chaps_per_slot_attr.to_bytes())
        if number_responder_nodes_attr is not None: 
            payload.extend(number_responder_nodes_attr.to_bytes())
        if number_slots_per_round_attr is not None: 
            payload.extend(number_slots_per_round_attr.to_bytes())
        if sync_code_index_bitmask_attr is not None: 
            payload.extend(sync_code_index_bitmask_attr.to_bytes())
        if hopping_conf_bitmask_attr is not None: 
            payload.extend(hopping_conf_bitmask_attr.to_bytes())
        if mac_mode_attr is not None: 
            payload.extend(mac_mode_attr.to_bytes())
        payload.extend(vendor_specific_attr.to_bytes())
        message = BleMessage(
            ProtocolType.UWB_RANGING_SERVICE,
            UWB_RangingService_ID.RANGING_SESSION_SETUP_M3,
            payload,
        )
        message._encrypt(ble_encryption)
        return message

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
            await self.reader.send_ranging_session_setup_m1()
            # Await M2
            message = await self.reader.wait_for_ble_message(
                self.reader.session.get_ble_encryption()
            )
            message.parse_payload(self.reader.session.get_ble_encryption())

            ran_multiplier = int.from_bytes(message.ran_multiplier.value, "big")
            if (ran_multiplier >= 1) and (ran_multiplier <= 255):
                await self.reader.transport_protocol.set_ran_multiplier(ran_multiplier)
            else:
                self.mark_step_failure("Invalid RAN multiplier")

            self.reader.common_sync_code_index_bitmask = self.reader.common_sync_code_index(
                int.from_bytes(message.sync_code_index_bitmask.value, "big"),
                self.reader.transport_protocol.get_sync_code_bitmask(),
            )

            await self.reader.set_hopping_conf(
                int.from_bytes(message.hopping_configuration_bitmask.value, "big"),
                self.reader.transport_protocol.get_hopping_config_bitmask(),
            )

        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Test step 4: Reader sends AP message: RSS-M3 without RAN Multiplier
        try:
            logger.info("Sending ranging session setup M3 ble message")

            ran_multiplier = await self.reader.transport_protocol.get_ran_multiplier()
            num_chaps_per_slot = await self.reader.transport_protocol.get_num_chaps_per_slot()
            number_responder_nodes = await self.reader.transport_protocol.get_number_responders()
            number_slots_per_round = await self.reader.transport_protocol.get_slots_per_round()
            mac_mode = await self.reader.transport_protocol.get_mac_mode()
            vendor_specific = 0xFF

            message = self.create_ranging_session_setup_m3(
                ran_multiplier = None,
                num_chaps_per_slot = num_chaps_per_slot,
                number_responder_nodes = number_responder_nodes,
                number_slots_per_round = number_slots_per_round,
                sync_code_index_bitmask = self.reader.common_sync_code_index_bitmask,
                hopping_conf_bitmask = self.reader.common_hopping_conf,
                mac_mode = mac_mode,
                vendor_specific = vendor_specific,
                ble_encryption = self.reader.session.get_ble_encryption(),
            )
            await self.reader.transport_protocol.send_message(message)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)

        self.next_step()
        # Step5: User Device sends event General error wrong parameters
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
