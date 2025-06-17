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


class BLEUWB_RDR_NEG_M4_MISMATCH_PARAMETER(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLEUWB_RDR_NEG_M4_MISMATCH_PARAMETER",
        "version": "0.0.1",
        "title": "BLEUWB_RDR_NEG_M4_MISMATCH_PARAMETER",
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
            TestStep("Step3: Send UWB RSS-M2"),
            TestStep("Step4: Send UWB RSS-M4 without UWBTime0"),
            TestStep("Step5: Reader sends event General error wrong parameters"),
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

    def create_ranging_session_setup_m4(
        self,
        sts_index0: int,
        hop_mode_key: int,
        sync_code_index: int,
        ble_encryption: EncryptionEngine | None = None,
    ) -> BleMessage:
        data = sts_index0.to_bytes(4, "big")
        sts_index0_attr = BleAttribute(UWB_AttributeID.STS_INDEX0, data)
        data = hop_mode_key.to_bytes(4, "big")
        hop_mode_key_attr = BleAttribute(UWB_AttributeID.HOP_MODE_KEY, data)
        data = sync_code_index.to_bytes(1, "big")
        sync_code_index_attr = BleAttribute(UWB_AttributeID.SYNC_CODE_INDEX, data)

        payload = bytearray()
        payload.extend(sts_index0_attr.to_bytes())
        payload.extend(hop_mode_key_attr.to_bytes())
        payload.extend(sync_code_index_attr.to_bytes())
        message = BleMessage(
            ProtocolType.UWB_RANGING_SERVICE,
            UWB_RangingService_ID.RANGING_SESSION_SETUP_M4,
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
        # Step3: Send UWB RSS-M2
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
        # Step4: Send UWB RSS-M4 without UWBTime0
        try:
            message = await self.userdevice.wait_for_ble_message(
                self.userdevice.session.get_ble_encryption()
            )
            message.parse_payload(self.userdevice.session.get_ble_encryption())
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        await self.userdevice.transport_protocol.set_ran_multiplier(
            int.from_bytes(message.ran_multiplier.value, "big")
        )
        slot_duration = (
            int.from_bytes(message.number_chaps_per_slot.value, "big") / 3 * 1200
        )
        await self.userdevice.transport_protocol.set_slot_duration(int(slot_duration))
        await self.userdevice.transport_protocol.set_number_responders(
            int.from_bytes(message.number_responder_nodes.value, "big")
        )
        await self.userdevice.transport_protocol.set_slots_per_round(
            int.from_bytes(message.number_slots_per_round.value, "big")
        )

        sync_code_bitmask = int.from_bytes(message.sync_code_index_bitmask.value, "big")
        sync_codes = []
        for bit_index in range(32):
            if sync_code_bitmask & (1 << bit_index):
                sync_codes.append(bit_index + 1)

        # pick the first sync code in the list
        await self.userdevice.transport_protocol.set_sync_code_index(sync_codes[0])

        await self.userdevice.set_hopping_conf(
            int.from_bytes(message.hopping_configuration_bitmask.value, "big")
        )
        await self.userdevice.transport_protocol.set_mac_mode(int.from_bytes(message.mac_mode.value, "big"))

        logger.info("Sending ranging session setup M4 ble message")
        sts_index0 = await self.userdevice.transport_protocol.get_sts_index0()
        uwb_time0 = await self.userdevice.transport_protocol.get_uwb_time0()
        hop_mode_key = await self.userdevice.transport_protocol.get_hop_mode_key()
        sync_code_index = await self.userdevice.transport_protocol.get_sync_code_index()

        message = self.create_ranging_session_setup_m4(
            sts_index0,
            hop_mode_key,
            sync_code_index,
            self.userdevice.session.get_ble_encryption(),
        )
        try:
            await self.userdevice.transport_protocol.send_message(message, timeout=self.userdevice.timeout)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Step5: Reader sends event General error wrong parameters
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
        logger.info("BLEUWB_RDR_NEG_M4_MISMATCH_PARAMETER Cleanup")
        try:
            await self.userdevice.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass