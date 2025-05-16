from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    Transaction,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.hw_driver.murata_driver import (
    ReaderMurataDriver,
    UserDeviceMurataDriver,
)
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.transport_protocol.errors import NoDeviceConnectedError
from aliro_actuator.trust_framework.key import KeyPair
from aliro_actuator import Global
from aliro_actuator.transport_protocol import ALIRO_BLUETOOTH_LE_ADVERTISEMENT_VERSION
from aliro_actuator.transport_protocol.ble_uwb import BLEUWB
from aliro_actuator.hw_driver.murata_driver.fsci import (
    Message,
)
from aliro_actuator.hw_driver.murata_driver.opcodes import OpCodeGAP, OpGroup
from aliro_actuator.hw_driver.murata_driver.base_driver import MurataBaseDriver
import ucitool.base_uci.helpers.uci_helper as uci
from aliro_actuator.hw_driver.murata_driver.encryption import dynamic_tag_generation
from aliro_actuator.hw_driver.murata_driver.endianness import change_endianness
import os

from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors

SUPPORTED_VERSIONS = [0x0100]
DEFAULT_PORT = os.getenv('TH_MURATA_COM', '/dev/ttyUSB0')
DEFAULT_BAUDRATE = "230400"
ALIRO_SERVICE_UUID = bytes.fromhex("FFF2")

class BLEUWB_UD_NEG_WRONG_ADV(AliroUserDeviceTestCase, UserPromptSupport, MurataBaseDriver):
    metadata = {
        "public_id": "BLEUWB_UD_NEG_WRONG_ADV",
        "version": "0.0.1",
        "title": "BLEUWB_UD_NEG_WRONG_ADV",
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
            TestStep("Step1: Send Bluetooth LE advertisement by setting 6th and 7th bits of adv_ind payload to 0"),    
        ]

    async def set_advertising_data_with_modified_bits(
        self,
        service_uuid: bytes,
        notification: int,
        advertisement_version: int,
        tx_power: int,
        reader_group_identifier: bytes,
        reader_group_sub_identifier: bytes,
        dynamic_tag_timestamp: bytes,
        dynamic_tag: bytes,
        BLE_UWB_supported: bool = True,
        BLE_only_supported: bool = True,
    ) -> None:
        Global.logger.debug("Setting advertising data")

        byte_7 = advertisement_version & 0x07
        byte_7 |= (notification & 0x3) << 3

        '''
        if BLE_UWB_supported:   # Setting bit 7 and bit 6 of byte_7 to 0
            byte_7 |= 1 << 7
        if BLE_only_supported:
            byte_7 |= 1 << 6
        '''
        data = bytearray()
        data.append(0x01)  # advertising data included
        # advertising data
        data.append(0x02)  # Number of advertising data structures
        # element 1
        data.append(0x01)  # length (-1)
        data.append(0x01)  # Type (Flags)
        data.append(0x06)  # Data
        # element 2
        data.append(0x1A)  # length (-1)
        data.append(0x16)  # Type (Service data (16 bit UUID))
        data.extend(change_endianness(service_uuid))  # Aliro service UUID
        data.append(byte_7)
        data.append(tx_power)
        data.extend(reader_group_identifier[:8])
        data.extend(reader_group_sub_identifier[:2])
        data.extend(dynamic_tag_timestamp[:4])
        data.append(0x00)  # RFU
        data.extend(dynamic_tag[:7])

        data.append(0x00)  # Scan response data included
        # scan response data

        message = Message(OpGroup.GAP, OpCodeGAP.SET_ADVERTISING_DATA, len(data), data)
        self.write(message)
        await self.wait_for_confirm(OpGroup.GAP)
        await self.wait_for_message(
            OpGroup.GAP, OpCodeGAP.GENERIC_EVENT_ADVERTISING_DATA_SETUP_COMPLETE
        )
        Global.logger.debug("Advertising data setup complete")

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

        # Test step 1: Send Bluetooth LE advertisement by setting 6th and 7th bits of adv_ind payload to 0
        try:
            Global.logger.info("Setting up connection")
            driver: ReaderMurataDriver | UserDeviceMurataDriver = (
                ReaderMurataDriver(DEFAULT_PORT, DEFAULT_BAUDRATE)
            )
            supported_versions = SUPPORTED_VERSIONS
            await driver.uci_initialize(
                session_id=1,
                dev_role=uci.APP_CFG.DEVICE_ROLE.RESPONDER,
                dev_type=uci.APP_CFG.DEVICE_TYPE.CONTROLEE,
            )
            await driver.setup_gatt_database(
                self.reader.spsm,
                supported_versions,
                time_sync_0 = True,
                time_sync_1 = True,
                LE_coded_phy = True,
            )

            Global.logger.info("setup ble connection")
            advertising_address = await driver.read_public_device_address()
            dynamic_tag = dynamic_tag_generation(
                self.reader.group_resolving_key, advertising_address, expiry_timestamp = bytes.fromhex("7a4b8500")
            )
            await driver.set_advertising_parameters()
            await self.set_advertising_data_with_modified_bits(
                ALIRO_SERVICE_UUID,
                notification = 0x00,
                advertisement_version = ALIRO_BLUETOOTH_LE_ADVERTISEMENT_VERSION,
                tx_power=0x00,
                reader_group_identifier = self.reader.reader_group_identifier,
                reader_group_sub_identifier = self.reader.reader_group_sub_identifier,
                dynamic_tag_timestamp = bytes.fromhex("7a4b8500"),
                dynamic_tag=dynamic_tag,
                BLE_UWB_supported = True,
                BLE_only_supported = False,
            )
            await driver.set_tx_power_level(0, 0)
            await driver.start_advertising()
            
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step() 
        
    async def cleanup(self) -> None:
        logger.info("BLEUWB_UD_NEG_WRONG_ADV Cleanup")
        try:
            await self.reader.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass