from binascii import hexlify

from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.user_device import UserDevice
from aliro_actuator.transport_protocol import Mode
from aliro_actuator.transport_protocol.ble_uwb import CURRENT_VERSION
from aliro_actuator.transport_protocol.errors import NoDeviceConnectedError
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class RD_BLE_STDTXN_10(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "RD-BLE-STDTXN-1.0",
        "version": "0.0.1",
        "title": "RD-BLE-STDTXN-1.0",
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
            TestStep("Step1: Configure User Device to scan for BLE advertisements"),
            TestStep("Step2: Reader sends BLE packet: ADV_IND"),
            TestStep("Step3: User Device sends BLE packet: CONNECT_IND"),
            TestStep("Step4: User Device discovers services (GATT client)"),
            TestStep("Step5: Reader discovers services (GATT server)"),
            TestStep("Step6: Device sends BLE host Command"),
            TestStep("Step7: Reader sends BLE host response"),
            TestStep("Step8: Device BLE Host discovers GATT characteristics"),
            TestStep("Step9: Reader BLE Host discovers GATT characteristics"),
            TestStep("Step10: Device sends BLE host command: ATT_READ_BY_TYPE_REQ"),
            TestStep("Step11: Reader sends BLE host response: ATT_READ_BY_TYPE_RSP"),
            TestStep("Step12: Device sends BLE host command: ATT_WRITE_REQ"),
            TestStep("Step13: Reader sends BLE host response: ATT_WRITE_RSP"),
        ]

    async def setup(self) -> None:
        logger.info("This is a test case setup")
        access_credential = self.reader_access_credential()
        self.access_credential_list = [access_credential]
        self.group_resolving_key = self.reader_group_resolving_key()
        self.userdevice = UserDevice(
            transport_protocol=TransportProtocol.BLE_UWB,
            access_credentials=self.access_credential_list,
            mailbox=0x20,
            group_resolving_key=self.group_resolving_key,
        )

    @log_errors
    async def execute(self) -> None:
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Reset murata board by pressing switch SW1",
                options={"OK": 1},
            )
        )

        # Test step 1
        # Done in setup
        self.next_step()

        # Test step 2
        try:
            await self.send_prompt_request(
                OptionsSelectPromptRequest(
                    prompt="Set Reader Device Under Test in BLE advertising mode",
                    options={"OK": 1},
                )
            )
            reader_group_list = []
            for access_credential in self.access_credential_list:
                reader_group_list.extend(access_credential.get_all_reader_id())
            await self.userdevice.transport_protocol.initialization(
                Mode.USER_DEVICE,
                group_resolving_key=self.group_resolving_key,
                reader_group_identifier_list=reader_group_list,
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 3
        try:
            await self.userdevice.transport_protocol.driver.wait_for_connection()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 4
        self.next_step()

        # Test step 5
        try:
            await self.userdevice.transport_protocol.driver.handle_GATT_layer_setup()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 6
        try:
            primary_service = (
                await self.userdevice.transport_protocol.driver.handle_GATT_layer_get_primary_service()
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 7
        self.next_step()

        # Test step 8
        self.next_step()

        # Test step 9
        self.next_step()

        # Test step 10
        try:
            spsm, versions, features = (
                await self.userdevice.transport_protocol.driver.handle_GATT_layer_read_characteristic(
                    primary_service
                )
            )
            logger.info("SPSM found: {!r}".format(hexlify(spsm)))
            if CURRENT_VERSION not in versions:
                self.mark_step_failure(
                    "Version 0x{:04x} not found".format(CURRENT_VERSION)
                )
                return
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 11
        self.next_step()

        # Test step 12
        value = bytearray()
        value.extend(int.to_bytes(CURRENT_VERSION, 2, "big"))
        value.append(0x01) # Features Supported Length 
        value.append(features[0] & 0x07)
        try:
            await self.userdevice.transport_protocol.driver.handle_GATT_layer_write_characteristic(
                primary_service, value
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 13
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("RD_BLE_STDTXN_10 Cleanup")
        try:
            await self.userdevice.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass
