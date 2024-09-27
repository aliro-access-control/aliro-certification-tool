from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    INS,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidCommandError,
)
from aliro_actuator.access_protocol.user_device import UserDevice, UserSessionState
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.access_doc.mdl.request import DeviceRequest
from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class RD_NFC_ENVELOPE_10(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "RD-NFC-ENVELOPE-1.0",
        "version": "0.0.1",
        "title": "RD-NFC-ENVELOPE-1.0",
        "description": """Verify conformance of Reader UT in ENVELOPE command.""",
    }

    endpoint_ePuBK = bytes.fromhex(
        "045d75ab60136a2c54ff27b799ee157f3f3329435c0d"
        "f608de904c920ac29f72bd4274c2edc810a93e240bf5"
        "d6394a92c9766b690b2bf5128ae70d6e29257ea786"
    )  # from Test Vector
    endpoint_ePrivK = bytes.fromhex(
        "70637ee9b40cee568567c69589276888edca7128bb13fb531f9c4f502d8cc65e"
    )  # from Test Vector

    device_response = bytes.fromhex(
        "A3613163312E30613282A26131A26131A167616C69726F2D6181D818590132A461"
        "31016132504708316C77D5C08786A2DDE5A032BBD4613366666C6F6F72316134A6"
        "000101481234567890ABCDEF0282A3000301050202A200183F01050383A400C11A"
        "66F5ABC001C11A676C52C0024B00000E10000000150203000301A400C11A66F5AB"
        "C101C11A676C52C1024B00001C200000006A0201000300A400C11A66F5ABC201C1"
        "1A676C52C2024B00000708000000100402FF03010482187B1901C806A11A00FA14"
        "668284010101A300815013AC8FF518435D4128C29D7B2741FBE50158410462E62D"
        "1E9A4B2DABCEAC672D23EAF9DE0A79534F1DF12C7FF70EF14D7E7C8661D8E61D0C"
        "18A27ED0B0A527AEA78D3FBC113F65AF8A1FC0966419A3D470F455A30281A20048"
        "DB8C47BD724B6CD701506E1E6178703440E6C5391DC6C7F3E95A84010201A40018"
        "1E01010202030261328443A10126A204483C28B651BB526FE11821590155308201"
        "513081F9A003020102020101300A06082A8648CE3D0403023011310F300D060355"
        "04030C06697373756572301E170D3230303130313030303030305A170D34393031"
        "30313030303030305A30123110300E06035504030C077375626A65637430593013"
        "06072A8648CE3D020106082A8648CE3D03010703420004793E3A8F20428D54E731"
        "8046D75D05A8737EB6E074E5146A207BFF62DAE90E24039F372814A312C3CB82A5"
        "A97BB5BFA9E623A3CC886B09DC13D53EF0DA7DE7BDA341303F301F0603551D2304"
        "18301680142318E55671F08EAE212142A817720FB817EE93BF300C0603551D1301"
        "01FF04023000300E0603551D0F0101FF040403020780300A06082A8648CE3D0403"
        "020347003044022041D68E88DE6E1AAB6B0AB44224E62B81F3085145618567F403"
        "83B6A859843C4602204FE8E48EF498E89C20F916CB36469850B8D74791C1A9D10A"
        "77F8E1123E71AF7758ECD81858E8A7613163312E306132675348412D3235366133"
        "A167616C69726F2D61A1015820ED54EA975D720E7F77367873C27B2B9F2C18EDF2"
        "D9D624B2154920C64ED0ACC96134A16131A401022001215820ED1C8B8EB7E44C28"
        "42DB98730717C75CC94C96AB9AE60F079879E756980B4003225820B38FB449203F"
        "7237CB9F81077B8AC49C75C8115ED408312222EAB61E18FECA17613567616C6972"
        "6F2D616136A36131C074323032342D30392D32365431383A34353A31395A6132C0"
        "74323032342D30392D32365431383A34353A31395A6133C074323032342D31302D"
        "31305431383A34353A31395A6137F45840E0CF88ED5A2A2D053A0D8656919D3C37"
        "14A83103A5C392C2180ADBFE244E718E603FE456BFECE2E6128921D3A3C1585DD1"
        "EB46D3E831E69A3E8E5A7D1AA85082613567616C69726F2D61A26131A26131A167"
        "616C69726F2D7281D818590111A4613101613250DC7DCEE17CF6F651795906C18E"
        "495C74613366666C6F6F72326134A5000101000282A30058200102030405060708"
        "090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2001481234567890ABCD"
        "EF02C11A676C52BFA30058206465666768696A6B6C6D6E6F707172737475767778"
        "797A7B7C7D7E7F808182830150ABACADAEAFB0B1B2B3B4B5B6B7B8B9BA02C11A66"
        "FEE63F0382A2005820C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"
        "E0E1E2E3E4E5E6E70150CBCCCDCECFD0D1D2D3D4D5D6D7D8D9DAA200582028292A"
        "2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464701463031"
        "3233343504A11A00ABCDEF818319014109A20001010261328443A10126A204483C"
        "28B651BB526FE11821590155308201513081F9A003020102020101300A06082A86"
        "48CE3D0403023011310F300D06035504030C06697373756572301E170D32303031"
        "30313030303030305A170D3439303130313030303030305A30123110300E060355"
        "04030C077375626A6563743059301306072A8648CE3D020106082A8648CE3D0301"
        "0703420004793E3A8F20428D54E7318046D75D05A8737EB6E074E5146A207BFF62"
        "DAE90E24039F372814A312C3CB82A5A97BB5BFA9E623A3CC886B09DC13D53EF0DA"
        "7DE7BDA341303F301F0603551D230418301680142318E55671F08EAE212142A817"
        "720FB817EE93BF300C0603551D130101FF04023000300E0603551D0F0101FF0404"
        "03020780300A06082A8648CE3D0403020347003044022041D68E88DE6E1AAB6B0A"
        "B44224E62B81F3085145618567F40383B6A859843C4602204FE8E48EF498E89C20"
        "F916CB36469850B8D74791C1A9D10A77F8E1123E71AF7758ECD81858E8A7613163"
        "312E306132675348412D3235366133A167616C69726F2D72A1015820147127E2F8"
        "7835A59E86DA2353AEA87B934457A4F348ACD5002861177D4958956134A16131A4"
        "01022001215820ED1C8B8EB7E44C2842DB98730717C75CC94C96AB9AE60F079879"
        "E756980B4003225820B38FB449203F7237CB9F81077B8AC49C75C8115ED4083122"
        "22EAB61E18FECA17613567616C69726F2D726136A36131C074323032342D30392D"
        "32365431383A34353A31395A6132C074323032342D30392D32365431383A34353A"
        "31395A6133C074323032342D31302D31305431383A34353A31395A6137F4584078"
        "F08BACE1D2CB54A5F45265DF18974100050DD4CC9E2CF74C85C10F91C0B89FFC51"
        "13532069140A3EBE26B034CEA9B668309170317427A2E3C40F67430E2F15613567"
        "616C69726F2D72613300"
    )

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "",  # PICS in preparation
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Prerequisites"),
            TestStep("Step2: Send SELECT id signaling bitmap is set"),
            TestStep("Step2: Send Envelope command"),
            TestStep("Step3: Receive get response"),
        ]

    async def setup(self) -> None:
        logger.info("This is a test case setup")
        access_credential = self.reader_access_credential()
        self.userdevice = UserDevice(
            transport_protocol=TransportProtocol.NFC,
            access_credentials=[access_credential],
            mailbox=0x20,
            ephemeral_key_list=[KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK)],
            access_document=self.device_response,
        )

    @log_errors
    async def execute(self) -> None:
        # Prerequisites
        # Display pop-up to set the Reader Device Under Test in polling mode
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Set Reader Device Under Test in NFC polling mode",
                options={"OK": 1},
            )
        )

        # Display pop-up to put the Test Harness on the Reader device Under Test
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Bring Test Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )
        try:
            await self.userdevice.transaction_initiation()  # including select
        except (AccessProtocolError, InvalidCommandError) as error:
            self.mark_step_failure(str(error))
            return

        try:
            cmds_auth0 = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return
        try:
            await self.userdevice.handle_auth0(cmds_auth0)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        if not self.userdevice.session.state_valid(UserSessionState.AUTH0_STD_DONE):
            self.mark_step_failure(
                "Userdevice is not in state auth0 standard done, either fast "
                "transaction was requested or handling auth0 failed"
            )

        try:
            cmds_auth1 = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return
        if cmds_auth1.expected_response != Auth1Response.CREDENTIAL_PUBLIC_KEY:
            self.mark_step_failure(
                "Access Credential key type request is not endpoint public key!"
            )
            return

        # Test step 2
        try:
            await self.userdevice.handle_auth1(cmds_auth1)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 3,4 - reader sends envelope
        try:
            cmds_envelope = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return

        device_request = DeviceRequest()
        if not device_request.from_cbor(cmds_envelope.decrypted_payload):
            self.mark_step_failure("Failed to parse device request.")
            return

        if not device_request.is_valid():
            self.mark_step_failure("Failed to validate device request.")
            return

        try:
            await self.userdevice.handle_envelope(cmds_envelope)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("RD_NFC_STPUP_10 Cleanup")
        await self.userdevice.transaction_termination()
