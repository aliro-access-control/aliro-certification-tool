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
        "A3613163312E30613282A26131A26131A167616C69726F2D6181D818590121A461"
        "3101613250E33E4B23C8337EDE475C4451D49CE88F613366666C6F6F72316134A6"
        "000101481234567890ABCDEF0282A3000301050202A200183F01050383A4001A66"
        "F6C78C011A676D6E8C0285190E10150203000301A4001A66F6C78D011A676D6E8D"
        "0285191C20186A0201000300A4001A66F6C78E011A676D6E8E0285190708100402"
        "2003010482187B1901C806A11A00FA14668284010101A300815013AC8FF518435D"
        "4128C29D7B2741FBE501584104DD6CAFD87254D92AF7A55689D440FBB7BC2EB17B"
        "8B9102416136A952816D2565D5169374F98FAE05EEB00B06826302C66AF43D9B10"
        "6F6B82B1300CB161E36C9E0281A20048DB8C47BD724B6CD70150190BCBED09B869"
        "2561000ECB7DA0DCC084010201A400181E01010202030261328443A10126A20448"
        "3C28B651BB526FE11821590156308201523081F9A003020102020101300A06082A"
        "8648CE3D0403023011310F300D06035504030C06697373756572301E170D323030"
        "3130313030303030305A170D3439303130313030303030305A30123110300E0603"
        "5504030C077375626A6563743059301306072A8648CE3D020106082A8648CE3D03"
        "010703420004793E3A8F20428D54E7318046D75D05A8737EB6E074E5146A207BFF"
        "62DAE90E24039F372814A312C3CB82A5A97BB5BFA9E623A3CC886B09DC13D53EF0"
        "DA7DE7BDA341303F301F0603551D230418301680142318E55671F08EAE212142A8"
        "17720FB817EE93BF300C0603551D130101FF04023000300E0603551D0F0101FF04"
        "0403020780300A06082A8648CE3D0403020348003045022100ADCC53DF4DCDFF81"
        "B85F8042187010F63AF7E2077A403B2D178B762B286CE7AE02206B6AFEEF244F7A"
        "EDC828D0C9EB0207D464FFD0E612EE78232745AEAAC9F4122D58ECD81858E8A761"
        "3163312E306132675348412D3235366133A167616C69726F2D61A1015820982BD4"
        "A6EF3803D8B3945F52EA0D5BF892EF79E2F5E184A908DCF6DD805EF6366134A161"
        "31A401022001215820ED1C8B8EB7E44C2842DB98730717C75CC94C96AB9AE60F07"
        "9879E756980B4003225820B38FB449203F7237CB9F81077B8AC49C75C8115ED408"
        "312222EAB61E18FECA17613567616C69726F2D616136A36131C074323032342D30"
        "392D32375431343A35363A31315A6132C074323032342D30392D32375431343A35"
        "363A31315A6133C074323032342D31302D31315431343A35363A31315A6137F458"
        "407FB754B1F7323CD2686E99357820C5EC9BD8FB75B2124529F79A1CF556862B06"
        "41700C2448A46C7C1BF57B3325F9EE313C5C371FB5A49646E951AAD933C7175161"
        "3567616C69726F2D61A26131A26131A167616C69726F2D7281D818590111A46131"
        "01613250115CFC6764E69CA1C52B292C9AEA09E1613366666C6F6F72326134A500"
        "0101000282A30058200102030405060708090A0B0C0D0E0F101112131415161718"
        "191A1B1C1D1E1F2001481234567890ABCDEF02C11A676D6E8BA300582064656667"
        "68696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182830150ABACAD"
        "AEAFB0B1B2B3B4B5B6B7B8B9BA02C11A6700020B0382A2005820C8C9CACBCCCDCE"
        "CFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E70150CBCCCDCECFD0"
        "D1D2D3D4D5D6D7D8D9DAA200582028292A2B2C2D2E2F303132333435363738393A"
        "3B3C3D3E3F4041424344454647014630313233343504A11A00ABCDEF8183190141"
        "09A20001010261328443A10126A204483C28B651BB526FE1182159015630820152"
        "3081F9A003020102020101300A06082A8648CE3D0403023011310F300D06035504"
        "030C06697373756572301E170D3230303130313030303030305A170D3439303130"
        "313030303030305A30123110300E06035504030C077375626A6563743059301306"
        "072A8648CE3D020106082A8648CE3D03010703420004793E3A8F20428D54E73180"
        "46D75D05A8737EB6E074E5146A207BFF62DAE90E24039F372814A312C3CB82A5A9"
        "7BB5BFA9E623A3CC886B09DC13D53EF0DA7DE7BDA341303F301F0603551D230418"
        "301680142318E55671F08EAE212142A817720FB817EE93BF300C0603551D130101"
        "FF04023000300E0603551D0F0101FF040403020780300A06082A8648CE3D040302"
        "0348003045022100ADCC53DF4DCDFF81B85F8042187010F63AF7E2077A403B2D17"
        "8B762B286CE7AE02206B6AFEEF244F7AEDC828D0C9EB0207D464FFD0E612EE7823"
        "2745AEAAC9F4122D58ECD81858E8A7613163312E306132675348412D3235366133"
        "A167616C69726F2D72A101582036BBF526144CF40CB3A5943F5200BA8F27AE7763"
        "47F5D3F9793B9B915BEB0DB76134A16131A401022001215820ED1C8B8EB7E44C28"
        "42DB98730717C75CC94C96AB9AE60F079879E756980B4003225820B38FB449203F"
        "7237CB9F81077B8AC49C75C8115ED408312222EAB61E18FECA17613567616C6972"
        "6F2D726136A36131C074323032342D30392D32375431343A35363A31315A6132C0"
        "74323032342D30392D32375431343A35363A31315A6133C074323032342D31302D"
        "31315431343A35363A31315A6137F45840798CA361195CF0CEFC2A1293F3D9ED35"
        "8FE535EE1A82D6D802218F5403732C805510C549403C32742BADB9ED41D46BADC7"
        "DD7D34EFA5DAF3FF07F19F6A4AE656613567616C69726F2D72613300"
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
