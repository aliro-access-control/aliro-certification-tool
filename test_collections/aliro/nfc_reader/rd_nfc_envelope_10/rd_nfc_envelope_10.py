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
        "A3613163312E30613282A2613567616C69726F2D616131A26131A167616C69726F"
        "2D6181D818590132A4613101613250EFF883A548507DEF8417E7A99DF1A13B6133"
        "66666C6F6F72316134A6000101481234567890ABCDEF0282A3000301050202A200"
        "183F01050383A400C11A66DAF18B01C11A6751988B024B00000E10000000150203"
        "000301A400C11A66DAF18C01C11A6751988C024B00001C200000006A0201000300"
        "A400C11A66DAF18D01C11A6751988D024B00000708000000100402FF0301048218"
        "7B1901C806A11A00FA14668284010101A300815013AC8FF518435D4128C29D7B27"
        "41FBE501584104EB457C74776E6105A6D86A4F116B4EB53F71576E7800DD22B069"
        "9DBFCE5605E257A31F91D0F7EB1521C7F6C9C18F0C26EA75CC2C865A280A00B2E1"
        "18A317E5AE0281A20048DB8C47BD724B6CD70150C43638AC9A008707BE87527073"
        "6C8D2084010201A400181E01010202030261328443A10126A20448C61187E0F2F3"
        "503E182159015CD818590157308201533081F9A003020102020101300A06082A86"
        "48CE3D0403023011310F300D06035504030C06697373756572301E170D32303031"
        "30313030303030305A170D3439303130313030303030305A30123110300E060355"
        "04030C077375626A6563743059301306072A8648CE3D020106082A8648CE3D0301"
        "0703420004842242F6182BA1C1138D32B77FB9F7F37B70034B9F04443A5BEA3C18"
        "8BEADB36490A7E95F91A4C162ACFC3401C3A4F4E5A59251D45243AC8544A665CB9"
        "51422FA341303F301F0603551D230418301680142318E55671F08EAE212142A817"
        "720FB817EE93BF300C0603551D130101FF04023000300E0603551D0F0101FF0404"
        "03020780300A06082A8648CE3D040302034900304602210091CB69C580B62F455B"
        "4009F24285BDED15D0DEC8C537CD5D281E14ECC0884066022100E35EB9561337B5"
        "52835D4F5C521B6546143371F73F58C3C931619569FE6FA93A58ECD81858E8A761"
        "3163312E306132675348412D3235366133A167616C69726F2D61A1015820A3704D"
        "87A231E43477543552BDBC1E10429604DB21CC317C8F291F83981CF7586134A161"
        "31A401022001215820ED1C8B8EB7E44C2842DB98730717C75CC94C96AB9AE60F07"
        "9879E756980B4003225820B38FB449203F7237CB9F81077B8AC49C75C8115ED408"
        "312222EAB61E18FECA17613567616C69726F2D616136A36131C074323032342D30"
        "392D30365431323A31313A35345A6132C074323032342D30392D30365431323A31"
        "313A35345A6133C074323032342D30392D32305431323A31313A35345A6137F458"
        "40D981DB384201A76F6F7E1D75E08B978E4BB91BBB35DA580991B872409CC95FCC"
        "0A0D3B46269FB6872F4909AFE36B614F49B15F3698A1EA1BA3DABDCDA89426B6A2"
        "613567616C69726F2D726131A26131A167616C69726F2D7281D818590111A46131"
        "016132507F09EC36A28761C73B47EDD734A8AAC8613366666C6F6F72326134A500"
        "0101000282A30058200102030405060708090A0B0C0D0E0F101112131415161718"
        "191A1B1C1D1E1F2001481234567890ABCDEF02C11A6751988AA300582064656667"
        "68696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182830150ABACAD"
        "AEAFB0B1B2B3B4B5B6B7B8B9BA02C11A66E42C0A0382A2005820C8C9CACBCCCDCE"
        "CFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E70150CBCCCDCECFD0"
        "D1D2D3D4D5D6D7D8D9DAA200582028292A2B2C2D2E2F303132333435363738393A"
        "3B3C3D3E3F4041424344454647014630313233343504A11A00ABCDEF8183190141"
        "09A20001010261328443A10126A20448C61187E0F2F3503E182159015CD8185901"
        "57308201533081F9A003020102020101300A06082A8648CE3D0403023011310F30"
        "0D06035504030C06697373756572301E170D3230303130313030303030305A170D"
        "3439303130313030303030305A30123110300E06035504030C077375626A656374"
        "3059301306072A8648CE3D020106082A8648CE3D03010703420004842242F6182B"
        "A1C1138D32B77FB9F7F37B70034B9F04443A5BEA3C188BEADB36490A7E95F91A4C"
        "162ACFC3401C3A4F4E5A59251D45243AC8544A665CB951422FA341303F301F0603"
        "551D230418301680142318E55671F08EAE212142A817720FB817EE93BF300C0603"
        "551D130101FF04023000300E0603551D0F0101FF040403020780300A06082A8648"
        "CE3D040302034900304602210091CB69C580B62F455B4009F24285BDED15D0DEC8"
        "C537CD5D281E14ECC0884066022100E35EB9561337B552835D4F5C521B65461433"
        "71F73F58C3C931619569FE6FA93A58ECD81858E8A7613163312E30613267534841"
        "2D3235366133A167616C69726F2D72A1015820EE936DFE58AA645029538F3AD03D"
        "AB45B2C32995975F7A1528D3D404D02A2E626134A16131A401022001215820ED1C"
        "8B8EB7E44C2842DB98730717C75CC94C96AB9AE60F079879E756980B4003225820"
        "B38FB449203F7237CB9F81077B8AC49C75C8115ED408312222EAB61E18FECA1761"
        "3567616C69726F2D726136A36131C074323032342D30392D30365431323A31313A"
        "35345A6132C074323032342D30392D30365431323A31313A35345A6133C0743230"
        "32342D30392D32305431323A31313A35345A6137F45840F135C66049643977925D"
        "DB2D8F1A0443EB69F62BCD145AAC8CF5E8ABA71F75246D36DD1C2CDD6D0D2A7AA0"
        "14372F4008AE555C41AE258ADCB1A75BCFAE8F3778613300"
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
