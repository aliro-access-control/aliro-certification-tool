from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    Transaction,
    ReaderStatus,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidResponseError,
)
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors

import random

class NFC_UD_STANDARD_SIXTEEN_GROUPIDENTIFIER_ONE_AC(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_UD_STANDARD_SIXTEEN_GROUPIDENTIFIER_ONE_AC",
        "version": "0.0.1",
        "title": "NFC_UD_STANDARD_SIXTEEN_GROUPIDENTIFIER_ONE_AC",
        "description": """Expedited Standard Phase without Reader Certificate.""",
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

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "",  # PICS in preparation
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Initialization"),
            TestStep("Step2: Set to polling mode"),
            TestStep("Step3: Transaction initiation"),
            TestStep("Step4: Send/Receive AUTH0 command/response"),
            TestStep("Step5: Send/Receive AUTH1 command/response"),
            TestStep("Step6: Send/Receive EXCHANGE command/response"),
        ]

    async def setup(self) -> None:
        logger.info("This is a test case setup")
        # load parameters from project config

    @log_errors
    async def execute(self) -> None:
        # Test step 1
        # Done in setup
        self.next_step()

        # Test step 2
        # Display pop-up to put the User Device UT on the TH
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Tap User Device on the Test Harness NFC", options={"OK": 1}
            )
        )
        self.next_step()
        
        for i in range(2, 16):
            logger.info(f"===Iteration number: {i}===")
            group_id = [
                "00113344667799AA00113344667799AB",
                "00113344667799AA00113344667799AC",
                "00113344667799AA00113344667799AD",
                "00113344667799AA00113344667799AE",
                "00113344667799AA00113344667799AF",
                "00113344667799AA00113344667799BA",
                "00113344667799AA00113344667799BB",
                "00113344667799AA00113344667799BC",
                "00113344667799AA00113344667799BD",
                "00113344667799AA00113344667799BE",
                "00113344667799AA00113344667799BF",
                "00113344667799AA00113344667799CA",
                "00113344667799AA00113344667799CB",
                "00113344667799AA00113344667799CC",
                "00113344667799AA00113344667799CD",
                "00113344667799AA00113344667799CE",
            ]
            sub_group_id = "113344667799AA00113344667799AA00"
            readerPrivK = [
                "7ff96697caba6cc957e0f6899f300f3c2d46d7761ee3dd3088599457ce05f10e",
                "ec89fd59a8ec51afc5db036cf966d1a50e4b3aff0d61d4809c8661792ae4e1c3",
                "7bd793197381d32d06f11982dbaddfaecfa255698266e38fc0bc3f48f36fb4c4",
                "b5b051d2768abb46f94a0892d6c1664eb403e3a4d9412b9ccc271ede582b60b6",
                "58a6f53c494781428143a386d07202c02898612726400d5ef18d5d442b8cd2ca",
                "b23e91c7bb9acf800ba5384ade64efd4f3d2da219add9ba25a398788946fd2e4",
                "aebd755dd67cda2088550bf489712dbf6552173cc0961e46e0b0d3239908bcf5",
                "6a208fb0f9714798fa0b54d69e86309a3f0fb7c6a88381a6532b87b9b867a761",
                "7426ecd3309ec494ef781bd47cb285dc2dc987e902ed848406952aa933b2f913",
                "53562546ef675464102bab2331b50ae83f2d3f2152459bae5c8e40db53b4037d",
                "480875077dcbddb07af6a38bb5e3a5820fb0720da9c59d877e4f09587c42c99c",
                "02ca6d9ec60968dd5d7a901cdf5277817e13d435f3d76021f3f271f167794e13",
                "5b49f06363ecc0579a48156bfed1c7a64b6759833806f7d82d5916897907a1ae",
                "affc9b2c054e31dc29bf18200af842b3db02cb1391c5282ae95fce160014686f",
                "2c537a9524771a40b30dc0394f12393d9da2662c392ba34d366f1fd77134b1b8",
                "1205ecb475737df102bcc6091dbdd842a24bafd1a47b26c0f2c730987a6dfb4a",
            ]
            readerPubK = [
                "041d64ff1117de6653a352ca8e38b185910b10055ee8e366fb46d6a65f9c8addffbb2c7afb2dc271a7ce49246fc5461f4e6001a94fdfdfa1cdbd51d3a8dffb2acb",
                "04796d39c8792aa87be8ded0643cd9013a205cc7a174eddde6a2c3a6aa7be84e82bfe7e78b3724342d114a4972d917ee3b42fcb1694002f0e6a83325c9ab37898f",
                "0493f887192ee66ed596416e612dc814fedde827a96e83aedeadfa42cdeba1e363ab46868d9f799a44dabd7b057c714f2c7430598a2640cf9146b5102d6da9066f",
                "049a953902e3f2c18ef8a3cfad56b85bd04ff90b4cffc1e71dba5823f8236f19af5ae2074bd55d5712bcb7cb186a8cdb8a3ec1d1318edbfb47a2bd19f55dde894f",
                "04c9c9ea33e5daa6f291c706544f935a1e882abf9f51154affebae38d30ffcaa31c6a1d57c571b0e38fe90434e3aa0a49f4c7b12c938ea446cb14e1e4e06497c96",
                "0401daacbad0e9a914ff297430236c386bd2a45d1d30111fec6dd20757e1fa2708267312c65fd49773539f44f40d9a233c75c43cdda5eccf065be87ffe79ae2cf9",
                "044555995381ee5a724eca16ed19f1b90b97f1c25b98da8356432bc7f32d4be88ad4cac1ca98783f09a61ba13eeac1ed4cf56660ea661d59223f9abec876057374",
                "0458bae01be2b6e3f1ed2cf6c17a455dfb219862d7da55e31adf51c4f6c5381524a2238e1c2750668060af0e418830eafdcbb7cbd22d3f08ec70952dc450caef3e",
                "04470c12520d801c2a6172e0631a9eb80d788641d87c58a6a25ee0e02ea1ab6cac8e8ef606d271be9760666ebc18aabe90de9bcc8bb4d24d53dfbb1733347c0e39",
                "043e97e36b228700ca9a38bbf0fc06512e60c252bba6eebbe61027d782589cae8eb5b04568dec638e0dc7d7f7517fec0e281db9c26092b562a2ba6df9ffc6c9f6f",
                "047b75386775553f01cfe133cb02d21316682694a18c18bb9eb594e9db9f2f6278336387a381ffec95524d29c69f73cdd3b4e22b500f92d94677641e4e343e54af",
                "04d0d453a8abd945564eb7b10faabb27f04aea8f04d72b811c66682e9f0096f615c805b9f1f548a0f4f268e46eb09a953e95e516adc02df9ffecf39597af172c90",
                "04b18f0148de011ced618ce9ea73b8d1fe02404a7c7f408727aa16767758b205ab32f6dd308d09a92e6189ed9f1f5945483913c37b69163bb53c17d6f8d8835b77",
                "04b3bc8b89e4239195ff3c2a7124958b3958d0c05018c7931ee5327e40ee5f2d98c46073f885127f673d8b6e9d3b4c7845ca79e4bf5df9a5c76e3fb6a65d5ba015",
                "0453792d75286b552d7aca748cc2f8e16ff67b7d4637b5c33d6c85fbd09b80e6e73449154d1c4916cdc816a2878b5e20e412aaea7f4c56ab0944e03380b910df92",
                "0498e8b1f61e7a88e70708e46a7cdaccf6873208161d49eb050dc8deaeea5f1ecdd6fc34a5c14626ae34c22cad2a7e0e654316aafa7c0c1b02d1588d63b22f4b94",
            ]
            key = KeyPair(bytes.fromhex(readerPrivK[i]), bytes.fromhex(readerPubK[i]))

            # Initialize Aliro NFC Reader
            self.reader = Reader(
                transport_protocol=TransportProtocol.NFC,
                reader_group_identifier=bytes.fromhex(group_id[i]),
                reader_group_sub_identifier=bytes.fromhex(sub_group_id),
                reader_key=key,
                transaction_identifier_list=[self.transaction_identifier],
                ephemeral_key_list=[KeyPair(self.reader_ePrivK, self.reader_ePuBK)],
            )

            # Test step 3
            try:
                await self.reader.transaction_initiation()  # including SELECT command
            except (AccessProtocolError, InvalidResponseError) as error:
                self.mark_step_failure(str(error))
                return
            self.next_step()

            # Test step 4
            authentication_policy = random.randint(
                AuthenticationPolicy.USER_DEVICE, 
                AuthenticationPolicy.FORCE_USER_AUTHENTICATION
            )
            try:
                await self.reader.handle_auth0(
                    transaction_type=Transaction.STANDARD,
                    authentication_policy=AuthenticationPolicy(authentication_policy),
                )
            except (AccessProtocolError, InvalidResponseError) as error:
                self.mark_step_failure(str(error))
                return
            self.next_step()

            # Test step 5
            try:
                await self.reader.handle_auth1(
                    expected_response=Auth1Response.CREDENTIAL_PUBLIC_KEY
                )
            except (AccessProtocolError, InvalidResponseError) as error:
                self.mark_step_failure(str(error))
                return
            self.next_step()
            
            # Test step 6
            try:
                await self.reader.handle_exchange(
                    False, reader_status=ReaderStatus.READER_STATE_UNSECURED
                )
            except (AccessProtocolError, InvalidResponseError) as error:
                self.mark_step_failure(str(error))
                return
            self.next_step()

    async def cleanup(self) -> None:
        logger.info("NFC_UD_STANDARD_SIXTEEN_GROUPIDENTIFIER_ONE_AC Cleanup")
        await self.reader.transaction_termination()
