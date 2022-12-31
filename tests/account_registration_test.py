from DexilonClientImpl import DexilonClientImpl
from cosmospy import generate_wallet
from responses import CosmosFaucetResponse


class TestAccountRegistration:
    TEST_METAMASK_ADDRESS = '0x201d980aeD5C04a7e75860cFE29CeD9b5da05A08'
    TEST_PRIVATE_KEY = '87d25c8ade8c4bb32be098bb35cd594fd1c0511c4423bf36f006f4ecd27f017c'

    def setup(self):
        self.test_instance = DexilonClientImpl(self.TEST_METAMASK_ADDRESS, self.TEST_PRIVATE_KEY)
        # self.test_instance.setup()
        self.test_instance.change_api_url('http://api.dev.dexilon.io/api/v1')
        self.test_instance.change_cosmos_api_url('http://65.108.44.122:1317/dexilon-exchange/dexilonl2')
        self.test_instance.change_cosmos_faucet_api_url('http://65.108.44.122:4000')


    def test_should_generate_cosmos_address(self):
        cosmos_address = self.test_instance.generate_random_cosmos_wallet()
        assert cosmos_address is not None


    def test_should_generate_eth_address(self):
        eth_address = self.test_instance.generate_random_eth_wallet()
        assert eth_address is not None


    def test_should_call_cosmos_faucet_successfully(self):
        faucet_result = self.test_instance.call_cosmos_faucet('cosmos14m8eeep93z6ka5exp2ccazem7nyq8v77w23r6f')
        assert faucet_result is not None
        assert isinstance(faucet_result, CosmosFaucetResponse)


    def test_should_get_cosmos_address_signed(self):
        result = self.test_instance.getSignature(None, 'cosmos14m8eeep93z6ka5exp2ccazem7nyq8v77w23r6f')
        assert result is not None


    def test_should_register_new_random_user(self):
        result = self.test_instance.registerNewRandomUser(80001, "dexilon-dev")
        assert result is not None


    def test_should_register_new_user_from_existing_mnemonics(self):
        cosmos_wallet = generate_wallet()
        # cosmos_test_mnemonic = "derive blossom organ document arch rapid ginger invite attend radio scale hurry between payment defy distance february rough banner awful lock coral stock share"
        cosmos_test_mnemonic = cosmos_wallet["seed"]
        eth_test_mnemonic = "witness offer document call session syrup cruel lumber develop feel student verify"
        result = self.test_instance.registerUserWithExistingMnemonics(cosmos_test_mnemonic, eth_test_mnemonic, 80001, "dexilon-dev")
        assert result is not None


    def test_should_deposit_funds_successfully(self):
        eth_test_mnemonic = "witness offer document call session syrup cruel lumber develop feel student verify"
        cosmos_deposit_update = self.test_instance.depositFundsToCosmosWallet(eth_test_mnemonic, 'usdt', 10, 80001, "dexilon-dev")
        assert cosmos_deposit_update is not None


    def test_should_withdraw_funds_successfully(self):
        eth_test_mnemonic = "witness offer document call session syrup cruel lumber develop feel student verify"
        dexilon_withdraw_response = self.test_instance.withdraw_funds(eth_test_mnemonic, 10, 'usdt',  80001, "dexilon-dev")
        assert dexilon_withdraw_response is not None