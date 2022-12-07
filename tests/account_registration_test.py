from DexilonClientImpl import DexilonClientImpl


class TestAccountRegistration:
    TEST_METAMASK_ADDRESS = '0x201d980aeD5C04a7e75860cFE29CeD9b5da05A08'
    TEST_PRIVATE_KEY = '87d25c8ade8c4bb32be098bb35cd594fd1c0511c4423bf36f006f4ecd27f017c'

    def setup(self):
        self.test_instance = DexilonClientImpl(self.TEST_METAMASK_ADDRESS, self.TEST_PRIVATE_KEY)
        self.test_instance.change_api_url('http://api.dev.dexilon.io/api/v1')
        self.test_instance.change_cosmos_api_url('http://10.13.0.48:1317/dexilon-exchange/dexilonl2')


    def test_should_generate_cosmos_address(self):
        cosmos_address = self.test_instance.generate_random_cosmos_address()
        assert cosmos_address is not None


    def test_should_generate_eth_address(self):
        eth_address = self.test_instance.generate_random_eth_wallet();
        assert eth_address is not None


    def test_should_call_cosmos_faucet_successfully(self):
        faucet_result = self.test_instance.call_cosmos_faucet('cosmos1BL5hNswKw1B5pgJTTwPtAJZuATN9mduVZ')
        assert faucet_result is not None