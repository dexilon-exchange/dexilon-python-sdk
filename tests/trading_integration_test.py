from DexilonClientImpl import DexilonClientImpl


class TestTradingIntegration:
    TEST_METAMASK_ADDRESS = '0x201d980aeD5C04a7e75860cFE29CeD9b5da05A08'
    TEST_PRIVATE_KEY = '87d25c8ade8c4bb32be098bb35cd594fd1c0511c4423bf36f006f4ecd27f017c'

    def setup(self):
        self.test_instance = DexilonClientImpl(self.TEST_METAMASK_ADDRESS, self.TEST_PRIVATE_KEY)

    def test_get_max_available_to_buy(self):
        max_available_to_buy = self.test_instance.get_max_available_for_buy('btc_usdc')
        assert max_available_to_buy is not None

    def test_get_max_available_to_sell(self):
        max_available_to_sell = self.test_instance.get_max_available_for_sell('btc_usdc')
        assert max_available_to_sell is not None