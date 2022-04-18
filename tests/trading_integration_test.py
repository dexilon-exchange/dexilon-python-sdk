from DexilonClientImpl import DexilonClientImpl


class TestTradingIntegration:
    TEST_METAMASK_ADDRESS = '0x201d980aeD5C04a7e75860cFE29CeD9b5da05A08'
    TEST_PRIVATE_KEY = '87d25c8ade8c4bb32be098bb35cd594fd1c0511c4423bf36f006f4ecd27f017c'

    def setup(self):
        self.test_instance = DexilonClientImpl(self.TEST_METAMASK_ADDRESS, self.TEST_PRIVATE_KEY)

    def test_create_market_order(self):
        order_id = self.test_instance.market_order('TEST_MARKET_ORDER_1', 'eth_usdc', 'BUY', 0.10)
        assert len(order_id) > 0

    def test_create_limit_order(self):
        order_id = self.test_instance.limit_order('TEST_MARKET_ORDER_2', 'eth_usdc', 'BUY', 3200.0, 0.1)
        assert len(order_id) > 0

    def test_should_cancel_all_orders(self):
        result = self.test_instance.cancel_all_orders()
        assert result

    def test_should_cancel_order(self):
        result = self.test_instance.cancel_order('TESTORDERID', 'eth_usdc')
        assert result

    def test_should_get_margin(self):
        margin_data = self.test_instance.get_margin()
        assert margin_data is not None