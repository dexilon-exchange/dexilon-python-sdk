from DexilonClientImpl import DexilonClientImpl
from OrderErrorInfo import OrderErrorInfo
from responses import FullOrderInfo, LeverageUpdateInfo


class TestTradingIntegration:
    TEST_METAMASK_ADDRESS = '0x201d980aeD5C04a7e75860cFE29CeD9b5da05A08'
    TEST_PRIVATE_KEY = '87d25c8ade8c4bb32be098bb35cd594fd1c0511c4423bf36f006f4ecd27f017c'

    # TEST_METAMASK_ADDRESS = '0x92f4888b49442244bD99A85AF84cccc49907f3f7'
    # TEST_PRIVATE_KEY = '7bf5ae9f4d080107e105212f40cdc3d897d1101e69fd8f0a36e5bb648055ff52'

    def setup(self):
        self.test_instance = DexilonClientImpl(self.TEST_METAMASK_ADDRESS, self.TEST_PRIVATE_KEY)
        self.test_instance.change_api_url('https://dex-dev2-api.cronrate.com/api/v1')

    def test_create_market_order(self):
        full_order_info = self.test_instance.market_order('TEST_MARKET_ORDER_1', 'eth_usdc', 'SELL', 0.20)
        assert isinstance(full_order_info, FullOrderInfo) and full_order_info.orderId is not None

    def test_create_market_order_with_rejected_state(self):
        order_submit_result = self.test_instance.market_order('TEST_MARKET_ORDER_1', 'eth_usdc', 'BUY', 1000000000.00)
        assert isinstance(order_submit_result, OrderErrorInfo)
        assert 'NEW_ORDER_REJECTED' in order_submit_result.state

    def test_create_limit_order(self):
        full_order_info = self.test_instance.limit_order('TEST_LIMIT_ORDER_2', 'eth_usdc', 'BUY', 1650.0, 0.2)
        assert isinstance(full_order_info, FullOrderInfo) and full_order_info.orderId is not None

    def test_create_limit_order_with_rejected_state(self):
        full_order_info = self.test_instance.limit_order('TEST_LIMIT_ORDER_2', 'eth_usdc', 'BUY', 3200.0, 100.0)
        assert isinstance(full_order_info, OrderErrorInfo)

    def test_should_cancel_all_orders(self):
        result = self.test_instance.cancel_all_orders()
        assert result

    def test_should_cancel_order(self):
        result = self.test_instance.cancel_order('TESTORDERID', 'eth_usdc')
        assert isinstance(result, OrderErrorInfo)

    def test_should_create_and_cancel_order_sucessfully(self):
        full_order_info = self.test_instance.limit_order('TEST_LIMIT_ORDER_2', 'eth_usdc', 'BUY', 1200.0, 0.2)
        assert isinstance(full_order_info, FullOrderInfo)
        canceled_order_info = self.test_instance.cancel_order(full_order_info.orderId, full_order_info.symbol)
        assert isinstance(canceled_order_info, FullOrderInfo)

    def test_should_get_account_info(self):
        account_info_result = self.test_instance.get_account_info()
        assert account_info_result is not None

    def test_should_get_all_open_orders(self): #
        full_order_info = self.test_instance.limit_order('TEST_LIMIT_ORDER_2', 'eth_usdc', 'BUY', 1200.0, 0.2)

        open_orders = self.test_instance.get_open_orders()
        assert len(open_orders) > 0

        self.test_instance.cancel_order(full_order_info.orderId, full_order_info.symbol)

    # def test_should_get_order_info(self): #
    #     full_order_info = self.test_instance.limit_order('TEST_LIMIT_ORDER_2', 'eth_usdc', 'BUY', 1200.0, 0.2)
    #
    #     order_info = self.test_instance.get_order_info(full_order_info.orderId, full_order_info.symbol)
    #     assert order_info is not None
    #     assert isinstance(order_info, FullOrderInfo)
    #     cancel_result = self.test_instance.cancel_order(order_info.orderId, order_info.symbol)
    #     assert cancel_result is not None
    #     assert isinstance(cancel_result, FullOrderInfo)

    def test_should_error_on_cancel_wrong_order(self):
        cancel_result = self.test_instance.cancel_order('RANDOMID1', 'eth_usdc')
        assert isinstance(cancel_result, OrderErrorInfo)

    def test_should_parse_response_for_illegal_char_in_cancel_request(self):
        cancel_result = self.test_instance.cancel_order('RANDOM-ID-1', 'eth_usdc')
        assert isinstance(cancel_result, OrderErrorInfo)

    def test_should_process_error_for_limit_order_submit(self):
        order_submit_result = self.test_instance.limit_order('TEST_MARKET_ORDER_1', 'eth_usdc', 'BUY', 1600.00, 0.10)
        assert isinstance(order_submit_result, OrderErrorInfo)
        if isinstance(order_submit_result, OrderErrorInfo):
            assert 'REJECTED' in order_submit_result.state

    def test_should_set_leverage(self):
        leverage_update = self.test_instance.set_leverage('eth_usdc', 1)
        assert isinstance(leverage_update, LeverageUpdateInfo)