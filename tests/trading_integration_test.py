import time

from DexilonClientImpl import DexilonClientImpl
from OrderErrorInfo import OrderErrorInfo
from responses import OrderEvent, LeverageEvent, FundsTransferResponse


class TestTradingIntegration:
    TEST_METAMASK_ADDRESS = '0x201d980aeD5C04a7e75860cFE29CeD9b5da05A08'
    TEST_PRIVATE_KEY = '87d25c8ade8c4bb32be098bb35cd594fd1c0511c4423bf36f006f4ecd27f017c'

    def setup(self):
        self.test_instance = DexilonClientImpl(self.TEST_METAMASK_ADDRESS, self.TEST_PRIVATE_KEY)
        self.test_instance.change_api_url('https://api.dev.dexilon.io/api/v1')
        self.test_instance.change_dexilon_account_api_url('http://65.108.44.122:1317/dexilon-exchange/dexilonl2')

    def test_create_market_order(self):
        full_order_info = self.test_instance.market_order('0c3e662f-3143-e4c1-39f7-dafd2faa10bd', 'eth_usdt', 'BUY', 0.10)
        assert isinstance(full_order_info, OrderEvent) and full_order_info.orderId is not None

    def test_create_market_order_with_rejected_state(self):
        order_submit_result = self.test_instance.market_order('0c3e662f-3143-e4c1-39f7-dafd2faa10bd', 'eth_usdt', 'BUY', 1000000000.00)
        assert isinstance(order_submit_result, OrderErrorInfo)
        assert 'NEW_ORDER_REJECTED' in order_submit_result.state

    def test_create_limit_order(self):
        full_order_info = self.test_instance.limit_order('880d2806-f396-4dc4-c795-8abb2d00853e', 'eth_usdt', 'SELL', 1400.0, 0.1)
        assert isinstance(full_order_info, OrderEvent) and full_order_info.orderId is not None

    def test_create_limit_order_with_rejected_state(self):
        full_order_info = self.test_instance.limit_order('880d2806-f396-4dc4-c795-8abb2d00853e', 'eth_usdt', 'BUY', 3200.0, 100.0)
        assert isinstance(full_order_info, OrderErrorInfo)

    def test_should_cancel_all_orders(self):
        result = self.test_instance.cancel_all_orders()
        assert result

    def test_should_return_error_on_cancel_order(self):
        result = self.test_instance.cancel_order(1000, 'eth_usdt')
        assert isinstance(result, OrderErrorInfo)

    def test_should_create_and_cancel_order_sucessfully(self):
        full_order_info = self.test_instance.limit_order('880d2806-f396-4dc4-c795-8abb2d00853e', 'eth_usdt', 'BUY', 1280.0, 0.2)
        assert isinstance(full_order_info, OrderEvent)
        canceled_order_info = self.test_instance.cancel_order(full_order_info.orderId, full_order_info.symbol)
        assert isinstance(canceled_order_info, OrderEvent)

    def test_should_get_account_info(self):
        account_info_result = self.test_instance.get_account_info()
        assert account_info_result is not None

    def test_should_get_all_open_orders(self): #
        full_order_info = self.test_instance.limit_order('880d2806-f396-4dc4-c795-8abb2d00853e', 'eth_usdt', 'BUY', 1200.0, 0.2)

        time.sleep(3) #TODO: remove after it will be fixed on backend: order does not appear immediatelly in open order list

        open_orders = self.test_instance.get_open_orders()
        assert len(open_orders) > 0

        self.test_instance.cancel_order(full_order_info.orderId, full_order_info.symbol)

    def test_should_get_order_info(self): #
        full_order_info = self.test_instance.limit_order('880d2806-f396-4dc4-c795-8abb2d00853e', 'eth_usdt', 'BUY', 1260.0, 0.2)

        time.sleep(3)  # TODO: remove after it will be fixed on backend: order does not appear immediatelly in open order list

        order_info = self.test_instance.get_order_info(full_order_info.orderId, full_order_info.clientOrderId, full_order_info.symbol)
        assert order_info is not None
        assert isinstance(order_info, OrderEvent)
        cancel_result = self.test_instance.cancel_order(order_info.orderId, order_info.symbol)
        assert cancel_result is not None
        assert isinstance(cancel_result, OrderEvent)

    def test_should_error_on_cancel_wrong_order(self):
        cancel_result = self.test_instance.cancel_order('0c3e662f-3143-e4c1-39f7-da3ф2faa10bd', 'eth_usdt')
        assert isinstance(cancel_result, OrderErrorInfo)

    def test_should_parse_response_for_illegal_char_in_cancel_request(self):
        cancel_result = self.test_instance.cancel_order('RANDOM-ID-1', 'eth_usdt')
        assert isinstance(cancel_result, OrderErrorInfo)

    def test_should_process_error_for_limit_order_submit(self):
        order_submit_result = self.test_instance.limit_order('880d2806-f396-4dc4-c795-8abb2d00853e', 'eth_usdt', 'BUY', 2000.00, 0.10)
        assert isinstance(order_submit_result, OrderErrorInfo)
        if isinstance(order_submit_result, OrderErrorInfo):
            assert 'NEW_ORDER_REJECTED' in order_submit_result.state

    def test_should_set_leverage(self):
        self.test_instance.cancel_all_orders()
        leverage_update = self.test_instance.set_leverage('eth_usdt', 1)
        assert isinstance(leverage_update, LeverageEvent)


    def test_should_transfer_funds_from_trading_to_spot(self):
        test_transfer_amount = 10
        transfer_result = self.test_instance.transfer_funds_from_trading_to_spot(test_transfer_amount, 'usdt')
        assert transfer_result is not None
        assert isinstance(transfer_result, FundsTransferResponse)
        assert transfer_result.amount == test_transfer_amount
