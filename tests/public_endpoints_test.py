from DexilonClientImpl import DexilonClientImpl
from responses import AvailableSymbolsResponse, AvailableSymbol, OrderBookInfo
from typing import List


class TestGetAllSymbols:
    TEST_METAMASK_ADDRESS = '0x201d980aeD5C04a7e75860cFE29CeD9b5da05A08'
    TEST_PRIVATE_KEY = '87d25c8ade8c4bb32be098bb35cd594fd1c0511c4423bf36f006f4ecd27f017c'

    def setup(self):
        self.test_instance = DexilonClientImpl(self.TEST_METAMASK_ADDRESS, self.TEST_PRIVATE_KEY)
        self.test_instance.change_api_url('https://dex-dev2-api.cronrate.com/api/v1')

    def test_get_all_symbols(self):
        all_symbols = self.test_instance.get_all_symbols()
        isinstance(all_symbols, List)
        assert len(all_symbols) > 0

    def test_should_get_order_book(self):
        order_book_data = self.test_instance.get_orderbook('sol_usdc')
        assert isinstance(order_book_data, OrderBookInfo)
