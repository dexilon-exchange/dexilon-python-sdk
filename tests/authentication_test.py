from DexilonClientImpl import DexilonClientImpl
from OrderErrorInfo import OrderErrorInfo
from responses import FullOrderInfo


class TestAuthentication:
    TEST_METAMASK_ADDRESS = '0x201d980aeD5C04a7e75860cFE29CeD9b5da05A08'
    TEST_PRIVATE_KEY = '87d25c8ade8c4bb32be098bb35cd594fd1c0511c4423bf36f006f4ecd27f017c'

    def setup(self):
        self.test_instance = DexilonClientImpl(self.TEST_METAMASK_ADDRESS, self.TEST_PRIVATE_KEY)
        self.test_instance.change_api_url('https://api.dev.dexilon.io/api/v1')
        self.test_instance.change_cosmos_api_url('https://proxy.dev.dexilon.io/dexilon-exchange/dexilonl2')
        # self.test_instance.change_api_url('https://testnet-v2-api.dexilon-dev.xyz/api/v1')

    def test_should_get_cosmos_address_mapping_successfully(self):
        cosmos_address_maping = self.test_instance.get_cosmos_address_mapping(self.TEST_METAMASK_ADDRESS)
        assert cosmos_address_maping is not None
        assert cosmos_address_maping.addressMapping is not None


    def test_should_get_address_not_found_if_there_is_no_mapping(self):
        cosmos_address_maping = self.test_instance.get_cosmos_address_mapping(self.TEST_METAMASK_ADDRESS + "_WRONG")
        assert cosmos_address_maping is not None
        assert cosmos_address_maping.code == 5

    def test_should_authenticate(self):
        self.test_instance.authenticate()
        assert self.test_instance.JWT_KEY != ''

    def test_should_reauthenticate_on_get_accounts_request_if_token_expired(self):
        self.test_instance.authenticate()
        self.test_instance.JWT_KEY = 'CHANGED_GWT_KEY'
        self.test_instance.client.update_headers({'Authorization': 'Bearer + ' + self.test_instance.JWT_KEY})
        account_info = self.test_instance.get_account_info()
        assert account_info is not None

    def test_should_reauthenticate_on_post_market_order(self):
        self.test_instance.authenticate()
        self.test_instance.JWT_KEY = 'CHANGED_GWT_KEY'
        self.test_instance.headers['Authorization'] = 'Bearer + ' + self.test_instance.JWT_KEY
        order_submit_response = self.test_instance.market_order('TEST_MARKET_ORDER_1', 'eth_usdc', 'BUY', 0.20)
        if isinstance(order_submit_response, OrderErrorInfo):
            assert True
        else:
            assert isinstance(order_submit_response, FullOrderInfo)

    def test_should_reauthenticate_on_delete_order(self):
        self.test_instance.authenticate()
        self.test_instance.JWT_KEY = 'CHANGED_GWT_KEY'
        self.test_instance.headers['Authorization'] = 'Bearer + ' + self.test_instance.JWT_KEY
        result = self.test_instance.cancel_order('TESTORDERID1', 'btc_usdc')
        assert result
