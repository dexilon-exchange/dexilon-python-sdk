from DexilonClientImpl import DexilonClientImpl


class TestAuthentication:
    TEST_METAMASK_ADDRESS = '0x201d980aeD5C04a7e75860cFE29CeD9b5da05A08'
    TEST_PRIVATE_KEY = '87d25c8ade8c4bb32be098bb35cd594fd1c0511c4423bf36f006f4ecd27f017c'

    def setup(self):
        self.test_instance = DexilonClientImpl(self.TEST_METAMASK_ADDRESS, self.TEST_PRIVATE_KEY)

    def test_should_authenticate(self):
        self.test_instance.authenticate()
        assert self.test_instance.JWT_KEY != ''

    def test_should_reauthenticate_on_get_margin_request_if_token_expired(self):
        self.test_instance.authenticate()
        self.test_instance.JWT_KEY = 'CHANGED_GWT_KEY'
        self.test_instance.headers['Authorization'] = 'Bearer + ' + self.test_instance.JWT_KEY
        margin = self.test_instance.get_margin()
        assert margin is not None

    def test_should_reauthenticate_on_post_market_order(self):
        self.test_instance.authenticate()
        self.test_instance.JWT_KEY = 'CHANGED_GWT_KEY'
        self.test_instance.headers['Authorization'] = 'Bearer + ' + self.test_instance.JWT_KEY
        order_id = self.test_instance.market_order('TEST_MARKET_ORDER_1', 'eth_usdc', 'BUY', 0.10)
        assert len(order_id) > 0

    def test_should_reauthenticate_on_delete_order(self):
        self.test_instance.authenticate()
        self.test_instance.JWT_KEY = 'CHANGED_GWT_KEY'
        self.test_instance.headers['Authorization'] = 'Bearer + ' + self.test_instance.JWT_KEY
        result = self.test_instance.cancel_order('TESTORDERID1', 'btc_usdc')
        assert result
