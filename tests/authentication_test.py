import sys
try:
    sys.path.append('/opt/dexbot3/src/')
    sys.path.append('/opt/dexbot3/src/dexilon-python-sdk')
except:
    print("path not exist")

from DexilonClientImpl import DexilonClientImpl
from OrderErrorInfo import OrderErrorInfo
from responses import FullOrderInfo


class TestAuthentication:
    # TEST_METAMASK_ADDRESS = '0x201d980aeD5C04a7e75860cFE29CeD9b5da05A08'
    # TEST_PRIVATE_KEY = '87d25c8ade8c4bb32be098bb35cd594fd1c0511c4423bf36f006f4ecd27f017c'
    TEST_METAMASK_ADDRESS = '0x40e42c763Dfd16EF2302c49240040a480a081C3A'
    TEST_PRIVATE_KEY = '8abc5ca595d9bb6ebe133936ede1f689450baba2e5a571c2a0e356872a695b28'

    def setup(self):
        self.test_instance = DexilonClientImpl(self.TEST_METAMASK_ADDRESS, self.TEST_PRIVATE_KEY)
        self.test_instance.change_api_url('https://dex-dev2-api.cronrate.com/api/v1')

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

if __name__ == "__main__":
    t1 = TestAuthentication()
    t1.setup()
    t1.test_should_get_cosmos_address_mapping_successfully()