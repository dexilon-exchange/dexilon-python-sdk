from datetime import datetime

import requests as requests

from web3.auto import w3
from eth_account.messages import encode_defunct
from eth_keys import keys

from AvailableSymbol import AvailableSymbol
from DexilonClient import DexilonClient
from FullOrderInfo import FullOrderInfo
from MarginData import MarginData
from OrderBook import OrderBook
from OrderBookInfo import OrderBookInfo
from OrderInfo import OrderInfo
from exceptions import DexilonAPIException, DexilonRequestException, DexilonAuthException
from typing import List


class DexilonClientImpl(DexilonClient):
    API_URL = 'https://dex-dev-api.cronrate.com/api/v1'

    JWT_KEY = ''

    pk1 = ''

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    def __init__(self, metamask_address, api_secret):
        """ Dexilon API Client constructor

        :param metamask_address: Public Metamask Address
        :type metamask_address: str.
        :param api_secret: Api Secret
        :type api_secret: str.
        """

        self.METAMASK_ADDRESS = metamask_address
        self.API_SECRET = api_secret
        self.pk1 = keys.PrivateKey(bytes.fromhex(api_secret))

    def change_api_url(self, api_url):
        """
        Used for testing purposes

        :param api_url: Public
        :type api_url: str.

        """

        self.API_URL = api_url

    def get_open_orders(self) -> List[OrderInfo]:
        orders_response = {}
        self.check_authentication()
        open_orders_response = self.request_get('/orders/open', None)
        open_orders_by_symbol = open_orders_response['body']
        for orders_by_symbol in open_orders_by_symbol:
            symbol = orders_by_symbol['symbol']
            order_list = orders_by_symbol['orders']
            orders_response[symbol] = []
            for order in order_list:
                order_info = OrderInfo(order['id'], order['type'], order['amount'], order['price'], order['side'],
                                       order['placedAt'])
                orders_response[symbol].append(order_info)
        return orders_response

    def get_order_info(self, order_id: str, symbol: str) -> FullOrderInfo:
        self.check_authentication()
        get_order_info_request_params = {'symbol': symbol, 'orderId': order_id}
        order_info_response = self.request_get('/orders', get_order_info_request_params)
        return FullOrderInfo(order_info_response['body']['symbol'], order_info_response['body']['orderId'], order_info_response['body']['price'], order_info_response['body']['amount'],
                             order_info_response['body']['filledAmount'], order_info_response['body']['avgPrice'], order_info_response['body']['type'], order_info_response['body']['side'], order_info_response['body']['status'],
                             )

    def market_order(self, client_order_id: str, symbol: str, side: str, size: float) -> str:
        self.check_authentication()
        json_request_body = {'clientorderId': client_order_id, 'symbol': symbol, 'side': side, 'size': size}
        market_order_response = self.request_post('/orders/market', **json_request_body)
        market_order_id = market_order_response['body']['orderId']
        return market_order_id

    # {'eventType': 'REJECTED', 'event': {'cause': "User don't have enough balance for market order execution"}}

    def limit_order(self, client_order_id: str, symbol: str, side: str, price: float, size: float) -> str:
        self.check_authentication()
        json_request_body = {'clientorderId': client_order_id, 'symbol': symbol, 'side': side, 'size': size,
                             'price': price}
        limit_order_response = self.request_post('/orders/limit', **json_request_body)
        limit_order_id = limit_order_response['body']['orderId']
        return limit_order_id

    def cancel_all_orders(self) -> bool:
        cancel_all_orders_response = self.request_delete('/orders/batch')
        return cancel_all_orders_response['errors'] is None

    def cancel_order(self, order_id: str, symbol: str) -> bool:
        cancel_order_request_body = {'symbol': symbol, 'orderId': order_id}
        cancel_order_response = self.request_delete('/orders', **cancel_order_request_body);
        return cancel_order_response['errors'] is None

    # {'body': {'eventType': 'REJECTED', 'event': {'cause': 'Order has been executed'}}, 'errors': None, 'debugInfo': None}

    def get_all_symbols(self) -> List[AvailableSymbol]:
        all_symbols_response = self.request_get('/symbols', None)
        available_symbols = []
        all_symbols_list = all_symbols_response['body']
        for symbol in all_symbols_list:
            available_symbols.append(
                AvailableSymbol(symbol['symbol'], symbol['isFavorite'], symbol['lastPrice'], symbol['volume'],
                                symbol['price24Percentage']))
        return available_symbols

    def get_orderbook(self, symbol: str) -> OrderBookInfo:
        orderbook_request = {'symbol': symbol}
        orderbooks_response = self.request_get('/orders/book', orderbook_request)
        all_orderbook_values = orderbooks_response['body']

        return OrderBookInfo(self.parse_order_books('ask', all_orderbook_values),
                             self.parse_order_books('bid', all_orderbook_values), datetime.now())

    def get_margin(self) -> MarginData:
        self.check_authentication()
        margin_response = self.request_get('/margin', None)

        return MarginData(margin_response['body']['margin'], margin_response['body']['upl'],
                          margin_response['body']['equity'], margin_response['body']['lockedBalanceForOpenOrders'])

    def request_get(self, uri, params_request):
        r = requests.get(self.API_URL + uri, headers=self.headers, params=params_request)
        response = self.handle_response(r)
        error_message = self.get_error_message(response)
        if len(error_message) > 0 and 'Unable to validate JWT token' in error_message:
            print('JWT Token expired. Need to reauthenticate')
            self.authenticate()
            r = requests.get(self.API_URL + uri, headers=self.headers, params=params_request)
            return self.handle_response(r)
        return response

    def request_post(self, uri, **kwargs):
        self.check_authentication()
        r = requests.post(self.API_URL + uri, headers=self.headers, json=kwargs)
        response = self.handle_response(r)
        error_message = self.get_error_message(response)
        if len(error_message) > 0 and 'Unable to validate JWT token' in error_message['message']:
            print('JWT Token expired. Need to reauthenticate')
            self.authenticate()
            r = requests.post(self.API_URL + uri, headers=self.headers, json=kwargs)
            return self.handle_response(r)
        return response

    def request_delete(self, uri, **kwargs):
        self.check_authentication()
        r = requests.delete(self.API_URL + uri, headers=self.headers, params=kwargs)
        response = self.handle_response(r)
        error_message = self.get_error_message(response)
        if len(error_message) > 0 and 'Unable to validate JWT token' in error_message['message']:
            print('JWT Token expired. Need to reauthenticate')
            self.authenticate()
            r = requests.delete(self.API_URL + uri, headers=self.headers, params=kwargs)
            return self.handle_response(r)
        return response


    def get_error_message(self, response) -> str:
        if 'errors' in response and response['errors'] is not None and len(response['errors']) > 0:
            return response['errors']
        return ''

    def parse_order_books(self, type: str, data_holder) -> List[OrderBook]:
        data_entries = data_holder[type]
        result = []
        for data_entry in data_entries:
            result.append(OrderBook(data_entry['price'], data_entry['size'], data_entry['sum']))

        return result

    def check_authentication(self):
        if len(self.JWT_KEY) == 0:
            self.authenticate()

    def authenticate(self):
        payload = {'metamaskAddress': self.METAMASK_ADDRESS}
        r = requests.post(self.API_URL + '/auth/startAuth', json=payload, headers=self.headers)
        nonce_response = self._handle_response(r)
        nonce = nonce_response['body']['nonce']
        if len(nonce) == 0:
            print('ERROR: nonce was not received for Authentication request')
        print(nonce)

        signature = w3.eth.account.sign_message(
            encode_defunct(str.encode(nonce)), private_key=self.pk1
        ).signature

        signature_payload = {'metamaskAddress': self.METAMASK_ADDRESS, 'signedNonce': signature.hex()}

        print(signature_payload)

        auth_response = requests.post(self.API_URL + '/auth/finishAuth', json=signature_payload, headers=self.headers)

        auth_info = self._handle_response(auth_response)

        jwk_token = auth_info['body']['jwt']
        if jwk_token is None or len(jwk_token) == 0:
            raise DexilonAuthException('Was not able to obtain JWT token for authentication')

        print(auth_info)
        self.headers['Authorization'] = 'Bearer ' + jwk_token
        self.headers['MetamaskAddress'] = self.METAMASK_ADDRESS

        self.JWT_KEY = jwk_token

    def _handle_response(self, response):
        """Internal helper for handling API responses from the Dexilon server.
        Raises the appropriate exceptions when necessary; otherwise, returns the
        response.
        """
        if not str(response.status_code).startswith('2'):
            raise DexilonAPIException(response)
        try:
            return response.json()
        except ValueError:
            raise DexilonRequestException('Invalid Response: %s' % response.text)

    def handle_response(self, response):
        try:
            return response.json()
        except ValueError:
            raise DexilonRequestException('Invalid Response: %s' % response.text)
