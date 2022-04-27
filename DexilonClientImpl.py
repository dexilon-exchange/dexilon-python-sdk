from datetime import datetime

import requests as requests
from eth_keys.datatypes import PrivateKey
from pydantic import BaseModel, parse_obj_as

from web3.auto import w3
from eth_account.messages import encode_defunct
from eth_keys import keys

from DexilonClient import DexilonClient
from ErrorInfo import ErrorInfo
from FullOrderInfo import FullOrderInfo
from MarginData import MarginData
from OrderErrorInfo import OrderErrorInfo
from OrderInfo import OrderInfo
from SessionClient import SessionClient
from exceptions import DexilonAPIException, DexilonRequestException, DexilonAuthException, DexilonEventException
from typing import List

from responses import AvailableSymbol, OrderBookInfo, OrderBook


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

        self.METAMASK_ADDRESS = metamask_address.lower()
        self.pk1 = keys.PrivateKey(bytes.fromhex(api_secret))

        self.client: SessionClient = SessionClient(self.API_URL, self.headers)

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
        if 'body' in order_info_response:
            order_info_body = order_info_response['body']
            # TODO add client_order_id
            return FullOrderInfo('',
                                 self.parse_value_or_return_None(order_info_body, 'symbol'),
                                 self.parse_value_or_return_None(order_info_body, 'orderId'),
                                 self.parse_value_or_return_None(order_info_body, 'price'),
                                 self.parse_value_or_return_None(order_info_body, 'amount'),
                                 self.parse_value_or_return_None(order_info_body, 'filledAmount'),
                                 self.parse_value_or_return_None(order_info_body, 'avgPrice'),
                                 self.parse_value_or_return_None(order_info_body, 'type'),
                                 self.parse_value_or_return_None(order_info_body, 'side'),
                                 self.parse_value_or_return_None(order_info_body, 'status'),
                                 self.parse_value_or_return_None(order_info_body, 'createdAt'),
                                 self.parse_value_or_return_None(order_info_body, 'updatedAt')
                                 )

        return FullOrderInfo('', order_info_response['body']['symbol'], order_info_response['body']['orderId'],
                             order_info_response['body']['price'], order_info_response['body']['amount'],
                             order_info_response['body']['filledAmount'], order_info_response['body']['avgPrice'],
                             order_info_response['body']['type'], order_info_response['body']['side'],
                             order_info_response['body']['status'], order_info_response['body']['createdAt'], order_info_response['body']['updatedAt']
                             )

    def market_order(self, client_order_id: str, symbol: str, side: str, size: float):
        self.check_authentication()
        json_request_body = {'clientorderId': client_order_id, 'symbol': symbol, 'side': side, 'size': size}
        market_order_response = self.request_post('/orders/market', **json_request_body)
        return self.parse_order_info_response(market_order_response, 'MARKET', client_order_id)

    def parse_order_info_response(self, order_info_response, order_type, client_order_id):
        if 'errors' in order_info_response and order_info_response['errors'] is not None:
            errors = order_info_response['errors']
            return ErrorInfo(self.parse_value_or_return_None(errors, 'code'), self.parse_value_or_return_None(errors, 'message'))
        if 'body' in order_info_response:
            if 'eventType' in order_info_response['body']:
                eventType = order_info_response['body']['eventType']
                if eventType in ['EXECUTED', 'PARTIALLY_EXECUTED', 'APPLIED']:
                    order_data = order_info_response['body']['event']
                    return FullOrderInfo(client_order_id, self.parse_value_or_return_None(order_data, 'symbol'),
                                         self.parse_value_or_return_None(order_data, 'orderId'),
                                         self.parse_value_or_return_None(order_data, 'price'),
                                         self.parse_value_or_return_None(order_data, 'size'),
                                         self.parse_value_or_return_None(order_data, 'filled'),
                                         self.parse_value_or_return_None(order_data, 'avgPrice'),
                                         order_type,
                                         self.parse_value_or_return_None(order_data, 'side'),
                                         eventType,
                                         self.parse_value_or_return_None(order_data, 'placedAt'),
                                         self.parse_value_or_return_None(order_data, 'placedAt')
                                         )
                if 'REJECTED' == eventType:
                    order_error_data = order_info_response['body']['event']
                    return OrderErrorInfo(client_order_id, '', eventType, order_error_data['cause'])

    def parse_value_or_return_None(self, object_to_parse, param_name):
        if param_name in object_to_parse:
            return object_to_parse[param_name]
        else:
            return None

    def limit_order(self, client_order_id: str, symbol: str, side: str, price: float, size: float):
        self.check_authentication()
        json_request_body = {'clientorderId': client_order_id, 'symbol': symbol, 'side': side, 'size': size,
                             'price': price}
        limit_order_response = self.request_post('/orders/limit', **json_request_body)
        return self.parse_order_info_response(limit_order_response, 'LIMIT', client_order_id)

    def cancel_all_orders(self) -> bool:
        cancel_all_orders_response = self.request_delete('/orders/batch')
        return cancel_all_orders_response['errors'] is None

    def cancel_order(self, order_id: str, symbol: str):
        cancel_order_request_body = {'symbol': symbol, 'orderId': order_id}
        cancel_order_response = self.request_delete('/orders', **cancel_order_request_body);
        return self.parse_order_info_response(cancel_order_response, '', '')

    def get_all_symbols(self) -> List[AvailableSymbol]:
        return self._request('GET', '/symbols', model=List[AvailableSymbol])

    def _request(self, method: str, path: str, params: dict = None, data: dict = None, model: BaseModel = None) -> BaseModel:

        return self._handle_response_new(
            response=self.client.request(
                method=method,
                path=path,
                params=params,
                data=data
            ),
            model=model
        )

    def get_orderbook(self, symbol: str) -> OrderBookInfo:
        orderbook_request = {'symbol': symbol}
        orderbook_info = self._request('GET', '/orders/book', params=orderbook_request, model=OrderBookInfo)
        orderbook_info.timestamp = datetime.now()
        return orderbook_info

    def get_margin(self) -> MarginData:
        self.check_authentication()
        margin_response = self.request_get('/margin', None)
        margin_response_body = margin_response['body']

        return MarginData(self.parse_value_or_return_None(margin_response_body, 'margin'),
                          self.parse_value_or_return_None(margin_response_body, 'upl'),
                          self.parse_value_or_return_None(margin_response_body, 'equity'),
                          self.parse_value_or_return_None(margin_response_body, 'locked')
                          )

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

    def check_authentication(self):
        if len(self.JWT_KEY) == 0:
            self.authenticate()

    def authenticate(self):
        payload = {'metamaskAddress': self.METAMASK_ADDRESS}
        nonce_response = self._request('POST', '/auth/startAuth', model=dict, data=payload)
        nonce = nonce_response['nonce']
        if len(nonce) == 0:
            print('ERROR: nonce was not received for Authentication request')
        print(nonce)

        signature = w3.eth.account.sign_message(
            encode_defunct(str.encode(nonce)), private_key=self.pk1
        ).signature

        signature_payload = {'metamaskAddress': self.METAMASK_ADDRESS, 'signedNonce': signature.hex()}

        print(signature_payload)

        # auth_response = requests.post(self.API_URL + '/auth/finishAuth', json=signature_payload, headers=self.headers)
        auth_response = self._request('POST', '/auth/finishAuth', model=dict, data=signature_payload)

        jwk_token = auth_response['jwt']
        if jwk_token is None or len(jwk_token) == 0:
            raise DexilonAuthException('Was not able to obtain JWT token for authentication')

        print(jwk_token)
        self.client.update_headers({'Authorization':'Bearer ' + jwk_token, 'MetamaskAddress': self.METAMASK_ADDRESS})
        # self.headers['Authorization'] = 'Bearer ' + jwk_token
        # self.headers['MetamaskAddress'] = self.METAMASK_ADDRESS

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

    def _handle_response_new(self, response: dict, model: BaseModel = None) -> BaseModel:
        data: dict = response['body']
        if 'eventType' in data or 'event' in data:
            self._handle_event(
                event_type=data.get('eventType'),
                event_data=data.get('event')
            )
        elif model:
            return parse_obj_as(model, data)
        else:
            return data

    def _handle_event(self, event_type: str, event_data: dict):
        if event_type == 'REJECTED':
            raise DexilonEventException(event_data['cause'])
