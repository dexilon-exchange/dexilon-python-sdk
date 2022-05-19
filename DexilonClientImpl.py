from datetime import datetime
import time

import requests as requests
from pydantic import BaseModel
from pydantic import BaseModel, parse_obj_as

from web3.auto import w3
from eth_account.messages import encode_defunct
from eth_keys import keys

from DexilonClient import DexilonClient
from ErrorBody import ErrorBody
from FullOrderInfo import FullOrderInfo
from OrderErrorInfo import OrderErrorInfo
from SessionClient import SessionClient
from exceptions import DexilonAPIException, DexilonRequestException, DexilonAuthException
from typing import List

from responses import AvailableSymbol, OrderBookInfo, OrderBook, NonceResponse, JWTTokenResponse, OrderEvent, \
    ServiceResponse, DebugInfo, ErrorBody, AccountInfo, OrderBalanceInfo, PositionInfo, OrderInfo, AllOpenOrders


class DexilonClientImpl(DexilonClient):
    API_URL = 'https://dex-dev-api.cronrate.com/api/v1'

    JWT_KEY = ''
    REFRESH_TOKEN = ''

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
        self.headers['MetamaskAddress'] = self.METAMASK_ADDRESS
        self.API_SECRET = api_secret
        self.pk1 = keys.PrivateKey(bytes.fromhex(api_secret))
        self.client: SessionClient = SessionClient(self.API_URL, self.headers)

    def change_api_url(self, api_url):
        """
        Used for testing purposes

        :param api_url: Public
        :type api_url: str.

        """

        self.API_URL = api_url
        self.client.base_url = api_url

    def get_open_orders(self) -> List[OrderInfo]:
        self.check_authentication()
        all_open_orders_response = self._request('GET', '/orders/open', model=AllOpenOrders)
        if isinstance(all_open_orders_response, AllOpenOrders):
            return all_open_orders_response.content
        return all_open_orders_response

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
        nonce = self.compose_nonce([client_order_id, symbol, side, size])
        signed_nonce = self.sign(nonce)
        json_request_body = {'clientorderId': client_order_id, 'symbol': symbol, 'side': side, 'size': size, 'nonce': nonce, 'signedNonce': signed_nonce}
        order_response = self._request('POST', '/orders/market', data=json_request_body, model=OrderEvent)
        return self.parse_order_info_response(order_response, 'MARKET', client_order_id)

    # def compose_nonce(self, client_order_id, symbol, side, size):
    def compose_nonce(self, kwargs: []):
        current_milliseconds = round(time.time() * 1000)
        nonce_value = ''
        for param in kwargs:
            nonce_value = nonce_value + str(param) + ':'
        return nonce_value + str(current_milliseconds)
        # return client_order_id + ':' + symbol + ':' + side + ':' + str(size) + ':' + str(current_milliseconds)

    def parse_order_info_response(self, order_info_response, order_type, client_order_id):
        if isinstance(order_info_response, ServiceResponse) :
            return OrderErrorInfo(client_order_id, '', order_info_response.errorBody.name, ';'.join(order_info_response.errorBody.details))
        error_body = self.get_error_body(order_info_response)
        if error_body is not None:
            return OrderErrorInfo(client_order_id, '', error_body.name, error_body.details)
        if order_info_response.eventType is not None:
            if order_info_response.eventType in ['EXECUTED', 'PARTIALLY_EXECUTED', 'APPLIED']:
                order_data = order_info_response.event
                return FullOrderInfo(client_order_id, self.parse_value_or_return_None(order_data, 'symbol'),
                                     self.parse_value_or_return_None(order_data, 'orderId'),
                                     self.parse_value_or_return_None(order_data, 'price'),
                                     self.parse_value_or_return_None(order_data, 'size'),
                                     self.parse_value_or_return_None(order_data, 'filled'),
                                     self.parse_value_or_return_None(order_data, 'avgPrice'),
                                     order_type,
                                     self.parse_value_or_return_None(order_data, 'side'),
                                     order_info_response.eventType,
                                     self.parse_value_or_return_None(order_data, 'placedAt'),
                                     self.parse_value_or_return_None(order_data, 'placedAt')
                                     )
            if 'REJECTED' == order_info_response.eventType:
                order_error_data = order_info_response['event']
                return OrderErrorInfo(client_order_id, '', order_info_response.eventType, order_error_data['cause'])

    def parse_value_or_return_None(self, object_to_parse, param_name):
        if param_name in object_to_parse:
            return object_to_parse[param_name]
        else:
            return None

    def limit_order(self, client_order_id: str, symbol: str, side: str, price: float, size: float):
        self.check_authentication()
        nonce = self.compose_nonce([client_order_id, symbol, side, size, price])
        signed_nonce = self.sign(nonce)
        json_request_body = {'clientorderId': client_order_id, 'symbol': symbol, 'side': side, 'size': size,
                             'price': price, 'nonce': nonce, 'signedNonce': signed_nonce}
        limit_order_response = self._request('POST', '/orders/limit', data=json_request_body, model=OrderEvent)
        return self.parse_order_info_response(limit_order_response, 'LIMIT', client_order_id)

    def cancel_all_orders(self) -> bool:
        self.check_authentication()
        cancel_all_orders_response = self._request('DELETE', '/orders/batch', model=List[OrderEvent])
        return isinstance(cancel_all_orders_response, list)

    def cancel_order(self, order_id: str, symbol: str):
        self.check_authentication()
        cancel_order_request_body = {'symbol': symbol, 'orderId': order_id}
        cancel_order_response = self._request('DELETE', '/orders', params=cancel_order_request_body, model=OrderEvent)
        return self.parse_order_info_response(cancel_order_response, '', '')

    def get_all_symbols(self) -> List[AvailableSymbol]:
        return self._request('GET', '/symbols', model=List[AvailableSymbol])

    def get_orderbook(self, symbol: str) -> OrderBookInfo:
        orderbook_request = {'symbol': symbol}
        return self._request('GET', '/orders/book', params=orderbook_request, model=OrderBookInfo)

    def get_account_info(self) -> AccountInfo:
        self.check_authentication()
        return self._request('GET', '/accounts', model=AccountInfo)

    def _request(self, method: str, path: str, params: dict = None, data: dict = None,
                 model: BaseModel = None) -> BaseModel:

        return self._handle_response_new(
            response=self.client.request(
                method=method,
                path=path,
                params=params,
                data=data
            ),
            model=model
        )

    def _handle_response_new(self, response: dict, model: BaseModel = None) -> BaseModel:
        data: dict = response['body']
        if data is None:
            service_response = parse_obj_as(ServiceResponse, response)
            return service_response
            # error_event_response = self._handle_error_event(service_response)
            # if error_event_response is not None:
            #     return error_event_response
        if model:
            return parse_obj_as(model, data)
        else:
            return data

    # def _handle_error_event(self, event_data: dict):
    #     if event_data.errorBody is not None:
    #         event_name = event_data.errorBody.name
    #         if 'NEW_ORDER_REJECTED' in event_name:
    #             return OrderErrorInfo('', '', event_name, event_data.errorBody.details)
    #     return None

    def request_get(self, uri, params_request):
        r = requests.get(self.API_URL + uri, headers=self.headers, params=params_request)
        response = self.handle_response(r)
        if r.status_code == 401:
            print('The user is not authorized to perform the request. Reauthorizing...')
            self.authenticate()
            r = requests.get(self.API_URL + uri, headers=self.headers, params=params_request)
            return self.handle_response(r)
        return response

    # def request_post_signed(self, uri, **kwargs):
    #     r = requests.post(self.API_URL + uri, headers=self.headers, json=kwargs)
    #     return self.handle_response(r)

    def request_post(self, uri, **kwargs):
        r = requests.post(self.API_URL + uri, headers=self.headers, json=kwargs)
        response = self.handle_response(r)
        if r.status_code == 401:
            print('The user is not authorized to perform the request. Reauthorizing...')
            self.authenticate()
            r = requests.post(self.API_URL + uri, headers=self.headers, json=kwargs)
            return self.handle_response(r)
        return response

    # def request_delete(self, uri, **kwargs):
    #     self.check_authentication()
    #     r = requests.delete(self.API_URL + uri, headers=self.headers, params=kwargs)
    #     response = self.handle_response(r)
    #     if r.status_code == 401:
    #         print('The user is not authorized to perform the request. Reauthorizing...')
    #         self.authenticate()
    #         r = requests.delete(self.API_URL + uri, headers=self.headers, params=kwargs)
    #         return self.handle_response(r)
    #     return response

    def get_error_body(self, response) -> ErrorBody:
        if 'errorBody' in response and response['errorBody'] is not None:
            error_body = response['errorBody']
            return ErrorBody(error_body['code'], error_body['name'], ';'.join(error_body['details']))
        return None

    # def parse_order_books(self, type: str, data_holder) -> List[OrderBook]:
    #     data_entries = data_holder[type]
    #     result = []
    #     for data_entry in data_entries:
    #         result.append(OrderBook(data_entry['price'], data_entry['size'], data_entry['sum']))
    #
    #     return result

    def check_authentication(self):
        if len(self.JWT_KEY) == 0:
            self.authenticate()

    def sign(self, nonce: str) -> str:
        return w3.eth.account.sign_message(
            encode_defunct(str.encode(nonce)), private_key=self.pk1
        ).signature.hex()

    def authenticate(self):
        payload = {'metamaskAddress': self.METAMASK_ADDRESS.lower()}
        self.client.delete_header("MetamaskAddress")
        nonce_response = self._request('POST', '/auth/startAuth', data=payload, model=NonceResponse)
        nonce = nonce_response.nonce
        if len(nonce) == 0:
            print('ERROR: nonce was not received for Authentication request')
        print(nonce_response)

        signature_payload = {'metamaskAddress': self.METAMASK_ADDRESS.lower(), 'signedNonce': self.sign(nonce)}
        print(signature_payload)

        auth_info = self._request('POST', '/auth/finishAuth', data=signature_payload, model=JWTTokenResponse)

        jwt_token = auth_info.accessToken
        refresh_token = auth_info.refreshToken
        if jwt_token is None or len(jwt_token) == 0:
            raise DexilonAuthException('Was not able to obtain JWT token for authentication')

        print(jwt_token)
        self.client.update_headers({'Authorization': 'Bearer ' + jwt_token, 'MetamaskAddress': self.METAMASK_ADDRESS.lower()})
        self.headers['Authorization'] = 'Bearer ' + jwt_token
        self.headers['MetamaskAddress'] = self.METAMASK_ADDRESS.lower()
        self.JWT_KEY = jwt_token
        self.REFRESH_TOKEN = refresh_token

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
