import json
import logging
from datetime import datetime
from typing import List

import requests as requests
from eth_account.messages import encode_defunct
from eth_keys import keys
from pydantic import BaseModel, parse_obj_as
from web3 import Web3
from web3.auto import w3

from DexilonClient import DexilonClient
from ErrorBody import ErrorBody
from OrderErrorInfo import OrderErrorInfo
from SessionClient import SessionClient
from exceptions import DexilonAPIException, DexilonRequestException, DexilonAuthException,DexilonErrorBodyException
from responses import AvailableSymbol, OrderBookInfo, JWTTokenResponse, OrderEvent, \
    ServiceResponse, ErrorBody, AccountInfo, OrderInfo, AllOpenOrders, \
    FullOrderInfo, LeverageUpdateInfo, CosmosAddressMapping


class DexilonClientImpl(DexilonClient):
    API_URL = 'https://dex-dev2-api.cronrate.com/api/v1'
    COSMOS_ADDRESS_API_URL = 'http://88.198.205.192:1317/dexilon-exchange/dexilonl2'

    JWT_KEY = ''
    REFRESH_TOKEN = ''

    pk1 = ''

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    cosmos_headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    def __init__(self, metamask_address, api_secret):
        """ Dexilon API Client constructor

        :param metamask_address: Public Metamask Address
        :type metamask_address: str.
        :param api_secret: Api Secret
        :type api_secret: str.
        """

        self.METAMASK_ADDRESS = metamask_address
        self.headers['MetamaskAddress'] = self.METAMASK_ADDRESS
        self.API_SECRET = api_secret
        self.pk1 = keys.PrivateKey(bytes.fromhex(api_secret))

    def setup(self):
        self.client: SessionClient = SessionClient(self.API_URL, self.headers)
        self.client.base_url = self.API_URL
        self.dex_session_client: SessionClient = SessionClient(self.COSMOS_ADDRESS_API_URL, self.cosmos_headers)

    def change_api_url(self, api_url, cosmos_address_api_url):
        """
        Used for testing purposes

        :param api_url: Public
        :type api_url: str.

        """
        self.API_URL = api_url
        self.COSMOS_ADDRESS_API_URL = cosmos_address_api_url


    def change_cosmos_api_url(self, cosmos_api_url):
        """
        Used for testing purposes
        :param cosmos_api_url:
        :return:
        """
        self.COSMOS_ADDRESS_API_URL = cosmos_api_url

    def get_open_orders(self) -> List[OrderInfo]:
        self.check_authentication()
        all_open_orders_response = self._request('GET', '/orders/open', model=AllOpenOrders)
        if isinstance(all_open_orders_response, AllOpenOrders):
            return all_open_orders_response.content
        return all_open_orders_response

    def get_order_info(self, order_id: str, symbol: str) -> FullOrderInfo:
        self.check_authentication()
        get_order_info_request_params = {'symbol': symbol, 'orderId': order_id}
        return self._request('GET', '/orders', params=get_order_info_request_params, model=FullOrderInfo)

    def market_order(self, client_order_id: str, symbol: str, side: str, size: float):
        self.check_authentication()
        json_request_body = {'clientorderId': client_order_id, 'symbol': symbol, 'side': side, 'size': size}
        order_response = self._request('POST', '/orders/market', data=json_request_body, model=OrderEvent)
        return self.parse_order_info_response(order_response, 'MARKET', client_order_id)

    def parse_order_info_response(self, order_info_response, order_type, client_order_id):
        if isinstance(order_info_response, ServiceResponse):
            return OrderErrorInfo(client_order_id, '', order_info_response.errorBody.name,
                                  ';'.join(order_info_response.errorBody.details))
        error_body = self.get_error_body(order_info_response)
        if error_body is not None:
            return OrderErrorInfo(client_order_id, '', error_body.name, error_body.details)
        if order_info_response.eventType is not None:
            if order_info_response.eventType in ['EXECUTED', 'PARTIALLY_EXECUTED', 'APPLIED']:
                order_data = order_info_response.event
                order_dict = {
                    "clientOrderId": client_order_id,
                    "symbol": self.parse_value_or_return_None(order_data, 'symbol'),
                    "orderId": self.parse_value_or_return_None(order_data, 'orderId'),
                    "price": self.parse_value_or_return_None(order_data, 'price'),
                    "amount": self.parse_value_or_return_None(order_data, 'size'),
                    "filledAmount": self.parse_value_or_return_None(order_data, 'filled'),
                    "avgPrice": self.parse_value_or_return_None(order_data, 'avgPrice'),
                    "type": order_type,
                    "side": self.parse_value_or_return_None(order_data, 'side'),
                    "status": order_info_response.eventType,
                    "createdAt": self.parse_value_or_return_None(order_data, 'placedAt'),
                    "updatedAt": self.parse_value_or_return_None(order_data, 'placedAt')
                }
                return FullOrderInfo(**order_dict)
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
        json_request_body = {'clientorderId': client_order_id, 'symbol': symbol, 'side': side, 'size': size,
                             'price': price}
        limit_order_response = self._request('POST', '/orders/limit', data=json_request_body, model=OrderEvent)
        return self.parse_order_info_response(limit_order_response, 'LIMIT', client_order_id)

    def cancel_all_orders(self) -> bool:
        self.check_authentication()
        cancel_all_orders_response = self._request('DELETE', '/orders/all', model=List[OrderEvent])
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

    def set_leverage(self, symbol: str, leverage: int) -> LeverageUpdateInfo:
        self.check_authentication()
        leverage_request = {'symbol': symbol, 'leverage': leverage}
        return self._request('PUT', '/accounts/leverage', data=leverage_request, model=LeverageUpdateInfo)

    def _request(self, method: str, path: str, params: dict = None, data: dict = None,
                 model: BaseModel = None) -> BaseModel:
        return self.request_with_client(self.client, method, path, params, data, model)

    def _request_dexilon_api(self, method: str, path: str, params: dict = None, data: dict = None,
                             model: BaseModel = None) -> BaseModel:
        return self._handle_dexilon_response(
            response=self.dex_session_client.request(
                method=method,
                path=path,
                params=params,
                data=data
            ),
            model=model
        )

    def _handle_dexilon_response(self, response: dict, model: BaseModel = None) -> BaseModel:
        logging.debug("response: %s" % (response))
        if response is None:
            service_response = parse_obj_as(ServiceResponse, response)
            return service_response
        if model:
            return parse_obj_as(model, response)
        else:
            return response

    def request_with_client(self, client, method: str, path: str, params: dict = None, data: dict = None,
                            model: BaseModel = None) -> BaseModel:
        try:
            return self._handle_response_new(
                response=client.request(
                    method=method,
                    path=path,
                    params=params,
                    data=data
                ),
                model=model
            )
        except DexilonAuthException:
            self.authenticate()
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
        logging.debug("response: %s" % (response))
        data: dict = response['body']
        if data is None:
            error_body: dict = response.get('errorBody')
            if error_body:
                raise DexilonErrorBodyException(
                    ErrorBody(
                        code=error_body.get('code'),
                        name=error_body.get('name'),
                        details=error_body.get('details', [])
                    )
                )
            else:
                raise DexilonRequestException(
                    'body and errorBody is empty in response %s' % json.dumps(response))
            service_response = parse_obj_as(ServiceResponse, response)
            return service_response
        if model:
            return parse_obj_as(model, data)
        else:
            return data

    def request_get(self, uri, params_request):
        r = requests.get(self.API_URL + uri, headers=self.headers, params=params_request)
        response = self.handle_response(r)
        if r.status_code == 401:
            print('The user is not authorized to perform the request. Reauthorizing...')
            self.authenticate()
            r = requests.get(self.API_URL + uri, headers=self.headers, params=params_request)
            return self.handle_response(r)
        return response

    def request_post(self, uri, **kwargs):
        r = requests.post(self.API_URL + uri, headers=self.headers, json=kwargs)
        response = self.handle_response(r)
        if r.status_code == 401:
            print('The user is not authorized to perform the request. Reauthorizing...')
            self.authenticate()
            r = requests.post(self.API_URL + uri, headers=self.headers, json=kwargs)
            return self.handle_response(r)
        return response

    def get_error_body(self, response) -> ErrorBody:
        if 'errorBody' in response and response['errorBody'] is not None:
            error_body = response['errorBody']
            return ErrorBody(error_body['code'], error_body['name'], ';'.join(error_body['details']))
        return None

    def check_authentication(self):
        if len(self.JWT_KEY) == 0:
            self.authenticate()

    def sign(self, nonce: str) -> str:
        return w3.eth.account.sign_message(
            encode_defunct(nonce), private_key=self.pk1
        ).signature.hex()

    def get_cosmos_address_mapping(self, eth_address: str, chain_id: str):
        cosmos_maping_response = self._request_dexilon_api('GET', '/registration/address_mapping/mirror/' + chain_id + '/' + eth_address,
                                                           model=CosmosAddressMapping)
        return cosmos_maping_response

    def hash_keccak(self, message: str):
        return Web3.solidityKeccak(['string'], [message])

    def authenticate(self):
        # TODO remove hardcode!
        dexilon_address = self.get_cosmos_address_mapping(self.METAMASK_ADDRESS, "80001")
        if dexilon_address.code is not None:
            print(
                'There is no Dexilon chain mapping for Etherium address ' + self.METAMASK_ADDRESS + '. Registering user in Dexilon chain')
            dexilon_chain_address = self.register_dexilon_user(self.METAMASK_ADDRESS)
        else:
            dexilon_chain_address = dexilon_address.addressMapping.cosmosAddress

        cur_time_in_milliseconds = int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds() * 1000)
        nonce = str(cur_time_in_milliseconds) + '#' + dexilon_chain_address
        nonce_hashed = self.hash_keccak(nonce)
        payload = {'ethAddress': self.METAMASK_ADDRESS, 'nonce': nonce, 'signedNonce': self.sign(nonce_hashed)}

        auth_info = self._request('POST', '/auth/accessToken', data=payload, model=JWTTokenResponse)

        jwt_token = auth_info.accessToken
        refresh_token = auth_info.refreshToken
        if jwt_token is None or len(jwt_token) == 0:
            raise DexilonAuthException('Was not able to obtain JWT token for authentication')

        print(jwt_token)
        self.client.update_headers({'Authorization': 'Bearer ' + jwt_token, 'CosmosAddress': dexilon_chain_address})
        self.headers['Authorization'] = 'Bearer ' + jwt_token
        self.headers['CosmosAddress'] = dexilon_chain_address
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

    def register_dexilon_user(self, metamask_address: str):
        pass
