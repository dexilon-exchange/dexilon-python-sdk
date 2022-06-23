import json
import time
from typing import List, Any

from pydantic import BaseModel, parse_obj_as

from web3.auto import w3
from eth_account.messages import encode_defunct
from eth_keys import keys

from DexilonClient import DexilonClient
from SessionClient import SessionClient

from exceptions import DexilonAuthException, DexilonRequestException, DexilonErrorBodyException, OrderErrorInfo

from responses import AvailableSymbol, OrderBookInfo, NonceResponse, JWTTokenResponse, OrderEvent, \
    ErrorBody, AccountInfo, OrderInfo, AllOpenOrders, \
    FullOrderInfo, LeverageUpdateInfo


class DexilonClientImpl(DexilonClient):

    API_URL: str = 'https://dex-dev-api.cronrate.com/api/v1'

    JWT_KEY: str = ''
    REFRESH_TOKEN: str = ''

    def __init__(self, metamask_address: str, api_secret: str) -> None:
        """ Dexilon API Client constructor

        :param metamask_address: Public Metamask Address
        :type metamask_address: str.
        :param api_secret: Api Secret
        :type api_secret: str.
        """

        self.METAMASK_ADDRESS: str = metamask_address.lower()

        self.API_SECRET: str = api_secret
        self.pk1: keys.PrivateKey = keys.PrivateKey(bytes.fromhex(api_secret))
        self.client: SessionClient = SessionClient(self.API_URL, {
            'MetamaskAddress': self.METAMASK_ADDRESS
        })

    def check_authentication(func):
        def method(self: 'DexilonClientImpl', *args, **kwargs):
            if not self.JWT_KEY:
                self.authenticate()
            return func(self, *args, **kwargs)
        return method

    def change_api_url(self, api_url):
        """
        Used for testing purposes

        :param api_url: Public
        :type api_url: str.

        """

        self.API_URL = api_url
        self.client.base_url = api_url

    @check_authentication
    def get_open_orders(self) -> List[OrderInfo]:
        all_open_orders_response = self._request(
            'GET', '/orders/open', model=AllOpenOrders
        )
        if isinstance(all_open_orders_response, AllOpenOrders):
            return all_open_orders_response.content
        return all_open_orders_response

    @check_authentication
    def get_order_info(self, order_id: str, symbol: str) -> FullOrderInfo:
        get_order_info_request_params = {'symbol': symbol, 'orderId': order_id}
        return self._request('GET', '/orders', params=get_order_info_request_params, model=FullOrderInfo)

    @check_authentication
    def market_order(self, client_order_id: str, symbol: str, side: str, size: float):
        nonce = self.compose_nonce([client_order_id, symbol, side, size])
        signed_nonce = self.sign(nonce)
        json_request_body = {
            'clientorderId': client_order_id,
            'symbol': symbol,
            'side': side,
            'size': size,
            'nonce': nonce,
            'signedNonce': signed_nonce
        }
        order_response = self._request(
            'POST', '/orders/market', data=json_request_body, model=OrderEvent
        )
        return self.parse_order_info_response(order_response, 'MARKET', client_order_id)

    def compose_nonce(self, kwargs: List[Any]):
        current_milliseconds = round(time.time() * 1000)
        nonce_value = ''
        for param in kwargs:
            nonce_value = nonce_value + str(param) + ':'
        return nonce_value + str(current_milliseconds)

    def parse_order_info_response(self, order_info_response: OrderEvent, order_type: str, client_order_id: str):

        if order_info_response.eventType is not None:

            if order_info_response.eventType in ['EXECUTED', 'PARTIALLY_EXECUTED', 'APPLIED']:
                order_data: dict = order_info_response.event

                return FullOrderInfo(
                    clientOrderId=client_order_id,
                    symbol=order_data.get('symbol'),
                    orderId=order_data.get('orderId'),
                    price=order_data.get('price'),
                    amount=order_data.get('size'),
                    filledAmount=order_data.get('filled'),
                    avgPrice=order_data.get('avgPrice'),
                    type=order_type,
                    side=order_data.get('side'),
                    status=order_info_response.eventType,
                    createdAt=order_data.get('placedAt'),
                    updatedAt=order_data.get('updatedAt')
                )

            if 'REJECTED' == order_info_response.eventType:
                order_error_data = order_info_response['event']
                raise OrderErrorInfo(
                    client_order_id=client_order_id,
                    state=order_info_response.eventType,
                    message=order_error_data['cause']
                )

    @check_authentication
    def limit_order(self, client_order_id: str, symbol: str, side: str, price: float, size: float):
        nonce = self.compose_nonce(
            [client_order_id, symbol, side, size, price])
        signed_nonce = self.sign(nonce)
        json_request_body = {
            'clientorderId': client_order_id,
            'symbol': symbol,
            'side': side,
            'size': size,
            'price': price,
            'nonce': nonce,
            'signedNonce': signed_nonce
        }
        limit_order_response = self._request(
            'POST', '/orders/limit', data=json_request_body, model=OrderEvent
        )
        return self.parse_order_info_response(limit_order_response, 'LIMIT', client_order_id)

    @check_authentication
    def cancel_all_orders(self) -> bool:
        cancel_all_orders_response = self._request(
            'DELETE', '/orders/batch', model=List[OrderEvent]
        )
        return isinstance(cancel_all_orders_response, list)

    @check_authentication
    def cancel_order(self, order_id: str, symbol: str):
        cancel_order_request_body = {'symbol': symbol, 'orderId': order_id}
        cancel_order_response = self._request(
            'DELETE', '/orders', params=cancel_order_request_body, model=OrderEvent
        )
        return self.parse_order_info_response(cancel_order_response, '', '')

    def get_all_symbols(self) -> List[AvailableSymbol]:
        return self._request('GET', '/symbols', model=List[AvailableSymbol])

    def get_orderbook(self, symbol: str) -> OrderBookInfo:
        orderbook_request = {'symbol': symbol}
        return self._request('GET', '/orders/book', params=orderbook_request, model=OrderBookInfo)

    @check_authentication
    def get_account_info(self) -> AccountInfo:
        return self._request('GET', '/accounts', model=AccountInfo)

    @check_authentication
    def set_leverage(self, symbol: str, leverage: int) -> LeverageUpdateInfo:
        leverage_request = {'symbol': symbol, 'leverage': leverage}
        return self._request('PUT', '/accounts/leverage', data=leverage_request, model=LeverageUpdateInfo)

    def _request(self,
                 method: str,
                 path: str,
                 params: dict = None,
                 data: dict = None,
                 model: BaseModel = None
                 ) -> BaseModel:

        try:
            return self._handle_response(
                response=self.client.request(
                    method=method,
                    path=path,
                    params=params,
                    data=data
                ),
                model=model
            )
        except DexilonAuthException:

            self.authenticate()

            return self._handle_response(
                response=self.client.request(
                    method=method,
                    path=path,
                    params=params,
                    data=data
                ),
                model=model
            )

    def _handle_response(self, response: dict, model: BaseModel = None) -> BaseModel:
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
        if model:
            return parse_obj_as(model, data)
        else:
            return data

    def sign(self, nonce: str) -> str:
        return w3.eth.account.sign_message(
            encode_defunct(str.encode(nonce)), private_key=self.pk1
        ).signature.hex()

    def authenticate(self):
        payload = {'metamaskAddress': self.METAMASK_ADDRESS.lower()}
        self.client.delete_header("MetamaskAddress")
        nonce_response = self._request(
            'POST', '/auth/startAuth', data=payload, model=NonceResponse
        )

        nonce = nonce_response.nonce

        if len(nonce) == 0:
            raise DexilonAuthException(
                'nonce was not received for Authentication request'
            )

        signature_payload = {
            'metamaskAddress': self.METAMASK_ADDRESS.lower(),
            'signedNonce': self.sign(nonce)
        }

        auth_info = self._request(
            'POST', '/auth/finishAuth', data=signature_payload, model=JWTTokenResponse
        )

        jwt_token = auth_info.accessToken
        refresh_token = auth_info.refreshToken
        if jwt_token is None or len(jwt_token) == 0:
            raise DexilonAuthException(
                'Was not able to obtain JWT token for authentication'
            )

        self.client.update_headers({
            'Authorization': 'Bearer ' + jwt_token,
            'MetamaskAddress': self.METAMASK_ADDRESS.lower()
        })

        self.JWT_KEY = jwt_token
        self.REFRESH_TOKEN = refresh_token
