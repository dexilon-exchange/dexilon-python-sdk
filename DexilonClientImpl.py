import secrets
from datetime import datetime, time
from typing import List

import requests as requests

from _transaction import Transaction
from cosmospy import generate_wallet
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_keys import keys
from pydantic import BaseModel, parse_obj_as
from web3 import Web3
from web3.auto import w3

from DexilonClient import DexilonClient
from ErrorBody import ErrorBody
from OrderErrorInfo import OrderErrorInfo
from SessionClient import SessionClient
from exceptions import DexilonAPIException, DexilonRequestException, DexilonAuthException
from responses import AvailableSymbol, OrderBookInfo, JWTTokenResponse, OrderEvent, \
    ErrorBody, AccountInfo, OrderInfo, AllOpenOrders, \
    CosmosAddressMapping, LeverageEvent, CosmosFaucetResponse, DexilonAccountInfo, DexilonRegistrationTransactionInfo


class DexilonClientImpl(DexilonClient):
    API_URL = 'https://dex-dev2-api.cronrate.com/api/v1'
    COSMOS_ADDRESS_API_URL = 'http://88.198.205.192:1317/dexilon-exchange/dexilonl2'
    COSMOS_FAUCET_API_URL = 'http://proxy.dev.dexilon.io'

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
        self.client: SessionClient = SessionClient(self.API_URL, self.headers)
        self.dex_session_client: SessionClient = SessionClient(self.COSMOS_ADDRESS_API_URL, self.cosmos_headers)
        self.dex_faucet_client: SessionClient = SessionClient(self.COSMOS_FAUCET_API_URL, self.cosmos_headers)

    def change_api_url(self, api_url):
        """
        Used for testing purposes

        :param api_url: Public
        :type api_url: str.

        """

        self.API_URL = api_url
        self.client.base_url = api_url

    def change_cosmos_api_url(self, cosmos_api_url):
        """
        Used for testing purposes
        :param cosmos_api_url:
        :return:
        """
        self.COSMOS_ADDRESS_API_URL = cosmos_api_url
        self.dex_session_client.base_url = cosmos_api_url


    def change_cosmos_faucet_api_url(self, cosmos_faucet_api_url):
        self.COSMOS_FAUCET_API_URL = cosmos_faucet_api_url
        self.dex_faucet_client.base_url = cosmos_faucet_api_url


    def get_open_orders(self) -> List[OrderInfo]:
        self.check_authentication()
        # all_orders_request = {'symbol': symbol, 'type': order_type, 'side': order_side}

        all_open_orders_response = self._request('GET', '/orders/open', model=AllOpenOrders)
        if isinstance(all_open_orders_response, AllOpenOrders):
            return all_open_orders_response.content
        return all_open_orders_response

    def get_order_info(self, order_id: str, client_order_id: str, symbol: str) -> OrderEvent:
        self.check_authentication()
        get_order_info_request_params = {'symbol': symbol, 'orderId': order_id}
        return self._request('GET', '/orders', params=get_order_info_request_params, model=OrderEvent)

    def market_order(self, client_order_id: str, symbol: str, side: str, size: float):
        self.check_authentication()
        json_request_body = {'clientOrderId': client_order_id, 'symbol': symbol, 'side': side, 'size': size}
        order_response = self._request('POST', '/orders/market', data=json_request_body, model=OrderEvent)
        return self.parse_order_info_response(order_response, client_order_id)

    def parse_order_info_response(self, order_info_response, client_order_id):
        if isinstance(order_info_response, ErrorBody):
            return OrderErrorInfo(client_order_id, '', order_info_response.name,
                                  ';'.join(order_info_response.details))
        return order_info_response

    def parse_value_or_return_None(self, object_to_parse, param_name):
        if param_name in object_to_parse:
            return object_to_parse[param_name]
        else:
            return None

    def limit_order(self, client_order_id: str, symbol: str, side: str, price: float, size: float):
        self.check_authentication()
        json_request_body = {'clientOrderId': client_order_id, 'symbol': symbol, 'side': side, 'size': size,
                             'price': price}
        limit_order_response = self._request('POST', '/orders/limit', data=json_request_body, model=OrderEvent)
        return self.parse_order_info_response(limit_order_response, client_order_id)

    def cancel_all_orders(self) -> bool:
        self.check_authentication()
        cancel_all_orders_response = self._request('DELETE', '/orders/all', model=List[OrderEvent])
        return isinstance(cancel_all_orders_response, list)

    def cancel_order(self, order_id: int, symbol: str):
        self.check_authentication()
        cancel_order_request_body = {'symbol': symbol, 'orderId': order_id}
        cancel_order_response = self._request('DELETE', '/orders', params=cancel_order_request_body, model=OrderEvent)
        return self.parse_order_info_response(cancel_order_response, '')

    def get_all_symbols(self) -> List[AvailableSymbol]:
        return self._request('GET', '/symbols', model=List[AvailableSymbol])

    def get_orderbook(self, symbol: str) -> OrderBookInfo:
        orderbook_request = {'symbol': symbol}
        return self._request('GET', '/orders/book', params=orderbook_request, model=OrderBookInfo)

    def get_account_info(self, ) -> AccountInfo:
        self.check_authentication()
        return self._request('GET', '/accounts', model=AccountInfo)

    def set_leverage(self, symbol: str, leverage: int) -> LeverageEvent:
        self.check_authentication()
        leverage_request = {'symbol': symbol, 'leverage': leverage}
        return self._request('PUT', '/accounts/leverage', data=leverage_request, model=LeverageEvent)

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

    def _request_dexilon_faucet(self, method:str, path: str, params: dict = None, data: dict = None, model: BaseModel = None) -> BaseModel:
        return self._handle_dexilon_response(
            response=self.dex_faucet_client.request(
                method=method,
                path=path,
                params=params,
                data=data
            ),
            model=model
        )

    def _handle_dexilon_response(self, response: dict, model: BaseModel = None) -> BaseModel:
        if response is None:
            service_response = parse_obj_as(ErrorBody, response)
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
        # data: dict = response['body']
        # data: dict = response
        if response is None:
            service_response = parse_obj_as(ErrorBody, response)
            return service_response
        if 'code' in response:
            service_response = parse_obj_as(ErrorBody, response)
            return service_response
        if model:
            return parse_obj_as(model, response)
        else:
            return response

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

    def check_authentication(self):
        if len(self.JWT_KEY) == 0:
            self.authenticate()

    def sign(self, nonce: str) -> str:
        return w3.eth.account.sign_message(
            encode_defunct(nonce), private_key=self.pk1
        ).signature.hex()

    def get_cosmos_address_mapping(self, eth_address: str):
        cosmos_maping_response = self._request_dexilon_api('GET', '/registration/address_mapping/mirror/' + eth_address,
                                                           model=CosmosAddressMapping)
        return cosmos_maping_response

    def call_cosmos_faucet(self, cosmos_address: str):
        json_request_body = {'address': cosmos_address}
        cosmos_faucet_response = self._request_dexilon_faucet('POST', '/faucet', data=json_request_body, model=CosmosFaucetResponse)
        return cosmos_faucet_response

    def hash_keccak(self, message: str):
        return Web3.solidityKeccak(['string'], [message])

    def authenticate(self):

        dexilon_address = self.get_cosmos_address_mapping(self.METAMASK_ADDRESS)
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


    def registerNewUser(self, eth_chain_id: int, dexilon_chain_id: str):
        cosmos_wallet = self.generate_random_cosmos_wallet()
        if 'address' not in cosmos_wallet:
            raise DexilonRequestException('Was not able to generate Cosmos wallet')
        cosmos_address = cosmos_wallet['address']
        cosmos_faucet_response = self.call_cosmos_faucet(cosmos_address)

        if not isinstance(cosmos_faucet_response, CosmosFaucetResponse):
            raise DexilonRequestException('Was not able to receive response from faucet')

        eth_wallet = self.generate_random_eth_wallet()
        eth_address = eth_wallet.address

        signature = self.getSignature(eth_wallet, cosmos_address)

        account_info = self.get_cosmos_account_info(cosmos_address)

        cosmos_account_number = account_info.account.account_number
        cosmos_account_sequence = account_info.account.sequence

        cosmo_tx = Transaction(
            privkey=cosmos_wallet["private_key"],
            account_num=cosmos_account_number,
            sequence=cosmos_account_sequence,
            fee=0,
            fee_denom="dxln",
            gas= 200_000,
            memo="",
            chain_id=dexilon_chain_id,
        )

        cosmos_tx_data = {}
        cosmos_tx_data["creator"] = cosmos_address
        cosmos_tx_data["chainId"] = eth_chain_id
        cosmos_tx_data["address"] = eth_address
        cosmos_tx_data["signature"] = signature
        cosmos_tx_data["signedMessage"] = cosmos_address

        cosmo_tx.add_registration(**cosmos_tx_data)

        tx_bytes = cosmo_tx.get_tx_bytes()

        json_request_body = {'tx_bytes': tx_bytes, "mode": "BROADCAST_MODE_BLOCK"}
        cosmos_faucet_response = self._request_dexilon_faucet('POST', '/cosmos/tx/v1beta1/txs', data=json_request_body, model=DexilonRegistrationTransactionInfo)

        if cosmos_faucet_response.tx_response.code is not 0:
            print("Error while sending request for registration to Dexilon network for " + cosmos_address)
            raise DexilonRequestException("Error trying to register new user in Dexilon network: " + cosmos_address)

        print("Dexilon user " + cosmos_address + " successfully registered")

        return {
            'cosmosAddress': cosmos_address,
            'cosmosMnemonic': cosmos_wallet["seed"],
            'cosmosPrivateKey': cosmos_wallet["private_key"],
            'cosmosPublicKey': cosmos_wallet["public_key"],
            'ethAddress': eth_wallet.address,
            'ethPrivateKey': eth_wallet.privateKey.hex(),
            'ethPublicKey': eth_wallet.key.hex()
        }

    def get_cosmos_account_info(self, cosmos_address: str) -> DexilonAccountInfo:
        return self._request_dexilon_faucet('GET', '/cosmos/auth/v1beta1/accounts/' + cosmos_address, model=DexilonAccountInfo)

    def updateAccountInfo(self):
        api_url = self.cosmos_url + "/cosmos/auth/v1beta1/accounts/"
        for i in range(self.NUMBER_OF_RETRIES):
            try:
                self.account_info = httpx.get(
                    api_url + self.account_address, timeout=10.0
                ).json()
                break
            except Exception as e:
                print(f"Error Cosmos connect: {repr(e)}")
                time.sleep(1 + i)
                print(f"Retry Cosmos connect, attempt {i + 1}")


    def wrapObject(self, value):
        return {
            'typeUrl': '/dexilon_exchange.dexilonL2.registration.MsgCreateAddressMapping',
            'value': {
                'messages': [
                    {
                        'typeUrl': '/dexilon_exchange.dexilonL2.registration.MsgCreateAddressMapping',
                        'value' : value
                    }
                ]
            }
        }


    def getSignature(self, eth_wallet, cosmos_address: str):
        solidity_keccak256_hash = Web3.solidityKeccak(['string'], [cosmos_address])
        return w3.eth.account.sign_message(encode_defunct(solidity_keccak256_hash), private_key=eth_wallet.privateKey).signature.hex()


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

    def generate_random_cosmos_wallet(self):
        wallet = generate_wallet()
        return wallet

    def generate_random_eth_wallet(self):
        priv = secrets.token_hex(32)
        private_key = '0x' + priv
        acct = Account.from_key(private_key)
        return acct
