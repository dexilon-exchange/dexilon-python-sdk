import json
import secrets
from datetime import datetime
from typing import List
import logging
import time

import requests as requests

from cosmospy._transaction import Transaction
from cosmospy import generate_wallet, _wallet
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
    CosmosAddressMapping, LeverageEvent, CosmosFaucetResponse, DexilonAccountInfo, DexilonTransactionResponseInfo


class DexilonClientImpl(DexilonClient):
    API_URL = 'https://dex-dev2-api.cronrate.com/api/v1'
    COSMOS_ADDRESS_API_URL = 'http://88.198.205.192:1317/dexilon-exchange/dexilonl2'
    COSMOS_FAUCET_API_URL = 'http://proxy.dev.dexilon.io'
    TIME_BETWEEN_BLOCKS = 5

    DECIMALS_USDC = 6

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


    # def setup(self):
    #     self.client: SessionClient = SessionClient(self.API_URL, self.headers)
    #     self.client.base_url = self.API_URL
    #     self.dex_session_client: SessionClient = SessionClient(self.COSMOS_ADDRESS_API_URL, self.cosmos_headers)
    #     self.dex_faucet_client: SessionClient = SessionClient(self.COSMOS_FAUCET_API_URL, self.cosmos_headers)

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
        logging.debug("response: %s" % (response))
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
        logging.debug("response: %s" % (response))
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


    def get_eth_wallet_from_mnemonic(self, eth_mnemonic: []):
        Account.enable_unaudited_hdwallet_features()
        return Account.from_mnemonic(eth_mnemonic)


    def grant_permission_to_grantee_wallet(self, grantee_cosmos_wallet, granter_cosmos_address: str, eth_wallet, eth_address, dexilon_chain_id: str):
        grantee_cosmos_address = grantee_cosmos_wallet['address']
        account_info = self.get_cosmos_account_info(grantee_cosmos_address)

        cosmos_account_number = account_info.account.account_number
        cosmos_account_sequence = account_info.account.sequence

        # grant permission request. Call MsgGrantPermissionRequest to give grantee grants to control granters funds

        print("Sending Grant permission transaction to Dexilon Blockchain")

        cosmos_grant_permission_tx = Transaction(
            privkey=grantee_cosmos_wallet["private_key"],
            account_num=cosmos_account_number,
            sequence=cosmos_account_sequence,
            fee=0,
            fee_denom="dxln",
            gas=200_000,
            memo="",
            chain_id=dexilon_chain_id,
        )

        cosmos_grant_permission_tx_data = {}

        cur_time_in_milliseconds = int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds() * 1000)
        nonce = str(cur_time_in_milliseconds) + '#' + grantee_cosmos_address
        signature = self.getSignature(eth_wallet, nonce)

        cosmos_grant_permission_tx_data["creator"] = grantee_cosmos_address
        cosmos_grant_permission_tx_data["granter_eth_address"] = eth_address
        cosmos_grant_permission_tx_data["signature"] = signature
        cosmos_grant_permission_tx_data["signedMessage"] = nonce
        cosmos_grant_permission_tx_data["expirationTime"] = 15 * 60

        cosmos_grant_permission_tx.add_grant_permission(**cosmos_grant_permission_tx_data)
        cosmos_grant_permission_tx_bytes = cosmos_grant_permission_tx.get_tx_bytes()

        json_request_body = {'tx_bytes': cosmos_grant_permission_tx_bytes, "mode": "BROADCAST_MODE_BLOCK"}
        cosmos_faucet_response = self._request_dexilon_faucet('POST', '/cosmos/tx/v1beta1/txs', data=json_request_body,
                                                              model=DexilonTransactionResponseInfo)

        if cosmos_faucet_response.tx_response.code is not 0:
            print("Error while sending transaction for grant permission. Granter wallet: " + granter_cosmos_address)
            raise DexilonRequestException(
                "Error while sending transaction for grant permission. Granter wallet: " + granter_cosmos_address)

        print("Transaction for grant permission is successfull. Granter Dexilon wallet: " + grantee_cosmos_wallet[
            'address'] + "; Eth address: " + eth_address)

    def rpc_connect(self):
        # TODO: add Dexilon node here
        rpc_list = [
            "https://polygon-mumbai.g.alchemy.com/v2/YSB9dpzl-6DQcXynxssJXUHJQIAvIk5r",
            "https://rpc-mumbai.matic.today",
            "https://matic-mainnet.chainstacklabs.com",
            "https://rpc-mumbai.maticvigil.com",
        ]

        for rpc in rpc_list:
            w3 = Web3(Web3.HTTPProvider(rpc))
            if w3.isConnected():
                return w3

    def deposit_funds_to_contract(self, eth_wallet, amount: int):

        with open("../blockchain_abi/bridge_v10_abi.json", "r") as f:
            bridge_abi = json.load(f)

        w3 = self.rpc_connect()

        user_address = eth_wallet.address

        userAddress = Web3.toChecksumAddress(user_address)
        token_address = Web3.toChecksumAddress("0x8f54629e7d660871abab8a6b4809a839ded396de")
        final_amount = int(
            int(1_000_000 * float(amount)) * 10 ** self.DECIMALS_USDC / 1_000_000
        )
        timestamp = int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds() * 1000)

        approve_transaction_result = self.run_approve_transaction(userAddress, final_amount, eth_wallet, w3)

        if isinstance(approve_transaction_result, tuple) is False or (len(approve_transaction_result) != 2 and approve_transaction_result[1] != 200):
            raise Exception("Approve transaction was not run correctly")

        deposit_contract = w3.eth.contract(
            address="0x52039E2f8263cE47afdBBB3E5124F22Fc87F557E", abi=bridge_abi
        )

        try:
            nonce = w3.eth.getTransactionCount(userAddress)
            tx = deposit_contract.functions.deposit(token_address, amount).buildTransaction(
                {
                    # "address": w3.eth.getTransactionCount(userAddress),
                    "nonce": nonce,
                    "from": userAddress,
                    "gasPrice": self.get_gas_price(),
                    "gas": 200_000,
                }
            )

            tx_response = self.sign_and_post_transaction(tx, "Deposit", eth_wallet, w3)
            return tx_response

        except Exception as web3_error:
            return repr(web3_error), 400


    def run_approve_transaction(self, address: str, amount: int, eth_wallet, w3):
        with open("../blockchain_abi/usdt_abi.json", "r") as f:
            usdt_abi = json.load(f)

        usdt_contract = w3.eth.contract(
            address=Web3.toChecksumAddress("0x8f54629e7d660871abab8a6b4809a839ded396de"), abi=usdt_abi
        )

        try:
            nonce = w3.eth.getTransactionCount(address)
            tx = usdt_contract.functions.approve(address, amount).buildTransaction(
                {
                    "nonce": nonce,
                    "from": address,
                    "gasPrice": self.get_gas_price(),
                    "gas": 200_000,
                }
            )

            return self.sign_and_post_transaction(tx, "approve", eth_wallet, w3)

        except Exception as web3_error:
            return repr(web3_error), 400


    def sign_and_post_transaction(self, tx, tx_type, eth_wallet, w3):
        retries = 10
        delay = self.get_block_time() / retries
        try:
            # retrying only sendRawTransaction request to JSON-RPC server
            for i in range(retries):
                try:
                    signed_tx = w3.eth.account.sign_transaction(tx, private_key=eth_wallet.privateKey)
                    sent_tx = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                    break
                except Exception as e:
                    if i < retries - 1:
                        time.sleep(delay)
                        tx["nonce"] += 1
                        delay += i + 1
                        continue
                    else:
                        raise

            # wait for it to return receipt
            time.sleep(self.get_block_time())  # it cannot be faster than 2 seconds
            tx_receipt = w3.eth.wait_for_transaction_receipt(sent_tx)
            tx_link = (
                    "https://mumbai.polygonscan.com/tx/"
                    + tx_receipt.get("transactionHash").hex()
            )

        except Exception as web3_error:
            return repr(web3_error), 400

        if tx_receipt.get("status") == True:
            return tx_link, 200

        elif tx_receipt.get("status") == False:
            # Failed

            fail_reason = "unknown"
            try:
                # replay the transaction locally:
                # build a new transaction to replay:
                # fetch a reverted transaction:
                tx = w3.eth.get_transaction(tx_receipt.get("transactionHash"))
                replay_tx = {
                    "to": tx["to"],
                    "from": tx["from"],
                    "value": tx["value"],
                    "data": tx["input"],
                }
                w3.eth.call(replay_tx, tx.blockNumber - 1)
            except Exception as e:
                fail_reason = repr(e)

            return f"{tx_type} failed. Reason: {fail_reason}. Link: {tx_link}", 400

        else:
            # Failed miserably
            return "Trade failed.", 400


    def get_gas_price(priority="fast"):
        """Get standart gas price for the testnet"""
        try:
            # gas_price = int(w3.eth.gas_price * 15 / 10)
            gas_price = w3.eth.gas_price
        except:
            gas_price = w3.toWei(10, "gwei")
            print("RPC failed to provide gas price!")

        return gas_price

    def get_block_time(self):
        """Get current block time"""
        gas_station = "https://gasstation-mumbai.matic.today/v2"
        block_time = self.TIME_BETWEEN_BLOCKS
        try:
            block_time = requests.get(gas_station).json()["blockTime"]
        except Exception as e:
            print("Polygon gas station is not working!")
        return int(block_time)


    def depositFundsToCosmosWallet(self, eth_mnemonic: [], asset: str, amount: int, eth_chain_id: int, dexilon_chain_id: str):
        eth_wallet = self.get_eth_wallet_from_mnemonic(eth_mnemonic)
        eth_address = eth_wallet.address

        deposit_funds_to_contract_response = self.deposit_funds_to_contract(eth_wallet, amount)


        granter_cosmos_address = self.get_cosmos_address_mapping(eth_address)
        grantee_cosmos_wallet = generate_wallet()
        grantee_cosmos_address = grantee_cosmos_wallet['address']

        self.call_cosmos_faucet(grantee_cosmos_address)

        self.grant_permission_to_grantee_wallet(grantee_cosmos_wallet, granter_cosmos_address.addressMapping, eth_wallet, eth_address, dexilon_chain_id)

        account_info = self.get_cosmos_account_info(grantee_cosmos_address)

        cosmos_account_number = account_info.account.account_number
        cosmos_account_sequence = account_info.account.sequence

        # using given grant create deposit trading transaction wrapped to AuthZ module(authz_exec)

        cosmo_tx = Transaction(
            privkey=grantee_cosmos_wallet["private_key"],
            account_num=cosmos_account_number,
            sequence=cosmos_account_sequence,
            fee=0,
            fee_denom="dxln",
            gas=200_000,
            memo="",
            chain_id=dexilon_chain_id,
        )

        cosmos_tx_data = {}
        cosmos_tx_data["recipient"] = granter_cosmos_address.addressMapping.cosmosAddress
        cosmos_tx_data["balance"] = str(amount)
        cosmos_tx_data["denom"] = asset

        message_any = cosmo_tx.add_deposit_tx(**cosmos_tx_data)

        # tx_bytes = cosmo_tx.get_tx_bytes()

        print("Sending transaction for deposit to trading account")

        self.send_auth_trasaction(message_any, grantee_cosmos_address, grantee_cosmos_wallet, dexilon_chain_id, granter_cosmos_address.addressMapping.cosmosAddress, eth_address)


    def send_auth_trasaction(self, message, grantee_cosmos_address: str, grantee_cosmos_wallet, dexilon_chain_id: str, granter_cosmos_address: str, eth_address: str):
        account_info = self.get_cosmos_account_info(grantee_cosmos_address)

        cosmos_account_number = account_info.account.account_number
        cosmos_account_sequence = account_info.account.sequence

        cosmos_auth_tx = Transaction(
            privkey=grantee_cosmos_wallet["private_key"],
            account_num=cosmos_account_number,
            sequence=cosmos_account_sequence,
            fee=0,
            fee_denom="dxln",
            gas=200_000,
            memo="",
            chain_id=dexilon_chain_id,
        )

        cosmos_auth_tx_data = {}
        cosmos_auth_tx_data["grantee"] = grantee_cosmos_address
        cosmos_auth_tx_data["message"] = message

        cosmos_auth_tx.add_auth_tx(**cosmos_auth_tx_data)

        cosmos_auth_tx_bytes = cosmos_auth_tx.get_tx_bytes()

        json_request_body = {'tx_bytes': cosmos_auth_tx_bytes, "mode": "BROADCAST_MODE_BLOCK"}
        cosmos_faucet_response = self._request_dexilon_faucet('POST', '/cosmos/tx/v1beta1/txs', data=json_request_body,
                                                              model=DexilonTransactionResponseInfo)

        if cosmos_faucet_response.tx_response.code is not 0:
            print("Error while sending request for registration to Dexilon network for " + granter_cosmos_address)
            raise DexilonRequestException(
                "Error trying to register new user in Dexilon network: " + granter_cosmos_address)

        print(
            "Cosmos Account " + granter_cosmos_address + " associated with ETH account " + eth_address + " was deposited successfully")


    def withdraw_funds(self, eth_mnemonic: [], amount: int, asset: str, eth_chain_id: int, dexilon_chain_id: str,):
        eth_wallet = self.get_eth_wallet_from_mnemonic(eth_mnemonic)
        eth_address = eth_wallet.address

        granter_cosmos_address = self.get_cosmos_address_mapping(eth_address)
        grantee_cosmos_wallet = generate_wallet()
        grantee_cosmos_address = grantee_cosmos_wallet['address']

        self.call_cosmos_faucet(grantee_cosmos_address)

        self.grant_permission_to_grantee_wallet(grantee_cosmos_wallet, granter_cosmos_address.addressMapping,
                                                eth_wallet, eth_address, dexilon_chain_id)

        account_info = self.get_cosmos_account_info(grantee_cosmos_address)

        cosmos_account_number = account_info.account.account_number
        cosmos_account_sequence = account_info.account.sequence

        cosmos_auth_tx = Transaction(
            privkey=grantee_cosmos_wallet["private_key"],
            account_num=cosmos_account_number,
            sequence=cosmos_account_sequence,
            fee=0,
            fee_denom="dxln",
            gas=200_000,
            memo="",
            chain_id=dexilon_chain_id,
        )

        cosmos_withdraw_tx_data = {}

        cosmos_withdraw_tx_data["granter"] = granter_cosmos_address
        cosmos_withdraw_tx_data["amount"] = amount
        cosmos_withdraw_tx_data["eth_chain_id"] = eth_chain_id
        cosmos_withdraw_tx_data["denom"] = asset

        message_any = cosmos_auth_tx.add_withdraw_tx(**cosmos_withdraw_tx_data)

        self.send_auth_trasaction(message_any, grantee_cosmos_address, grantee_cosmos_wallet, dexilon_chain_id,
                                  granter_cosmos_address.addressMapping.cosmosAddress, eth_address)





    def callCosmosFaucetForAddress(self, cosmos_address: str):
        cosmos_faucet_response = self.call_cosmos_faucet(cosmos_address)

        if not isinstance(cosmos_faucet_response, CosmosFaucetResponse):
            raise DexilonRequestException('Was not able to receive response from faucet')


    def registerUserWithExistingMnemonics(self, cosmos_mnemonic:[], eth_mnemonic:[], eth_chain_id: int, dexilon_chain_id: str):
        cosmos_wallet = self.generate_cosmos_wallet_from_mnemonic(cosmos_mnemonic)
        Account.enable_unaudited_hdwallet_features()
        eth_wallet = Account.from_mnemonic(eth_mnemonic)

        return self.generate_new_cosmos_user(cosmos_wallet, eth_wallet, eth_chain_id, dexilon_chain_id)


    def registerNewRandomUser(self, eth_chain_id: int, dexilon_chain_id: str):
        cosmos_wallet = generate_wallet()
        if 'address' not in cosmos_wallet:
            raise DexilonRequestException('Was not able to generate Cosmos wallet')
        eth_wallet = self.generate_random_eth_wallet()

        return self.generate_new_cosmos_user(cosmos_wallet, eth_wallet, eth_chain_id, dexilon_chain_id)


    def generate_new_cosmos_user(self, cosmos_wallet, eth_wallet, eth_chain_id: int, dexilon_chain_id: str):
        cosmos_address = cosmos_wallet['address']
        self.call_cosmos_faucet(cosmos_address)

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
            gas=200_000,
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
        cosmos_faucet_response = self._request_dexilon_faucet('POST', '/cosmos/tx/v1beta1/txs', data=json_request_body,
                                                              model=DexilonTransactionResponseInfo)

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


    def getSignature(self, eth_wallet, message_to_sign: str):
        solidity_keccak256_hash = Web3.solidityKeccak(['string'], [message_to_sign])
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

    def generate_cosmos_wallet_from_mnemonic(self, cosmos_mnemonic):
        cosmos_private_key = _wallet.seed_to_privkey(cosmos_mnemonic)
        cosmos_public_key = _wallet.privkey_to_pubkey(cosmos_private_key)
        cosmos_address = _wallet.privkey_to_address(cosmos_private_key)
        return {
            "seed": cosmos_mnemonic,
            "derivation_path": _wallet.DEFAULT_DERIVATION_PATH,
            "private_key": cosmos_private_key,
            "public_key": cosmos_public_key,
            "address": cosmos_address,
        }

    def generate_random_eth_wallet(self):
        priv = secrets.token_hex(32)
        private_key = '0x' + priv
        acct = Account.from_key(private_key)
        return acct


