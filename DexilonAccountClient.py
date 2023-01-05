import json

import requests
from web3 import Web3
from web3.auto import w3
from eth_account.messages import encode_defunct

from DexilonClientImpl import DexilonClientImpl
from cosmospy import generate_wallet, _wallet
from exceptions import DexilonRequestException
from cosmospy._transaction import Transaction
from eth_account import Account
from pydantic import BaseModel, parse_obj_as
import logging
from ErrorBody import ErrorBody
from SessionClient import SessionClient
from datetime import datetime
import time

import secrets

from responses import CosmosFaucetResponse, DexilonTransactionResponseInfo, DexilonAccountInfo, CosmosAddressMapping, \
    FundsTransferResponse


class DexilonAccountClient:
    API_URL = 'https://dex-dev2-api.cronrate.com/api/v1'
    COSMOS_ADDRESS_API_URL = 'http://88.198.205.192:1317/dexilon-exchange/dexilonl2'
    COSMOS_FAUCET_API_URL = 'http://proxy.dev.dexilon.io'

    TIME_BETWEEN_BLOCKS = 5
    BRIDGE_CONTRACT_ADDRESS = '0x1f4878d95d26C050D854D187De9d8FD4A8A3eE47'
    TOKEN_ADDRESS = "0x8f54629e7d660871abab8a6b4809a839ded396de"

    DECIMALS_USDC = 6

    NUMBER_OF_RETRIES_WAITING_FOR_FUNDS_AT_CONTRACT = 10
    DELAY_BETWEEN_RETRIES_WAITING_FOR_FUNDS_AT_CONTRACT = 10

    cosmos_headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    def __init__(self):
        self.dex_session_client: SessionClient = SessionClient(self.COSMOS_ADDRESS_API_URL, self.cosmos_headers)
        self.dex_faucet_client: SessionClient = SessionClient(self.COSMOS_FAUCET_API_URL, self.cosmos_headers)


    def change_api_url(self, api_url):
        """
        Used for testing purposes

        :param api_url: Public
        :type api_url: str.

        """
        self.API_URL = api_url

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


    def getSignature(self, eth_wallet, message_to_sign: str):
        solidity_keccak256_hash = Web3.solidityKeccak(['string'], [message_to_sign])
        return w3.eth.account.sign_message(encode_defunct(solidity_keccak256_hash), private_key=eth_wallet.privateKey).signature.hex()


    def call_cosmos_faucet(self, cosmos_address: str):
        json_request_body = {'address': cosmos_address}
        cosmos_faucet_response = self._request_dexilon_faucet('POST', '/faucet', data=json_request_body, model=CosmosFaucetResponse)
        return cosmos_faucet_response


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

    def _request_dexilon_faucet(self, method: str, path: str, params: dict = None, data: dict = None, model: BaseModel = None) -> BaseModel:
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

    def get_cosmos_address_mapping(self, eth_address: str):
        cosmos_maping_response = self._request_dexilon_api('GET', '/registration/address_mapping/mirror/' + eth_address, model=CosmosAddressMapping)
        return cosmos_maping_response

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


    def get_cosmos_account_info(self, cosmos_address: str) -> DexilonAccountInfo:
        return self._request_dexilon_faucet('GET', '/cosmos/auth/v1beta1/accounts/' + cosmos_address, model=DexilonAccountInfo)


    def generate_random_eth_wallet(self):
        priv = secrets.token_hex(32)
        private_key = '0x' + priv
        acct = Account.from_key(private_key)
        return acct


    def rpc_connect(self):
        # TODO: add Dexilon node here
        rpc_list = [
            "https://polygon-mumbai.g.alchemy.com/v2/fjT6Ftkwr6805C0Guo_eicthIqtL1Yev",
            "https://rpc-mumbai.matic.today",
            "https://matic-mainnet.chainstacklabs.com",
            "https://rpc-mumbai.maticvigil.com",
        ]

        for rpc in rpc_list:
            w3 = Web3(Web3.HTTPProvider(rpc))
            if w3.isConnected():
                return w3

    def verify_contract_response_is_success(self, response):
        return isinstance(response, tuple) is True and len(response) == 2 and response[1] == 200


    def get_eth_wallet_from_mnemonic(self, eth_mnemonic: []):
        Account.enable_unaudited_hdwallet_features()
        return Account.from_mnemonic(eth_mnemonic)

    def grant_permission_to_grantee_wallet(self, grantee_cosmos_wallet, granter_cosmos_address: str, eth_wallet,
                                           eth_address, dexilon_chain_id: str):
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

    def deposit_funds_to_contract(self, eth_wallet, amount: int):

        with open("../blockchain_abi/bridge_v10_abi.json", "r") as f:
            bridge_abi = json.load(f)

        w3 = self.rpc_connect()

        user_address = eth_wallet.address

        userAddress = Web3.toChecksumAddress(user_address)

        approve_transaction_result = self.run_approve_transaction(userAddress, amount, eth_wallet, w3)

        if not self.verify_contract_response_is_success(approve_transaction_result):
            raise Exception("Approve transaction was not run correctly")

        deposit_contract = w3.eth.contract(
            address=self.BRIDGE_CONTRACT_ADDRESS, abi=bridge_abi
        )

        try:
            nonce = w3.eth.getTransactionCount(userAddress)
            tx = deposit_contract.functions.deposit(Web3.toChecksumAddress(self.TOKEN_ADDRESS),
                                                    amount).buildTransaction(
                {
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
            address=Web3.toChecksumAddress(self.TOKEN_ADDRESS), abi=usdt_abi
        )

        try:
            nonce = w3.eth.getTransactionCount(address)
            checksum_address = Web3.toChecksumAddress(address)
            tx = usdt_contract.functions.approve(Web3.toChecksumAddress(self.BRIDGE_CONTRACT_ADDRESS),
                                                 amount).buildTransaction(
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

    def get_final_eth_amount(self, amount: int):
        return int(
            int(1_000_000 * float(amount)) * 10 ** self.DECIMALS_USDC / 1_000_000
        )

    def get_final_cosmos_amount(self, amount: int) -> str:
        return str(amount) + '000000000000000000'

    def depositFundsToCosmosWallet(self, eth_mnemonic: [], asset: str, amount: int, eth_chain_id: int,
                                   dexilon_chain_id: str):
        eth_wallet = self.get_eth_wallet_from_mnemonic(eth_mnemonic)
        eth_address = eth_wallet.address

        final_amount = self.get_final_eth_amount(amount)

        deposit_funds_to_contract_response = self.deposit_funds_to_contract(eth_wallet, final_amount)

        time.sleep(10)

        granter_cosmos_address = self.get_cosmos_address_mapping(eth_address)
        grantee_cosmos_wallet = generate_wallet()
        grantee_cosmos_address = grantee_cosmos_wallet['address']

        self.call_cosmos_faucet(grantee_cosmos_address)

        self.grant_permission_to_grantee_wallet(grantee_cosmos_wallet, granter_cosmos_address.addressMapping,
                                                eth_wallet, eth_address, dexilon_chain_id)

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

        final_cosmos_amount = self.get_final_cosmos_amount(amount)

        cosmos_tx_data = {}
        cosmos_tx_data["accountAddress"] = granter_cosmos_address.addressMapping.cosmosAddress
        cosmos_tx_data["balance"] = final_cosmos_amount
        cosmos_tx_data["denom"] = asset

        message_any = cosmo_tx.add_deposit_tx(**cosmos_tx_data)

        # tx_bytes = cosmo_tx.get_tx_bytes()

        print("Sending transaction for deposit to trading account")

        self.send_auth_trasaction(message_any, grantee_cosmos_address, grantee_cosmos_wallet, dexilon_chain_id,
                                  granter_cosmos_address.addressMapping.cosmosAddress, eth_address)

    def send_auth_trasaction(self, message, grantee_cosmos_address: str, grantee_cosmos_wallet, dexilon_chain_id: str,
                             granter_cosmos_address: str, eth_address: str):
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
            print("Error while sending authorization request to Dexilon network for " + granter_cosmos_address)
            raise DexilonRequestException(
                "Error trying to authorize transaction in Dexilon network: " + granter_cosmos_address)

        print(
            "Cosmos Account " + granter_cosmos_address + " associated with ETH account " + eth_address + " was deposited successfully")
        return True

    def withdraw_funds(self, eth_mnemonic: [], amount: int, asset: str, eth_chain_id: int, dexilon_chain_id: str, ):
        eth_wallet = self.get_eth_wallet_from_mnemonic(eth_mnemonic)
        eth_address = eth_wallet.address

        dexilon_client = DexilonClientImpl(eth_address, eth_wallet.privateKey.hex()[2:])
        dexilon_client.change_api_url(self.API_URL)
        dexilon_client.change_dexilon_account_api_url(self.COSMOS_ADDRESS_API_URL)

        transfer_funds_response = dexilon_client.transfer_funds_from_trading_to_spot(amount, asset)

        if not isinstance(transfer_funds_response, FundsTransferResponse) or transfer_funds_response.amount is not amount:
            raise DexilonRequestException("Was not able to transfer funds from Trading wallet to Spot")

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

        final_cosmos_amount = self.get_final_cosmos_amount(amount)
        final_eth_amount = self.get_final_eth_amount(amount)

        cosmos_withdraw_tx_data["granter"] = granter_cosmos_address.addressMapping.cosmosAddress
        cosmos_withdraw_tx_data["amount"] = final_cosmos_amount
        cosmos_withdraw_tx_data["eth_chain_id"] = eth_chain_id
        cosmos_withdraw_tx_data["denom"] = asset

        message_any = cosmos_auth_tx.add_withdraw_tx(**cosmos_withdraw_tx_data)

        self.send_auth_trasaction(message_any, grantee_cosmos_address, grantee_cosmos_wallet, dexilon_chain_id,
                                  granter_cosmos_address.addressMapping.cosmosAddress, eth_address)

        return self.check_money_arrived_to_contract_and_withdraw(eth_wallet, final_eth_amount)

    def check_money_arrived_to_contract_and_withdraw(self, eth_wallet, eth_amount: int):
        with open("../blockchain_abi/bridge_v10_abi.json", "r") as f:
            bridge_abi = json.load(f)

        w3 = self.rpc_connect()

        user_address = eth_wallet.address

        userAddress = Web3.toChecksumAddress(user_address)

        bridge_contract = w3.eth.contract(
            address=self.BRIDGE_CONTRACT_ADDRESS, abi=bridge_abi
        )

        self.wait_for_funds_arrive_to_contract(eth_amount, bridge_contract, userAddress)

        try:
            nonce = w3.eth.getTransactionCount(userAddress)
            tx = bridge_contract.functions.withdraw(Web3.toChecksumAddress(self.TOKEN_ADDRESS)).buildTransaction(
                {
                    "nonce": nonce,
                    "from": userAddress,
                    "gasPrice": self.get_gas_price(),
                    "gas": 200_000,
                }
            )

            tx_response = self.sign_and_post_transaction(tx, "withdraw", eth_wallet, w3)

            if not self.verify_contract_response_is_success(tx_response):
                print("Error while trying to withdraw funds from the Contract to user's wallet:  " + eth_wallet.address)
                return False

            print("Funds were successfully withdrawn to user's wallet: " + eth_wallet.address)
            return True

        except Exception as web3_error:
            return repr(web3_error), 400

    def wait_for_funds_arrive_to_contract(self, amount, bridge_contract, userAddress):
        current_try: int = 0
        try:
            while current_try <= self.NUMBER_OF_RETRIES_WAITING_FOR_FUNDS_AT_CONTRACT:
                print("Checking for balance changed at the contract for user. Try " + str(current_try + 1))
                current_contract_balance = bridge_contract.functions.getAvailableBalance(
                    Web3.toChecksumAddress(self.TOKEN_ADDRESS), userAddress).call()

                if current_contract_balance >= amount:
                    print("Amount has changed and funds ready for withdraw: " + str(current_contract_balance))
                    return True

                print("Funds at contract has not been changed yet. Sleeping for " + str(
                    self.DELAY_BETWEEN_RETRIES_WAITING_FOR_FUNDS_AT_CONTRACT) + " seconds to retry")
                time.sleep(self.DELAY_BETWEEN_RETRIES_WAITING_FOR_FUNDS_AT_CONTRACT)
                current_try = current_try + 1

        except Exception as web3_error:
            return repr(web3_error), 400

        raise Exception(
            "Contract amount has not been changed for the transaction within await time limit. Can not proceed with withdraw")

    def callCosmosFaucetForAddress(self, cosmos_address: str):
        cosmos_faucet_response = self.call_cosmos_faucet(cosmos_address)

        if not isinstance(cosmos_faucet_response, CosmosFaucetResponse):
            raise DexilonRequestException('Was not able to receive response from faucet')

    def registerUserWithExistingMnemonics(self, cosmos_mnemonic: [], eth_mnemonic: [], eth_chain_id: int,
                                          dexilon_chain_id: str):
        cosmos_wallet = self.generate_cosmos_wallet_from_mnemonic(cosmos_mnemonic)
        Account.enable_unaudited_hdwallet_features()
        eth_wallet = Account.from_mnemonic(eth_mnemonic)

        return self.generate_new_cosmos_user(cosmos_wallet, eth_wallet, eth_chain_id, dexilon_chain_id)

    def wrapObject(self, value):
        return {
            'typeUrl': '/dexilon_exchange.dexilonL2.registration.MsgCreateAddressMapping',
            'value': {
                'messages': [
                    {
                        'typeUrl': '/dexilon_exchange.dexilonL2.registration.MsgCreateAddressMapping',
                        'value': value
                    }
                ]
            }
        }
