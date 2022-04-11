import requests as requests

from web3.auto import w3
from eth_account.messages import encode_defunct
from eth_keys import keys

from DexilonClient import DexilonClient
from exceptions import DexilonAPIException, DexilonRequestException, DexilonAuthException


class DexilonClientImpl(DexilonClient):
    API_URL = 'https://dex-dev-api.cronrate.com/api/v1'

    JWT_KEY = ''

    pk1 = ''

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

        self.jwtToken = self.authenticate()

    def change_api_url(self, api_url):
        """
        Used for testing purposes

        :param api_url: Public
        :type api_url: str.

        """

        self.API_URL = api_url

    def authenticate(self):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        payload = {'metamaskAddress': self.METAMASK_ADDRESS}
        r = requests.post(self.API_URL + '/auth/startAuth', json=payload, headers=headers)
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

        auth_response = requests.post(self.API_URL + '/auth/finishAuth', json=signature_payload, headers=headers)

        auth_info = self._handle_response(auth_response)

        if auth_info['body']['jwt'] is None or len(auth_info['body']['jwt']) == 0:
            raise DexilonAuthException('Was not able to obtain JWT token for authentication')

        print(auth_info)

        return auth_info['body']['jwt']

    def _handle_response(self, response):
        """Internal helper for handling API responses from the Binance server.
        Raises the appropriate exceptions when necessary; otherwise, returns the
        response.
        """
        if not str(response.status_code).startswith('2'):
            raise DexilonAPIException(response)
        try:
            return response.json()
        except ValueError:
            raise DexilonRequestException('Invalid Response: %s' % response.text)
