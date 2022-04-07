import requests as requests

from DexilonClient import DexilonClient


class DexilonClientImpl(DexilonClient):

    API_URL = 'https://api.binance.com/api'

    def __init__(self, metamask_address, api_secret):
        """ Dexilon API Client constructor

        :param metamask_address: Public Metamask Address
        :type metamask_address: str.
        :param api_secret: Api Secret
        :type api_secret: str.
        """

        self.METAMASK_ADDRESS = metamask_address
        self.API_SECRET = api_secret

        self.jwtToken = self.authenticate()


    def change_api_url(self, api_url):
        """
        Used for testing purposes

        :param api_url: Public
        :type api_url: str.

        """

        self.API_URL = api_url


    def authenticate(self):
        session = requests.session()
        session.get()

        return session
