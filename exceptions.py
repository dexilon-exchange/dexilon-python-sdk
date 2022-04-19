class DexilonAPIException(Exception):

    def __init__(self, response):
        self.code = 0
        try:
            json_res = response.json()
        except ValueError:
            self.message = 'Invalid JSON error message from Binance: {}'.format(response.text)
        else:
            self.code = json_res['errors']['code']
            self.message = json_res['errors']['message']
        self.status_code = response.status_code
        self.response = response
        self.request = getattr(response, 'request', None)

    def __str__(self):
        return 'APIError(code=%s): %s' % (self.code, self.message)


class DexilonRequestException(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return 'DexilonRequestException: %s' % self.message


class DexilonAuthException(Exception) :
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return 'DexilonAuthException: %s' % self.message
