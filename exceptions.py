from responses import ErrorBody


class DexilonAPIException(Exception):

    def __init__(self, response):
        self.code = 0
        try:
            json_res = response.json()
        except ValueError:
            self.message = 'Invalid JSON error message from Dexilon: {}'.format(
                response.text)
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


class DexilonAuthException(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return 'DexilonAuthException: %s' % self.message


class DexilonErrorBodyException(Exception):
    def __init__(self, error_body: ErrorBody):
        self.error_body = error_body

    def __str__(self):
        return 'ErrorBodyException: %s' % self.error_body


class OrderErrorInfo(Exception):

    def __init__(self, client_order_id: str, state: str, message: str):
        self.client_order_id = client_order_id
        self.state = state
        self.message = message

    def __str__(self):
        return 'OrderErrorInfo: client_order_id=%s state=%s message=%s' % (self.client_order_id, self.state, self.message)
