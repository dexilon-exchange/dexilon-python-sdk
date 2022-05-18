import requests

from exceptions import DexilonAPIException, DexilonRequestException


class SessionClient:

    def __init__(self, base_url: str, headers: dict = {}) -> None:

        self.base_url: str = base_url
        self.session: requests.Session = requests.Session()
        self.session.headers.update(headers)

    def update_headers(self, headers: dict = {}) -> None:
        self.session.headers.update(headers)

    def delete_header(self, header_name: str) -> None:
        self.session.headers.pop(header_name)

    def request(self, method: str, path: str, params: dict = None, data: dict = None) -> dict:
        request = requests.Request(
            method=method.upper(),
            url=self.base_url + path,
            params=params,
            json=data
        )

        prepared_request = self.session.prepare_request(request)

        response = self.session.send(request=prepared_request)

        try:

            data = response.json()

            if not str(response.status_code).startswith('2'):
                errors = data.get('errors', {})
                raise DexilonAPIException(
                    code=errors.get('code', [0])[0],
                    message=errors.get('message', [''])[0]
                )

            return data

        except ValueError:
            raise DexilonRequestException(
                message='Invalid Response: {}'.format(response.text)
            )
