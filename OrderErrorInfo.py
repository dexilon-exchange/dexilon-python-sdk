
class OrderErrorInfo:

    def __init__(self, client_order_id: str, order_id: str, state: str, message: str):
        self.client_order_id = client_order_id
        self.order_id = order_id
        self.state = state
        self.message = message