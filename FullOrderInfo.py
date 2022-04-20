from datetime import datetime


class FullOrderInfo:

    def __init__(self, client_order_id: str, symbol: str, order_id: str, price: float, amount: float, filled_amount: float, avg_price: float, type: str, side: str, status: str, created_at: datetime, updated_at: datetime):
        self.client_order_id = client_order_id
        self.symbol = symbol
        self.order_id = order_id
        self.price = price
        self.amount = amount
        self.filled_amount = filled_amount
        self.avg_price = avg_price
        self.type = type
        self.side = side
        self.status = status
        self.created_at = created_at
        self.updated_at = updated_at