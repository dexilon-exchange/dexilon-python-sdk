import datetime


class OrderInfo:

    def __init__(self, id:str, type: str, amount: float, price: float, side: str, filled: float, notional_value: float, placed: datetime):
        self.id = id
        self.type = type
        self.amount = amount
        self.price = price
        self.side = side
        self.filled = filled
        self.notional_value = notional_value
        self.placed = placed
