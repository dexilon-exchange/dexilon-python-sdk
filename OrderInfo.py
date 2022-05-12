import datetime


class OrderInfo:

    def __init__(self, id:str, symbol: str, type: str, amount: float, price: float, side: str, filled: float, placed: datetime):
        self.id = id
        self.type = type
        self.amount = amount
        self.price = price
        self.side = side
        self.filled = filled
        self.placed = placed
        self.symbol = symbol
