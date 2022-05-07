
class PositionInfo:

    def __init__(self, symbol: str, amount: float, base_price: float, liq_price: float, pl: float, pl_percentage: int, leverage: int):
        self.symbol = symbol
        self.amount = amount
        self.base_price = base_price
        self.liq_price = liq_price
        self.pl = pl
        self.pl_percentage = pl_percentage
        self.leverage = leverage
