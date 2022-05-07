
class OrderBalanceInfo:

    def __init__(self, symbol: str, locked_ask: float, locked_bid: float):
        self.symbol = symbol
        self.locked_ask = locked_ask
        self.locked_bid = locked_bid
