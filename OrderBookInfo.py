import datetime

class OrderBookInfo:

    def __init__(self, asks: [], bids: [], timestamp: datetime):
        self.asks = asks
        self.bids = bids
        self.timestamp = timestamp