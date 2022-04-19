

class MarginData:

    def __init__(self, margin: float, upl: float, equity: float, lockedBalanceForOpenOrders: float, locked: float):
        self.margin = margin
        self.upl = upl
        self.equity = equity
        self.lockedBalanceForOpenOrders = lockedBalanceForOpenOrders
        self.locked = locked
