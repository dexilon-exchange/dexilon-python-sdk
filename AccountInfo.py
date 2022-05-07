from OrderBalanceInfo import OrderBalanceInfo
from PositionInfo import PositionInfo


class AccountInfo:

    def __init__(self, margin: float, locked: float, upl: float, equity: float, positions: [PositionInfo], orders: [OrderBalanceInfo]):
        self.margin = margin
        self.locked = locked
        self.upl = upl
        self.equity = equity
        self.positions = positions
        self.orders = orders
