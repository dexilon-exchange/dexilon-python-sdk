from datetime import datetime
from typing import List
from pydantic import BaseModel, Field
from pydantic.main import Optional


class AvailableSymbol(BaseModel):
    symbol: str
    isFavorite: bool
    lastPrice: Optional[float]
    volume: Optional[float]
    price24Percentage: Optional[float]
    # {'symbol': 'btc_usdc', 'isFavorite': False, 'lastPrice': None, 'volume': 0, 'price24Percentage': 0}


class OrderBook(BaseModel):
    price: float
    size: float
    sum: float


class OrderBookInfo(BaseModel):
    ask: List[OrderBook]
    bid: List[OrderBook]
    timestamp: Optional[datetime]


class ErrorInfo(BaseModel):
    code = str
    message = str
