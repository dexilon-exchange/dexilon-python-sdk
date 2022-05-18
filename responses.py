from datetime import datetime
from typing import List
from pydantic import BaseModel, Field
from pydantic.main import Optional


class ServiceResponse(BaseModel):
    errorBody: Optional[str]
    debugInfo: Optional[str]


class AvailableSymbol(BaseModel):
    symbol: str
    isFavorite: bool
    lastPrice: Optional[float]
    volume: Optional[float]
    price24Percentage: Optional[float]


class AvailableSymbolsResponse(ServiceResponse):
    body: List[AvailableSymbol]


class OrderBook(BaseModel):
    price: float
    size: float
    sum: float


class OrderBookInfo(BaseModel):
    ask: List[OrderBook]
    bid: List[OrderBook]


class NonceResponse(BaseModel):
    nonce: str


class JWTTokenResponse(BaseModel):
    accessToken: str
    refreshToken: str
