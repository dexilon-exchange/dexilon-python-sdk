from datetime import datetime
from typing import List
from pydantic import BaseModel, Field
from pydantic.main import Optional

class ErrorBody(BaseModel):
    code: int
    name: str
    details: List[str]

class DebugInfo(BaseModel):
    correlationId: Optional[str]
    stackTrace: Optional[str]

class ServiceResponse(BaseModel):
    errorBody: Optional[ErrorBody]
    debugInfo: Optional[DebugInfo]


class AvailableSymbol(BaseModel):
    symbol: str
    isFavorite: bool
    lastPrice: Optional[float]
    volume: Optional[float]
    price24Percentage: Optional[float]


class AvailableSymbolsResponse(BaseModel):
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


class OrderEvent(BaseModel):
    orderId: Optional[str]
    eventType: str
    event: dict


class PositionInfo(BaseModel):
    symbol: str
    amount: float
    basePrice: float
    liqPrice: float
    pl: float
    plPercentage: int
    leverage: int


class OrderBalanceInfo(BaseModel):
    symbol: str
    lockedAsk: float
    lockedBid: float


class AccountInfo(BaseModel):
    margin: float
    locked: float
    upl: float
    equity: float
    positions: List[PositionInfo]
    orders: List[OrderBalanceInfo]


class OrderInfo(BaseModel):
    id: str
    symbol: str
    type: str
    amount: float
    price: float
    side: str
    filled: float
    placedAt: datetime


class AllOpenOrders(BaseModel):
    content: List[OrderInfo]


class FullOrderInfo(BaseModel):
    clientOrderId: Optional[str]
    symbol: str
    orderId: str
    price: float
    amount: float
    filledAmount: Optional[float]
    avgPrice: Optional[float]
    type: str
    side: str
    status: str
    createdAt: datetime
    updatedAt: datetime