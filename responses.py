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

class AvailableSymbol(BaseModel):
    symbol: str
    lastPrice: Optional[float]
    volume: Optional[float]
    price24Percentage: Optional[float]

class CosmosAddressMapping(BaseModel):
    chainId: int
    address: str
    cosmosAddress: str

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


class CosmosFaucetResponse(BaseModel):
    result: Optional[dict]


class OrderEvent(BaseModel):
    orderId: Optional[str]
    clientOrderId: Optional[str]
    symbol: Optional[str]
    amount: float
    price: Optional[float]
    filled: float
    averageExecutionPrice: Optional[float]
    type: str
    side: str
    status: str
    updatedAt: datetime


class PositionInfo(BaseModel):
    symbol: str
    marginMode: Optional[str]
    amount: float
    basePrice: float
    liquidationPrice: Optional[float]
    markPrice: Optional[float]
    upl: Optional[float]
    uplPercentage: Optional[int]
    lockedBalance: Optional[float]
    leverage: int


class OrderBalanceInfo(BaseModel):
    symbol: str
    lockedAsk: float
    lockedBid: float
    sumSizeAsk: float
    sumSizeBid: float


class AssetInfo(BaseModel):
    name: str
    deposited: Optional[float]
    margin: Optional[float]
    locked: Optional[float]
    isMargin: Optional[bool]


class AccountInfo(BaseModel):
    upl: float
    equity: float
    feeTierStructure: int
    feeTierDiscount: int
    tradeFeeAsset: str
    assets: List[AssetInfo]
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


class LeverageEvent(BaseModel):
    leverage: int


class DexilonAccount(BaseModel):
    type: Optional[str]
    address: Optional[str]
    account_number: Optional[int]
    sequence: Optional[int]


class DexilonAccountInfo(BaseModel):
    account: Optional[DexilonAccount]


class DexilonTransactionInfoData(BaseModel):
    txhash: Optional[str]
    code: Optional[int]

class DexilonTransactionResponseInfo(BaseModel):
    tx_response: DexilonTransactionInfoData


class FundsTransferResponse(BaseModel):
    amount: Optional[int]