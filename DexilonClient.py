from typing import List

from responses import AvailableSymbol, OrderBookInfo, AccountInfo, OrderInfo, FullOrderInfo


class DexilonClient():

    def get_open_orders(self) -> List[OrderInfo]:
        """
        Returns full list of open orders
        :return: OrdersBySymbol[]
        """
        pass

    def get_order_info(self, order_id: str, client_order_id: str, symbol: str) -> FullOrderInfo:
        """
        Returns order information by orderId
        :param order_id: Dexilon order id
        :type order_id: str
        :param symbol: order symbol
        :type symbol: str
        :return: FullOrderInfo
        """


    def market_order(self, client_order_id: str, symbol: str, side: str, size: float):
        """
        Submit new market order
        :param client_order_id: generated on client side order id
        :type client_order_id: str.
        :param symbol: order symbol
        :type symbol: str.
        :param side: order side [BUY, SELL]
        :type side: str.
        :param size: amount of the order asset
        :type size: float
        :return: Dexilon generated order id

        :throws: OrderErrorInfo in case if there is any issues with submitted order
        """
        pass


    def limit_order(self, client_order_id: str, symbol: str, side: str, price: float, size: float):
        """
        Submit new limit order
        :param client_order_id: generated on client side order id
        :type client_order_id: str.
        :param symbol: order symbol
        :type symbol: str.
        :param side: order side [BUY, SELL]
        :type side: str.
        :param size: amount of the order asset
        :type size: float
        :param price: limit price
        :type price: float
        :return: Dexilon generated order id
        """
        pass

    def get_account_info(self) -> AccountInfo:
        """
        Get account balance info
        :return: AccountInfo
        """


    def cancel_all_orders(self) -> bool:
        """
        Cancel all open orders
        :return: result bool
        """
        pass


    def cancel_order(self, order_id: str, symbol: str):
        """
        Cancel specific order by order id and symbol
        :param order_id: str
        :param symbol:
        :return: result bool
        """
        pass


    def get_all_symbols(self) -> List[AvailableSymbol]:
        """
        Get all available symbols
        :return: AvailableSymbol[]
        """
        pass

    def get_orderbook(self, symbol: str) -> OrderBookInfo:
        """
        Get latest orderbook by symbol
        :return: OrderBookInfo
        """
