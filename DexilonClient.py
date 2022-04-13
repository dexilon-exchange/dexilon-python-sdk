

class DexilonClient():

    def get_open_orders(self) -> []:
        """
        Returns full list of open orders
        :return: OrdersBySymbol[]
        """

        pass


    def market_order(self, client_order_id: str, symbol: str, side: str, size: float) -> str:
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
        """
        pass


    def limit_order(self, client_order_id: str, symbol: str, side: str, price: float, size: float) -> str:
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


    def get_max_available_for_sell(self, symbol:str) -> float:
        """
        Get maximum available amount for sell by symbol
        :param symbol: symbol to get max amount available for sell
        :type symbol: str.
        :return: float available amount by symbol
        """
        pass


    def get_max_available_to_buy(self, symbol:str) -> float:
        """
        Get maximum available amount for buy by symbol
        :param symbol: symbol to get max amount available for buy
        :type symbol: str.
        :return: float available amount by symbol
        """
        pass


    def cancel_all_orders(self) -> bool:
        """
        Cancel all open orders
        :return: result bool
        """
        pass


    def cancel_order(self, order_id: str, symbol: str) -> bool:
        """
        Cancel specific order by order id and symbol
        :param order_id: str
        :param symbol:
        :return: result bool
        """
        pass


    def get_all_symbols(self) -> []:
        """
        Get all available symbols
        :return: AvailableSymbol[]
        """
        pass

    def get_orderbook(self, symbol:str) -> []:
        """
        Get latest orderbook by symbol
        :return:
        """
