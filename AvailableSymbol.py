

class AvailableSymbol:

    def __init__(self, symbol: str, is_favorite: bool, last_price: float, volume: float, price_24_percentage: float):
        self.symbol = symbol
        self.is_favorite = is_favorite
        self.last_price = last_price
        self.volume = volume
        self.price_24_percentage = price_24_percentage
