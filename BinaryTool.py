from typing import Optional, Any
from datetime import datetime, timezone, timedelta
from Config import UTC_TZ, DEFAULT_TZ

DATE_NO_TIME = datetime(1970, 1, 1, 0, 0, 0, tzinfo=UTC_TZ)

class BinaryDecodeTool:
    """
    BinaryをDecode
    """

    @staticmethod
    def to_int_(val: bytes):
        return int.from_bytes(val, "big")

    @classmethod
    def to_datetime_(cls, val: bytes) -> Optional[datetime]:
        number = cls.to_int_(val)
        if number <= 0:
            return None

        result = datetime.fromtimestamp(number, tz=DEFAULT_TZ)
        return result

    @staticmethod
    def to_string_(binary: bytes) -> str:
        zero_data = (0).to_bytes(1, "big")
        binary_raw = binary[:]
        text = binary_raw.replace(zero_data, b"").decode("utf-8", errors="ignore")
        return text

    @staticmethod
    def bypass_(val: Any) -> bytes:
        return val


class ByteConvertTool:
    @staticmethod
    def any_int_to_bytes__(size: int):
        def _func(val: int) -> bytes:
            return val.to_bytes(size, "big")

        return _func

    @classmethod
    def datetime_to_bytes__(cls, size: int):
        def _func(date_convert: datetime) -> bytes:
            if date_convert is None:
                date_convert = DATE_NO_TIME
            return cls.any_int_to_bytes__(size)(int(date_convert.timestamp()))

        return _func

    @staticmethod
    def string_to_bytes_with_padding__(padding: int):
        def _func(text: str) -> bytes:
            text_byte = text.encode("utf-8")
            padding_size = padding - len(text_byte)
            if padding_size > 0:
                text_byte += bytes(bytearray(padding_size))

            #print(text_byte[:padding], text_byte[:padding].decode("utf-8", errors="ignore"))
            return text_byte[:padding]

        return _func

    @staticmethod
    def string_to_bytes_(text: str) -> bytes:
        return text.encode("utf-8")

    @staticmethod
    def bypass_(val: Any) -> bytes:
        return val


class ValueImporter:
    """
    値を入力するやつ
    """
    @staticmethod
    def value_from_dict__(_data: dict):
        def _func(key: str):
            return _data[key]

        return _func

    @staticmethod
    def bypass_(val: Any):
        return val


class BinaryOrders:
    """
    バイナリの順番を定義
    """

    def __init__(self, orders: list):
        self.orders = orders


class BinaryCutTool:
    """
    バイナリの切断を実施
    """

    def __init__(self, orders: BinaryOrders):
        self.orders = orders
        self.seek_now = 0

    def seek_cut(self, binary: bytes):
        self.seek_now = 0
        seek_next = 0
        results = {}
        for order in self.orders.orders:
            seek_next += order[2]
            value_raw = binary[self.seek_now:seek_next]
            results[order[0]] = order[3](value_raw)

            self.seek_now = seek_next

        return results
