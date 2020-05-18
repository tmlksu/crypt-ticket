import hashlib
from ecdsa import SigningKey, VerifyingKey, BadSignatureError
from ecdsa.util import sigdecode_der, sigencode_der
from typing import Any, Optional
from datetime import datetime
from BinaryTool import ByteConvertTool, BinaryDecodeTool, BinaryCutTool, ValueImporter, BinaryOrders, DATE_NO_TIME
import base64
from enum import Enum


class AttributeBits(Enum):
    """
    Ticket自体の情報
    """
    IsNotPaid = 0b1  # Ticket IDは関係ない。
    Waiting = 0b10  # Ticket IDは関係ない。
    ChangedOnce = 0b100  # 変更済
    ChangeIsNotAllowed = 0b1000  # 変更不可
    IsVIP = 0b10000  # VIPフラグ



class OptionBits(Enum):
    """
    チケットの取り扱い方系Option
    """
    IsGroupEntry = 0b1  # Ticket IDは関係ない。


class BypassBits(Enum):
    BypassReEntry = 0b1
    BypassCapacity = 0b10
    BypassExpiryOfIssuedDate = 0b100


OUTPUT_BYTES_ORDERS_LIST = [
    ("symbol", ByteConvertTool.string_to_bytes_with_padding__(3), 3, BinaryDecodeTool.to_string_),
    ("version_major", ByteConvertTool.any_int_to_bytes__(1), 1, BinaryDecodeTool.to_int_),
    ("version_minor", ByteConvertTool.any_int_to_bytes__(1), 1, BinaryDecodeTool.to_int_),
    ("version_revision", ByteConvertTool.any_int_to_bytes__(1), 1, BinaryDecodeTool.to_int_),

    ("event_id", ByteConvertTool.any_int_to_bytes__(4), 4, BinaryDecodeTool.to_int_),
    ("ticket_type", ByteConvertTool.any_int_to_bytes__(1), 1, BinaryDecodeTool.to_int_),
    ("ticket_group_id", ByteConvertTool.any_int_to_bytes__(2), 2, BinaryDecodeTool.to_int_),
    ("ticket_id", ByteConvertTool.any_int_to_bytes__(4), 4, BinaryDecodeTool.to_int_),

    ("user_type", ByteConvertTool.any_int_to_bytes__(1), 1, BinaryDecodeTool.to_int_),
    ("valid_times", ByteConvertTool.any_int_to_bytes__(1), 1, BinaryDecodeTool.to_int_),

    ("attributes_byte", ByteConvertTool.any_int_to_bytes__(1), 1, BinaryDecodeTool.to_int_),
    ("options_byte", ByteConvertTool.any_int_to_bytes__(1), 1, BinaryDecodeTool.to_int_),
    ("bypasses_byte", ByteConvertTool.any_int_to_bytes__(1), 1, BinaryDecodeTool.to_int_),

    ("valid_since", ByteConvertTool.datetime_to_bytes__(8), 8, BinaryDecodeTool.to_datetime_),
    ("valid_until", ByteConvertTool.datetime_to_bytes__(8), 8, BinaryDecodeTool.to_datetime_),
    ("date_issued", ByteConvertTool.datetime_to_bytes__(8), 8, BinaryDecodeTool.to_datetime_),
    ("description", ByteConvertTool.string_to_bytes_with_padding__(16), 16, BinaryDecodeTool.to_string_),
    ("separator", ByteConvertTool.string_to_bytes_with_padding__(1), 1, BinaryDecodeTool.to_string_),
]
OUTPUT_BYTES_ORDERS_LIST_SIGNATURE = [
        ("signature", ByteConvertTool.bypass_, 80)
]

TICKET_OUTPUT_BINARY_ORDERS = BinaryOrders(OUTPUT_BYTES_ORDERS_LIST)
TICKET_OUTPUT_BINARY_ORDERS_SIGNATURE = BinaryOrders(OUTPUT_BYTES_ORDERS_LIST_SIGNATURE)
TICKET_OUTPUT_BINARY_ORDERS_ALL = BinaryOrders(OUTPUT_BYTES_ORDERS_LIST + OUTPUT_BYTES_ORDERS_LIST_SIGNATURE)

class Ticket:
    def __init__(self,
                 event_id: int,
                 ticket_type: int = 0,
                 ticket_group_id: int = 0,
                 ticket_id: int = 0,
                 valid_times: int = 0,
                 user_type: int = 0,
                 valid_since: datetime = DATE_NO_TIME,
                 valid_until: datetime = DATE_NO_TIME,
                 date_issued: datetime = DATE_NO_TIME,
                 description: str = "",
                 signature: Optional[bytes] = None,
                 original_data: bytes = None,
                 original_data_with_signature: bytes = None,
                 attributes_byte: int = 0,
                 options_byte: int = 0,
                 bypasses_byte: int = 0,
                 **others
                 ):

        self.data = {
            "event_id": event_id,
            "ticket_type": ticket_type,
            "ticket_group_id": ticket_group_id,
            "ticket_id": ticket_id,

            "valid_times": valid_times,
            "user_type": user_type,

            "attributes_byte": attributes_byte,
            "options_byte": options_byte,
            "bypasses_byte": bypasses_byte,

            "description": description,
            "valid_since": valid_since,
            "valid_until": valid_until,
            "date_issued": date_issued,
            "signature": signature,
        }

        self.original_data = original_data
        self.original_data_with_signature = original_data_with_signature

        self.imported_data = ValueImporter.value_from_dict__(self.data)

        self.data.update(others)
        self.data.update(self.fixed_values)

    fixed_values = {
        "symbol": "TCS",
        "version_major": 0,
        "version_minor": 0,
        "version_revision": 0,
        "separator": "\n",
    }

    output_bytes_order = TICKET_OUTPUT_BINARY_ORDERS
    output_bytes_order_signature = TICKET_OUTPUT_BINARY_ORDERS_SIGNATURE

    @classmethod
    def import_from_binary(cls, binary: bytes):

        bicut = BinaryCutTool(orders=TICKET_OUTPUT_BINARY_ORDERS)

        result = bicut.seek_cut(binary)

        if result["version_major"] != 0:
            raise ValueError("Incompatible Version")

        ticket = Ticket(**result)

        signature_cropped = binary[bicut.seek_now:]

        ticket.original_data = binary[:bicut.seek_now]
        ticket.original_data_with_signature = binary[:]

        ticket.data["signature"] = signature_cropped

        return ticket

    @property
    def signature(self) -> Optional[bytes]:
        return self.data["signature"]

    @property
    def date_issued(self) -> Optional[datetime]:
        """
        チケット発行日
        :return:
        """
        return self._date_returner("date_issued")

    @property
    def valid_since(self) -> Optional[datetime]:
        """
        チケット発行日
        :return:
        """
        return self._date_returner("valid_since")

    @property
    def valid_until(self) -> Optional[datetime]:
        """
        チケット発行日
        :return:
        """
        return self._date_returner("valid_until")

    def _date_returner(self, key: str) -> Optional[datetime]:
        """
        日付を正規化して返す
        :param key:
        :return:
        """
        if key not in self.data:
            return None
        elif self.data[key] == DATE_NO_TIME:
            return None

        return self.data[key]

    def verify_original_data(self, verifier: VerifyingKey) -> bool:
        """
        original_dataをVerify
        :param verifier:
        :return:
        """
        #print(self.original_data_with_signature)
        #print(self.signature)
        return verifier.verify(self.signature, self.original_data, hashlib.sha256, sigdecode=sigdecode_der)

    def sign(self, signer: SigningKey) -> bytes:
        """
        署名を実施
        :param signer:
        :return:
        """
        new_bytes = self.convert()
        #print(new_bytes)
        signature = signer.sign_deterministic(new_bytes, sigencode=sigencode_der)
        self.data["signature"] = signature
        return signature

    def convert(self) -> bytes:
        """
        バイト列に変換
        :return:
        """
        new_bytes = b""

        for order in self.output_bytes_order.orders:
            byte_part = order[1](self.data[order[0]])
            new_bytes += byte_part[:order[2]]

        return new_bytes

    def convert_with_signature(self) -> bytes:
        """
        署名付きバイト列に変換
        :return:
        """
        new_bytes = self.convert()
        for order in self.output_bytes_order_signature.orders:
            byte_part = order[1](self.data[order[0]])
            new_bytes += byte_part[:order[2]]

        return new_bytes


class TicketDisplayV0:
    """
    チケットの情報を表示するスクリプト
    """

    @classmethod
    def print(cls, ticket: Ticket, verifier: Optional[VerifyingKey] = None):
        text = ""

        forms = [
            ("Ticket Version", "{0}.{1}.{2}".format(
                ticket.data["version_major"],
                ticket.data["version_minor"],
                ticket.data["version_revision"],
            )),
            ("Event ID", "{0}".format(ticket.data["event_id"])),
            ("Ticket Code", "{0}-{1}".format(
                ticket.data["ticket_group_id"], ticket.data["ticket_id"]
             )),
            ("User Type", "{0}".format(ticket.data["user_type"])),
            ("Description", ticket.data["description"]),
        ]

        if ticket.data["valid_since"] is not None:
            forms.append(("Valid Date Since", ticket.data["valid_since"].strftime("%Y-%m-%d %H:%M:%S %z")))

        if ticket.data["valid_until"] is not None:
            forms.append(("Valid Date Until", ticket.data["valid_until"].strftime("%Y-%m-%d %H:%M:%S %z")))

        if ticket.data["date_issued"] is not None:
            forms.append(("Issued Date", ticket.data["date_issued"].strftime("%Y-%m-%d %H:%M:%S %z")))

        if ticket.data["date_issued"] is not None:
            forms.append(("Signature", base64.b85encode(ticket.signature).decode("utf-8") ))
        else:
            forms.append(("Signature", "None"))

        if verifier is not None:
            value_output = "Unknown(Not Verified)"
            try:
                raw_data_binary = ticket.original_data
                if ticket.original_data is None:
                    raw_data_binary = ticket.convert()

                result = verifier.verify(ticket.signature, raw_data_binary, hashlib.sha256, sigdecode=sigdecode_der)
                if result is True:
                    value_output = "Verified"
            except BadSignatureError:
                value_output = "Not Verified"

            forms.append(("Verification", value_output))

        for form in forms:
            text += "{0}: {1}\n".format(form[0], form[1])

        return text

