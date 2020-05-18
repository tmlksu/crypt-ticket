from TicketLib import Ticket
from PIL.Image import Image
from typing import Optional
import base64
import qrcode


class TicketQRCoder:
    """
    QRコードを作成する
    """

    @classmethod
    def convert(cls, ticket: Ticket) -> Optional[Image]:
        payload = ticket.convert_with_signature()
        print(len(payload))
        payload = "tcticket://" + base64.b85encode(payload).decode("utf-8")
        print(len(payload))
        return qrcode.make(payload)

