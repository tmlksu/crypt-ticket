from pathlib import Path
import base64
from ecdsa import SigningKey, VerifyingKey
from ecdsa.util import sigdecode_der, sigencode_der
from Config import UTC_TZ, DEFAULT_TZ
from TicketLib import Ticket, TicketDisplayV0, DATE_NO_TIME
import hashlib
from datetime import datetime, timedelta
from TicketChecker import TicketChecker, CheckDefinition, CheckDefinitionMaterials

with open("keys/sk.pem") as f:
    sk = SigningKey.from_pem(f.read(), hashfunc=hashlib.sha256)

with open("keys/vk.pem") as f:
    vk = VerifyingKey.from_pem(f.read())

with open("keys/data", "rb") as f:
    data = f.read()

with open("keys/dataa.sig", "rb") as f:
    signature2 = f.read()

data2 = "あいうえお\n".encode("utf-8")


rt = vk.verify(signature2, data2, hashlib.sha256, sigdecode=sigdecode_der)

date_from = datetime.strptime("2020-10-1", "%Y-%m-%d")
date_to = datetime.strptime("2020-11-1", "%Y-%m-%d")
date_from = None
date_to = None
current_date = datetime.now(tz=DEFAULT_TZ)
ticket = Ticket(1, 1, 1, 99, 1, 0, date_from, date_to, current_date, "BTCMeeting#29912", attributes_byte=13)
ticket.sign(sk)

binary_with_signature = ticket.convert_with_signature()
"""
bicut = BinaryCutTool(orders=TICKET_OUTPUT_BINARY_ORDERS)

result = bicut.seek_cut(binary_with_signature)
signature_cropped = binary_with_signature[bicut.seek_now:]
if len(signature_cropped) >= 1:
    result["signature"] = binary_with_signature[1:]
"""

t2 = Ticket.import_from_binary(binary_with_signature)
print(t2.verify_original_data(verifier=vk))
print(TicketDisplayV0.print(t2, verifier=vk))

# Define
date_to = datetime.now(tz=DEFAULT_TZ) - timedelta(hours=6)
check_defines_list = [
    CheckDefinitionMaterials.check_valid_date__(datetime.now(tz=DEFAULT_TZ)),
    CheckDefinitionMaterials.issued_specific_date__(date_to=date_to)
]
definition = CheckDefinition(check_defines_list)

ticket_checker = TicketChecker.check(ticket=t2, verifiers=[vk], check_definition=definition)
print(ticket_checker.state)

from QRCoder import TicketQRCoder

image = TicketQRCoder.convert(ticket=ticket)
image.save("hoge.png")

"""
with open("keys/outputter", "wb") as f:
    f.write(t2.original_data)

with open("keys/outputter.sig", "wb") as f:
    f.write(t2.signature)
"""

