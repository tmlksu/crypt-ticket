from enum import Enum
from TicketLib import Ticket
from typing import Optional, List
from ecdsa import SigningKey, VerifyingKey
from datetime import datetime

"""
チケットの中身を確認する
"""

class TicketState(Enum):
    """
    チケットの確認結果を返す
    """
    OK = 200
    NoGoodOnVerification = 400
    NoGoodOnCondition = 401
    NoGoodOnMalForm = 402

    def __bool__(self) -> bool:
        return self.is_passed()

    def is_passed(self) -> bool:
        """
        Ticketのチェックをパスしているか
        :return:
        """
        if self is TicketState.OK:
            return True

        return False


class TicketResult:
    """
    チケット
    """
    def __init__(self, state: TicketState, **data):
        self.state = state

    @classmethod
    def is_ok(cls, message: str=None):
        result = TicketResult(state=TicketState.OK)
        return result

    @classmethod
    def is_ng_not_verified(cls, message: str=None):
        result = TicketResult(state=TicketState.NoGoodOnVerification)
        return result


class CheckResult:
    """
    チェックごとの結果
    """
    def __init__(self, state: bool, message: Optional[str] = None):
        self.state = state
        self.message= message

    def __bool__(self) -> bool:
        return self.state

    @classmethod
    def get_check_ok(cls, message: Optional[str]=None):
        """
        チェックOKを返す
        :param message:
        :return:
        """
        return CheckResult(True, message)

    @classmethod
    def get_check_ng(cls, message: Optional[str]=None):
        """
        チェックNGを返す
        :param message:
        :return:
        """
        return CheckResult(False, message)


class CheckDefinition:
    """
    チェックの定義
    """

    def __init__(self, data: List):
        self.data = data

    def __iter__(self):
        return iter(self.data)


class CheckDefinitionMaterials:
    """
    チェック定義に用いる材料
    """
    @staticmethod
    def check_valid_date__(date_current: datetime):
        def _func(ticket: Ticket) -> CheckResult:
            if ticket.valid_until is not None:
                if not date_current <= ticket.valid_until:
                    return CheckResult.get_check_ng("チケットが失効しています。 ")

            if ticket.valid_since is not None:
                if not ticket.valid_since <= date_current:
                    return CheckResult.get_check_ng("このチケットはまだ利用できません。")

            return CheckResult.get_check_ok()

        return _func

    @staticmethod
    def issued_specific_date__(
          date_to: Optional[datetime],
          permit_to_date: bool = True,
          date_from: Optional[datetime] = None,
          permit_from_date: bool = True
        ):
        """
        Issued Dateが特定の日付かを確認する
        :param date_from:
        :param date_to:
        :param permit_from_date:
        :param permit_to_date:
        :return:
        """
        def _func(ticket: Ticket) -> CheckResult:
            if ticket.date_issued is None:
                return CheckResult.get_check_ok()

            if date_from is not None and ticket.date_issued is not None and not date_from <= ticket.date_issued:
                return CheckResult.get_check_ng("有効期限切れです")
            elif date_to is not None and ticket.date_issued is not None and not ticket.date_issued <= date_to:
                return CheckResult.get_check_ng("有効期限切れです")

            if permit_from_date is False and date_from == ticket.data["date_issued"]:
                return CheckResult.get_check_ng("有効期限切れです。")
            if permit_to_date is False and date_to == ticket.data["date_issued"]:
                return CheckResult.get_check_ng("有効期限切れです。")

            return CheckResult.get_check_ok()

        return _func


class TicketChecker:
    _version = 0

    @classmethod
    def check(cls, ticket: Ticket, verifiers: List[VerifyingKey], check_definition: CheckDefinition) -> TicketResult:
        """
        チェックの確認
        :param ticket:
        :param verifier:
        :param check_definition:
        :return:
        """

        # Verifyに失敗した場合
        if cls._verify_by_verifiers(ticket, verifiers=verifiers) is False:
            return TicketResult.is_ng_not_verified("署名に失敗しました")

        for check in check_definition:
            check_result = check(ticket)
            if check_result.state is False:
                return TicketResult.is_ng_not_verified("i")

        return TicketResult.is_ok()

    @staticmethod
    def _verify_by_verifiers(ticket: Ticket, verifiers: List[VerifyingKey]) -> bool:
        verified = False
        for verifier in verifiers:
            if ticket.verify_original_data(verifier=verifier) is True:
                return True

            return False
