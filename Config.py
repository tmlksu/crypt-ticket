from datetime import timezone, datetime, timedelta

UTC_TZ = timezone(timedelta(hours=0), "UTC")
DEFAULT_TZ = timezone(timedelta(hours=9), "Asia/Tokyo")
DATE_NO_TIME = datetime(1970, 1, 1, 0, 0, 0, tzinfo=UTC_TZ)
