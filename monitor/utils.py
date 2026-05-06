def get_site_status(log):
    if not log:
        return "DOWN"

    if log.response_time is None:
        return "DOWN"

    if getattr(log, "status", None) == "DOWN":
        return "DOWN"

    if log.response_time > 2000:
        return "SLOW"

    return "UP"


def get_site_snapshot(log):
    response_time = 0
    if log and log.response_time is not None:
        response_time = round(log.response_time, 2)

    return {
        "status": get_site_status(log),
        "response_time": response_time,
        "last_checked": log.checked_at if log else None,
    }
