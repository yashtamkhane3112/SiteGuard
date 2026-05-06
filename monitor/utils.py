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
