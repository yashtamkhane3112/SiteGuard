import socket
import ssl
from urllib.parse import urlparse

import requests

from .models import MonitorLog


def get_site_status(log):
    if not log:
        return "DOWN"

    if getattr(log, "status", None) == "DOWN":
        return "DOWN"

    if log.response_time is None:
        return "DOWN"

    if log.response_time > 2000:
        return "SLOW"

    return "UP"


def get_latest_logs_by_website(logs):
    latest_logs = {}

    for log in logs:
        if log.website_id not in latest_logs:
            latest_logs[log.website_id] = log

    return latest_logs


def get_favicon_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    return f"https://www.google.com/s2/favicons?domain={domain}&sz=64"


def check_ssl_status(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.path.split("/")[0]
        if not hostname:
            return "Invalid"

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return "Valid"
    except Exception:
        return "Invalid"


def run_single_check(website, timeout=5):
    url = website.url
    if not url.startswith("http"):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=timeout)
        response_time_ms = response.elapsed.total_seconds() * 1000

        if 200 <= response.status_code < 400:
            status = (
                MonitorLog.STATUS_SLOW
                if response_time_ms > 2000
                else MonitorLog.STATUS_UP
            )
        else:
            status = MonitorLog.STATUS_DOWN

        log = MonitorLog.objects.create(
            website=website,
            status=status,
            response_time=round(response_time_ms, 2),
        )
        return log, response
    except Exception:
        log = MonitorLog.objects.create(
            website=website,
            status=MonitorLog.STATUS_DOWN,
            response_time=0,
        )
        return log, None


def get_site_snapshot(log):
    response_time = 0
    if log and log.response_time is not None:
        response_time = round(log.response_time, 2)

    return {
        "status": get_site_status(log),
        "response_time": response_time,
        "last_checked": log.checked_at if log else None,
    }
