import ipaddress
import socket
from urllib.parse import urlparse

from django.core.exceptions import ValidationError


BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
}
BLOCKED_METADATA_IPS = {
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
}


def extract_hostname(raw_url):
    candidate = (raw_url or "").strip()
    if not candidate:
        raise ValidationError("Monitoring target is empty.")

    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    if parsed.scheme not in {"http", "https"}:
        raise ValidationError("Only HTTP and HTTPS monitoring targets are allowed.")

    hostname = (parsed.hostname or "").strip().rstrip(".")
    if not hostname:
        raise ValidationError("Monitoring target must include a hostname.")

    try:
        return hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValidationError("Monitoring target hostname contains invalid Unicode.") from exc


def is_blocked_ip(ip_obj):
    return any(
        (
            ip_obj.is_private,
            ip_obj.is_loopback,
            ip_obj.is_reserved,
            ip_obj.is_link_local,
            ip_obj.is_multicast,
            ip_obj.is_unspecified,
            ip_obj in BLOCKED_METADATA_IPS,
        )
    )


def is_blocked_hostname(hostname):
    lowered = (hostname or "").lower()
    if lowered in BLOCKED_HOSTNAMES or lowered.endswith(".local"):
        return True

    try:
        ip_obj = ipaddress.ip_address(lowered)
    except ValueError:
        return False

    return is_blocked_ip(ip_obj)


def resolve_public_addresses(raw_url, *, port=None):
    hostname = extract_hostname(raw_url)
    if is_blocked_hostname(hostname):
        raise ValidationError("Monitoring blocked: local, private, and metadata hosts are not allowed.")

    try:
        addrinfo = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValidationError("Monitoring target hostname could not be resolved.") from exc

    addresses = []
    for _family, _socktype, _proto, _canonname, sockaddr in addrinfo:
        ip_text = sockaddr[0]
        ip_obj = ipaddress.ip_address(ip_text)
        if is_blocked_ip(ip_obj):
            raise ValidationError("Monitoring blocked: resolved address is private, local, or reserved.")
        addresses.append(ip_text)

    if not addresses:
        raise ValidationError("Monitoring target hostname did not resolve to a public address.")

    return hostname, tuple(dict.fromkeys(addresses))
