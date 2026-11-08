from __future__ import annotations


def decode_client_fqdn(value) -> str:
    """Decode DHCP Option 81 (Client FQDN / RFC 4702)."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip().rstrip(".")
    raw = bytes(value)
    if len(raw) <= 3:
        return ""
    name = raw[3:]
    if raw[0] & 0x04:
        labels = []
        offset = 0
        while offset < len(name):
            length = name[offset]
            if length == 0:
                break
            offset += 1
            if length > 63 or offset + length > len(name):
                return ""
            labels.append(name[offset:offset + length].decode("utf-8", errors="ignore"))
            offset += length
        return ".".join(part for part in labels if part).rstrip(".")
    return name.decode("utf-8", errors="ignore").strip().rstrip(".\x00")


def extract_hostname(dhcp_opts) -> tuple[str, str]:
    """Option 12 has priority; Option 81 is the fallback."""
    hostname = dhcp_opts.get("hostname")
    if hostname:
        if isinstance(hostname, bytes):
            hostname = hostname.decode("utf-8", errors="ignore")
        hostname = str(hostname).strip().rstrip(".\x00")
        if hostname:
            return hostname, "option12"
    for key in ("client_FQDN", "client-fqdn", "fqdn", 81):
        if key in dhcp_opts:
            hostname = decode_client_fqdn(dhcp_opts[key])
            if hostname:
                return hostname, "option81"
    return "", "none"

