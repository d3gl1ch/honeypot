# офлайн-обогащение ip: страна, asn, провайдер и ptr
import ipaddress
import socket
from collections import Counter

# небольшой справочник подсетей, для семестровой хватает
_ROWS = [
    ("185.10.1.0/24", "RU", "AS49505", "Selectel"),
    ("45.33.2.0/24", "US", "AS63949", "Linode"),
    ("103.77.4.0/24", "SG", "AS13335", "Cloudflare"),
    ("91.200.8.0/24", "UA", "AS200000", "Example Hosting"),
    ("194.5.6.0/24", "NL", "AS60781", "LeaseWeb"),
]
_NETWORKS = [(ipaddress.ip_network(net), country, asn, org)
             for net, country, asn, org in _ROWS]
UNKNOWN = {"country": "??", "asn": "-", "org": "unknown"}


def lookup(ip):
    # ищем ip в справочнике подсетей
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return dict(UNKNOWN)
    for net, country, asn, org in _NETWORKS:
        if addr in net:
            return {"country": country, "asn": asn, "org": org}
    return dict(UNKNOWN)


def reverse_dns(ip, resolver=socket.gethostbyaddr):
    # ptr-запись, по умолчанию через системный резолвер
    try:
        host, _, _ = resolver(ip)
        return host
    except OSError:
        return ""


def enrich_ip(ip, dns=False):
    data = lookup(ip)
    data["ptr"] = reverse_dns(ip) if dns else ""
    return data


def enrich_events(events, dns=False):
    # добавляем поле enrich в копии событий
    cache = {}
    for e in events:
        ip = e.get("src_ip", "")
        if ip not in cache:
            cache[ip] = enrich_ip(ip, dns)
        item = dict(e)
        item["enrich"] = cache[ip]
        yield item


def count_by(events, field="country", dns=False):
    # сколько событий пришло из каждой страны/провайдера
    return Counter(e["enrich"][field] for e in enrich_events(events, dns))
