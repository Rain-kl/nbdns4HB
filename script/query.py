import requests, dns.message, base64, sys

DOH_URL, AUTH = "http://localhost:8854/dns-query", ("user", "password")


def query(domain, qtype="HTTPS"):
    q = dns.message.make_query(domain, qtype)
    enc = base64.urlsafe_b64encode(q.to_wire()).decode().rstrip("=")
    r = requests.get(
        f"{DOH_URL}?dns={enc}", headers={"Accept": "application/dns-message"}, auth=AUTH
    )
    return dns.message.from_wire(r.content) if r.status_code == 200 else None


def check(domain):
    print(f"\n{'='*60}\n{domain}")
    resp = query(domain)
    if not resp or not resp.answer:
        print("❌ 无 HTTPS 记录")
        return False

    for ans in resp.answer:
        print(f"TTL: {ans.ttl}s")
        for rd in ans:
            print(f"优先级: {rd.priority}, 目标: {rd.target}")
            if hasattr(rd, "params"):
                for k, v in rd.params.items():
                    if k == 5:  # ECH
                        eb = v.ech if hasattr(v, "ech") else v
                        print(
                            f"✅ ECH ({len(eb)}字节): {base64.b64encode(eb).decode()[:50]}..."
                        )
                        return True
                    elif k == 1:  # ALPN
                        alpn_list = v.alpn if hasattr(v, "alpn") else []
                        alpn_str = ", ".join(
                            [
                                a.decode("utf-8") if isinstance(a, bytes) else a
                                for a in alpn_list
                            ]
                        )
                        print(f"ALPN: {alpn_str}")
                    elif k == 4:  # IPv4Hint
                        ipv4_list = v.addresses if hasattr(v, "addresses") else []
                        print(f"IPv4: {', '.join(ipv4_list)}")
                    elif k == 6:  # IPv6Hint
                        ipv6_list = v.addresses if hasattr(v, "addresses") else []
                        print(f"IPv6: {', '.join(ipv6_list)}")
    print("❌ 无 ECH")
    return False


if __name__ == "__main__":
    domains = sys.argv[1:] or ["linux.do"]
    results = [(d, check(d)) for d in domains]
    print(f"\n{'='*60}\n✅ {sum(r for _,r in results)}/{len(results)} 支持 ECH")
    for d, r in results:
        print(f"  {'✅' if r else '❌'} {d}")
