#!/usr/bin/env python3
# filter.py —— 在 GitHub Actions 里跑：拉源 -> 解析 -> TCP 预筛 -> mihomo 真连接测 -> 输出
# 不依赖任何 Windows 组件，只吃 mihomo 可执行文件（由 workflow 下载到仓库根目录）
import base64
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

WORK = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get("OUT_DIR") or os.path.dirname(WORK)
os.makedirs(ROOT, exist_ok=True)
OUT_LINKS = os.path.join(ROOT, "live-links.txt")
OUT_SUB = os.path.join(ROOT, "live-sub.txt")
STATE = os.environ.get("STATE_DIR") or WORK
POOL = os.path.join(STATE, "pool.txt")
REPORT = os.path.join(STATE, "report.txt")
MIXED_PORT = 17899
API_PORT = 19090

TCP_TIMEOUT = 2.0
DELAY_TIMEOUT = 5000
TEST_URL = "https://www.gstatic.com/generate_204"
MAX_WORKERS = 64
API_WORKERS = 24
MAX_PROXIES = 1200

SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "rc4-md5", "chacha20-ietf", "xchacha20",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-ccm", "aes-256-ccm", "aes-128-gcm-siv", "aes-256-gcm-siv",
    "none",
}


def log(msg):
    print(time.strftime("[%H:%M:%S] ") + str(msg), flush=True)


def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "ignore")


def qs(query):
    out = {}
    for part in query.split("&"):
        if not part:
            continue
        k, _, v = part.partition("=")
        out[urllib.parse.unquote(k)] = urllib.parse.unquote(v)
    return out


def split_link(link, scheme):
    body = link[len(scheme) + 3:]
    frag = ""
    if "#" in body:
        body, frag = body.split("#", 1)
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    return body, qs(query), urllib.parse.unquote(frag)


def split_hostport(hp):
    if hp.startswith("["):
        host, _, port = hp.rpartition("]:")
        return host.lstrip("["), int(port) if port.isdigit() else 0
    host, _, port = hp.rpartition(":")
    return host, int(port) if port.isdigit() else 0


def parse_ss(link):
    body, query, frag = split_link(link, "ss")
    if "@" not in body:
        try:
            body = b64d(body)
        except Exception:
            return None
    if "@" not in body:
        return None
    userinfo, hp = body.rsplit("@", 1)
    if ":" in userinfo:
        method, password = userinfo.split(":", 1)
    else:
        try:
            dec = b64d(userinfo)
        except Exception:
            return None
        if ":" not in dec:
            return None
        method, password = dec.split(":", 1)
    host, port = split_hostport(hp)
    if not host or not port:
        return None
    if method not in SS_CIPHERS:
        return None
    if query.get("plugin"):
        return None
    p = {"name": "", "type": "ss", "server": host, "port": port,
         "cipher": method, "password": password, "udp": True}
    p["name"], p["_label"] = "", frag
    return p


def parse_vmess(link):
    body, _, frag = split_link(link, "vmess")
    try:
        cfg = json.loads(b64d(body))
    except Exception:
        return None
    host = str(cfg.get("add", "")).strip()
    port = int(str(cfg.get("port", "0")).strip() or 0)
    if not host or not port:
        return None
    net = str(cfg.get("net", "tcp")) or "tcp"
    tls = str(cfg.get("tls", "")) == "tls"
    p = {"name": "", "type": "vmess", "server": host, "port": port,
         "uuid": cfg.get("id", ""), "alterId": int(cfg.get("aid", 0) or 0),
         "cipher": "auto", "udp": True, "network": net}
    if not p["uuid"]:
        return None
    if tls:
        p["tls"] = True
        sni = str(cfg.get("sni", "") or cfg.get("host", "")).strip()
        if sni:
            p["servername"] = sni
        p["skip-cert-verify"] = True
    if net == "ws":
        p["ws-opts"] = {
            "path": str(cfg.get("path", "/") or "/"),
            "headers": {"Host": str(cfg.get("host", "") or host)},
        }
    elif net == "grpc":
        p["grpc-opts"] = {"grpc-service-name": str(cfg.get("path", "") or "")}
    p["name"], p["_label"] = "", frag
    return p


def parse_vless(link):
    body, query, frag = split_link(link, "vless")
    if "@" not in body:
        return None
    uuid, hp = body.rsplit("@", 1)
    host, port = split_hostport(hp)
    if not host or not port or not uuid:
        return None
    sec = query.get("security", "")
    net = query.get("type", "tcp") or "tcp"
    p = {"name": "", "type": "vless", "server": host, "port": port,
         "uuid": uuid, "udp": True, "network": net}
    if query.get("flow"):
        p["flow"] = query["flow"]
    if sec in ("tls", "reality"):
        p["tls"] = True
        sni = query.get("sni", "") or query.get("host", "")
        if sni:
            p["servername"] = sni
        p["skip-cert-verify"] = True
        if query.get("fp"):
            p["client-fingerprint"] = query["fp"]
        if sec == "reality":
            p["reality-opts"] = {"public-key": query.get("pbk", ""),
                                 "short-id": query.get("sid", "")}
            if not p["reality-opts"]["public-key"]:
                return None
    if net == "ws":
        p["ws-opts"] = {"path": query.get("path", "/") or "/",
                        "headers": {"Host": query.get("host", "") or host}}
    elif net == "grpc":
        p["grpc-opts"] = {"grpc-service-name": query.get("serviceName", "") or ""}
    elif net == "xhttp":
        return None
    p["name"], p["_label"] = "", frag
    return p


def parse_trojan(link, scheme="trojan"):
    body, query, frag = split_link(link, scheme)
    if "@" not in body:
        return None
    password, hp = body.rsplit("@", 1)
    host, port = split_hostport(hp)
    if not host or not port or not password:
        return None
    p = {"name": "", "type": scheme, "server": host, "port": port,
         "password": password, "udp": True, "skip-cert-verify": True}
    sni = query.get("sni", "") or query.get("peer", "")
    if sni:
        p["sni"] = sni
    p["name"], p["_label"] = "", frag
    return p


def parse_anytls(link):
    return parse_trojan(link, "anytls")


def parse_hy2(link):
    body, query, frag = split_link(link, "hysteria2")
    if "@" not in body:
        return None
    password, hp = body.rsplit("@", 1)
    host, port = split_hostport(hp)
    if not host or not port or not password:
        return None
    p = {"name": "", "type": "hysteria2", "server": host, "port": port,
         "password": password, "udp": True, "skip-cert-verify": True}
    sni = query.get("sni", "")
    if sni:
        p["sni"] = sni
    if query.get("obfs"):
        if not query.get("obfs-password"):
            return None
        p["obfs"] = query["obfs"]
        p["obfs-password"] = query["obfs-password"]
    p["name"], p["_label"] = "", frag
    return p


PARSERS = {
    "ss": parse_ss, "vmess": parse_vmess, "vless": parse_vless,
    "trojan": parse_trojan, "anytls": parse_anytls,
    "hysteria2": parse_hy2, "hy2": parse_hy2,
}


def fetch(url):
    for attempt, u in enumerate([url, url.replace("cdn.jsdelivr.net", "fastly.jsdelivr.net")]):
        try:
            req = urllib.request.Request(u, headers={
                "User-Agent": "Mozilla/5.0 auto-filter",
                "Accept": "*/*",
            })
            with urllib.request.urlopen(req, timeout=25) as r:
                raw = r.read()
            text = raw.decode("utf-8", "ignore")
            if "://" not in text:
                try:
                    text = b64d(text)
                except Exception:
                    pass
            return [x.strip() for x in text.splitlines() if "://" in x]
        except Exception as e:
            if attempt == 0:
                continue
            log("  拉取失败: %s (%s)" % (url, e))
    return []


def tcp_ok(server, port):
    try:
        with socket.create_connection((server, port), timeout=TCP_TIMEOUT):
            return True
    except Exception:
        return False


def main():
    with open(os.path.join(WORK, "sources.txt"), encoding="utf-8") as f:
        sources = [x.strip() for x in f if x.strip() and not x.startswith("#")]

    raw = []
    if os.path.exists(POOL):
        with open(POOL, encoding="utf-8") as f:
            got = [x.strip() for x in f if "://" in x]
        raw.extend(got)
        log("+%d <- 历史池 pool.txt" % len(got))
    for u in sources:
        got = fetch(u)
        raw.extend(got)
        log("+%d <- %s" % (len(got), u))

    seen = set()
    links = []
    for l in raw:
        key = l.split("#")[0]
        if key in seen:
            continue
        seen.add(key)
        links.append(l)
    log("去重后: %d 条" % len(links))

    meta = []
    sig = set()
    for l in links:
        if len(meta) >= MAX_PROXIES:
            break
        scheme = l.split("://")[0].lower()
        fn = PARSERS.get(scheme)
        if not fn:
            continue
        try:
            p = fn(l)
        except Exception:
            p = None
        if not p:
            continue
        s = "%s|%s|%s" % (p["type"], p["server"], p["port"])
        if s in sig:
            continue
        sig.add(s)
        p["_raw"] = l
        meta.append(p)
    log("解析成功: %d 个" % len(meta))

    log("第一级：TCP 预筛 %d 个..." % len(meta))
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        flags = list(ex.map(lambda p: tcp_ok(p["server"], p["port"]), meta))
    alive = [p for p, ok in zip(meta, flags) if ok]
    log("TCP 通过: %d / %d" % (len(alive), len(meta)))
    if not alive:
        log("一个都没过，退出")
        sys.exit(1)

    for i, p in enumerate(alive):
        p["name"] = "n%d" % i

    cfg = {
        "mixed-port": MIXED_PORT,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "silent",
        "ipv6": False,
        "external-controller": "127.0.0.1:%d" % API_PORT,
        "proxies": [{k: v for k, v in p.items() if not k.startswith("_")} for p in alive],
        "proxy-groups": [{"name": "AUTO", "type": "select",
                          "proxies": [p["name"] for p in alive]}],
        "rules": ["MATCH,AUTO"],
    }
    cfg_path = os.path.join(WORK, "config.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False)

    mihomo = os.path.join(ROOT, "mihomo")
    if not os.path.exists(mihomo):
        log("找不到 mihomo 可执行文件: %s" % mihomo)
        sys.exit(1)

    test = subprocess.run([mihomo, "-d", WORK, "-f", cfg_path, "-t"],
                          capture_output=True, text=True)
    if test.returncode != 0:
        log("配置校验失败: " + (test.stderr or "")[:400])
        bad = set()
        for m in re.finditer(r"proxy (\d+):", test.stderr or ""):
            idx = int(m.group(1))
            if 0 <= idx < len(alive):
                bad.add(idx)
        if not bad:
            sys.exit(1)
        alive = [p for i, p in enumerate(alive) if i not in bad]
        log("剔除非法配置 %d 个，剩 %d 个，重新校验" % (len(bad), len(alive)))
        cfg["proxies"] = [{k: v for k, v in p.items() if not k.startswith("_")} for p in alive]
        cfg["proxy-groups"][0]["proxies"] = [p["name"] for p in alive]
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False)

    log("第二级：启动 mihomo 测真连接...")
    proc = subprocess.Popen([mihomo, "-d", WORK, "-f", cfg_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ready = False
    for _ in range(60):
        time.sleep(0.5)
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/version" % API_PORT, timeout=2) as r:
                if json.loads(r.read()).get("version"):
                    ready = True
                    break
        except Exception:
            pass
    if not ready:
        proc.kill()
        log("mihomo 起不来")
        sys.exit(1)
    log("内核就绪")

    want = urllib.parse.quote(TEST_URL, safe="")
    results = []

    def probe(p):
        u = "http://127.0.0.1:%d/proxies/%s/delay?timeout=%d&url=%s" % (
            API_PORT, p["name"], DELAY_TIMEOUT, want)
        try:
            with urllib.request.urlopen(u, timeout=DELAY_TIMEOUT / 1000.0 + 8) as r:
                d = json.loads(r.read()).get("delay", 0)
                if d and int(d) > 0:
                    return (p, int(d))
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=API_WORKERS) as ex:
        for res in ex.map(probe, alive):
            if res:
                results.append(res)

    proc.kill()
    log("真连接可用: %d / %d" % (len(results), len(alive)))
    if not results:
        log("本轮 0 个可用，保留上一版文件不覆盖")
        sys.exit(1)

    results.sort(key=lambda x: x[1])

    def clean(p):
        v = p["_raw"].split("#")[0]
        v = v.replace("?&", "?").replace("&&", "&").rstrip("&")
        return v + "#" + (p.get("_label") or ("%s:%s" % (p["server"], p["port"])))

    out = [clean(p) for p, _ in results]
    with open(OUT_LINKS, "w", encoding="utf-8", newline="\r\n") as f:
        f.write("\n".join(out))
    b64 = base64.b64encode("\n".join(out).encode("utf-8")).decode()
    with open(OUT_SUB, "w", encoding="utf-8") as f:
        f.write(b64)

    pool = []
    pseen = set()
    for l in out + ([x.strip() for x in open(POOL, encoding="utf-8")] if os.path.exists(POOL) else []):
        k = l.split("#")[0]
        if "://" in l and k not in pseen:
            pseen.add(k)
            pool.append(l)
    with open(POOL, "w", encoding="utf-8") as f:
        f.write("\n".join(pool[:500]))

    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("时间 %s\n共 %d 个源条目，解析 %d，TCP 通过 %d，真连接可用 %d\n\n" % (
            time.strftime("%Y-%m-%d %H:%M:%S"), len(links), len(meta), len(alive), len(results)))
        for p, d in results:
            f.write("%6d ms  %-8s %s:%s\n" % (d, p["type"], p["server"], p["port"]))

    log("结果: 解析 %d，TCP %d，可用 %d，历史池 %d" % (len(meta), len(alive), len(results), len(pool)))
    for p, d in results[:20]:
        log("  %6d ms  %-8s %s:%s" % (d, p["type"], p["server"], p["port"]))


if __name__ == "__main__":
    main()