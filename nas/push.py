#!/usr/bin/env python3
# push.py —— 把 out/ 里的文件推到 GitHub 仓库，手机继续走 jsDelivr
# 配置文件 /app/state/github.txt：
#   token=ghp_xxx
#   owner=qq1183160989
#   repo=sub
#   path=live-links.txt
import base64
import json
import os
import sys
import urllib.error
import urllib.request

OUT = os.environ.get("OUT_DIR", "/app/out")
STATE = os.environ.get("STATE_DIR", "/app/state")
CFG = os.path.join(STATE, "github.txt")


def log(m):
    print("[push] " + str(m), flush=True)


def api(url, token, method="GET", body=None):
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "token " + token)
    req.add_header("User-Agent", "auto-live-sub")
    req.add_header("Accept", "application/vnd.github+json")
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or b"{}")


def push(conf, local_name, remote_path):
    token = conf["token"]
    owner = conf["owner"]
    repo = conf["repo"]
    fp = os.path.join(OUT, local_name)
    if not os.path.exists(fp):
        log("跳过，文件不存在: " + fp)
        return False
    text = open(fp, encoding="utf-8").read().strip()
    if len(text) < 10:
        log("跳过，内容为空: " + local_name)
        return False
    base = "https://api.github.com/repos/%s/%s/contents/%s" % (owner, repo, remote_path)
    sha = None
    try:
        sha = api(base + "?ref=main", token).get("sha")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            log("取 sha 失败 %s: %s" % (local_name, e.code))
            return False
    body = {
        "message": "auto: %s (%d bytes)" % (local_name, len(text)),
        "content": base64.b64encode(text.encode()).decode(),
        "branch": "main",
    }
    if sha:
        body["sha"] = sha
    try:
        r = api(base, token, "PUT", body)
        log("上传成功 %s -> %s commit=%s" % (local_name, remote_path, str(r.get("commit", {}).get("sha", ""))[:7]))
        return True
    except urllib.error.HTTPError as e:
        log("上传失败 %s: %s %s" % (local_name, e.code, e.read()[:200]))
        return False


def main():
    if not os.path.exists(CFG):
        log("没有 %s，跳过推送（只用本地 HTTP 服务）" % CFG)
        return
    conf = {}
    for line in open(CFG, encoding="utf-8"):
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            conf[k.strip().lower()] = v.strip()
    if not all(conf.get(k) for k in ("token", "owner", "repo")):
        log("github.txt 不全，至少要有 token / owner / repo")
        return
    ok = 0
    if push(conf, "live-links.txt", conf.get("path") or "live-links.txt"):
        ok += 1
    if push(conf, "live-sub.txt", "live-sub.txt"):
        ok += 1
    log("完成 %d/2" % ok)


if __name__ == "__main__":
    main()