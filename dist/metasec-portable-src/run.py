#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
绿色版 metasec 签名器 —— 解压即用，无需安装 Java / Maven / 联网。

它做什么：
  1. 用【内置的 JRE】(jre/) 驱动【混淆后的 MetasecDump-obf.jar】+ unidbg 依赖(deps/)
     在本地模拟执行 libs/libmetasec_ml.so，对给定 video_id 生成 6 个抖音/番茄安全头：
        x-argus / x-gorgon / x-helios / x-khronos / x-ladon / x-medusa
  2. 把"请求 URL + body + 6 个签名头 + x-ss-stub"等结果写入  <video_id>.json 。
  3. (可选) 加 --send 还会用这些头真实 POST 到番茄服务端，并把服务端响应一起写进 json。

用法（解压后在本目录运行）：
    python run.py                              # 用默认 video_id，离线生成签名 json
    python run.py --video-id 7650889194310470681
    python run.py --video-id 7650889194310470681 --send   # 额外发真实请求(需要 httpx + 有效 cookie)

注意：
  * 默认【离线】只生成签名 json，不联网、不需要第三方库，一定能出 <video_id>.json。
  * --send 需要 `pip install httpx[http2] brotli`，且服务端 cookie 未过期才会返回有效数据。
  * 本目录结构不要改名：jre/  deps/  libs/  MetasecDump-obf.jar  都要在同一目录。
"""

import argparse
import hashlib
import json
import os
import platform
import random
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
IS_WINDOWS = platform.system().lower().startswith("win")

# --- 内置 JRE：优先用 jre/，没有就退回 PATH 上的 java ---
_JAVA = os.path.join(HERE, "jre", "bin", "java.exe" if IS_WINDOWS else "java")
JAVA = _JAVA if os.path.exists(_JAVA) else ("java.exe" if IS_WINDOWS else "java")

OBF_JAR = os.path.join(HERE, "MetasecDump-obf.jar")
DEPS_GLOB = os.path.join(HERE, "deps", "*")
SO_PATH = os.path.join(HERE, "libs", "libmetasec_ml.so")

HOST = "api5-normal-sinfonlinea.fqnovel.com"
PATH = "/novel/player/video_model/v1/"

QUERY_PARAMS = {
    "iid": "1518852408614281", "device_id": "1518852408610185", "ac": "wifi",
    "channel": "huawei_8662_64", "aid": "8662", "app_name": "novelread",
    "version_code": "72432", "version_name": "7.2.4.32", "device_platform": "android",
    "os": "android", "ssmix": "a", "device_type": "23076RA4BC", "device_brand": "Redmi",
    "language": "zh", "os_api": "33", "os_version": "13", "manifest_version_code": "72432",
    "resolution": "1080*2226", "dpi": "440", "update_version_code": "72432",
    "_rticket": None, "host_abi": "arm64-v8a", "dragon_device_type": "phone",
    "pv_player": "72432", "compliance_status": "0", "need_personal_recommend": "1",
    "player_so_load": "1", "is_android_pad_screen": "0",
    "rom_version": "miui_V140_V14.0.10.0.TMWEUXM",
    "cdid": "6e297aec-fb86-48ed-98cc-289027ea46dd",
}

COOKIES = [
    ("store-region", "cn-sc"), ("store-region-src", "did"),
    ("install_id", "1518852408614281"),
    ("ttreq", "1$34f316b05b09f62be953e935766735fb815add21"),
    ("passport_csrf_token", "aedcb83ef8a84e650306aac6f8b47181"),
    ("passport_csrf_token_default", "aedcb83ef8a84e650306aac6f8b47181"),
    ("odin_tt", "156fb9222805404f83145902e224fd1c018f60e5635f0cfde8a6448017125ca0"
                "97ea102131f79b8fd82573d3c5cf2670b90283d71b64c3e5529ba3b263fe2119"
                "9072d7e4c3239d9c184edfc34a0e9139"),
]


def build_url(rticket_ms: int) -> str:
    params = dict(QUERY_PARAMS)
    params["_rticket"] = str(rticket_ms)
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    return f"https://{HOST}{PATH}?{qs}"


def build_body(video_id: str) -> str:
    body = {
        "biz_param": {
            "detail_page_version": 0, "device_level": 2, "disable_digg_stat": False,
            "disable_video_relate_book": False, "from_video_id": "",
            "need_all_video_definition": True, "need_mp4_align": False, "source": 4,
            "use_os_player": False, "use_server_dns": False, "video_platform": 3,
        },
        "content_type": 1004, "video_id": video_id,
    }
    return json.dumps(body, separators=(",", ":"))


def gen_trace_id() -> str:
    a = "%032x" % random.getrandbits(128)
    b = "%016x" % random.getrandbits(64)
    return f"00-{a}-{b}-01"


def run_harness(url: str, body: str, pump: int) -> dict:
    """用内置 JRE 驱动混淆后的 jar，返回解析出的 6 个安全头。"""
    if not os.path.exists(OBF_JAR):
        raise RuntimeError("missing MetasecDump-obf.jar next to run.py")
    if not os.path.exists(SO_PATH):
        raise RuntimeError("missing libs/libmetasec_ml.so")

    url_file = os.path.join(HERE, ".req_url.txt")
    body_file = os.path.join(HERE, ".req_body.txt")
    with open(url_file, "w", encoding="utf-8") as f:
        f.write(url)
    with open(body_file, "w", encoding="utf-8") as f:
        f.write(body)

    sep = ";" if IS_WINDOWS else ":"
    classpath = OBF_JAR + sep + DEPS_GLOB
    cmd = [
        JAVA,
        "-Dunidbg.tgkill.drop=true",
        "-Dbackend=dynarmic",
        f"-Dpump.seconds={pump}",
        f"-Dreq.url.file={url_file}",
        f"-Dreq.body.file={body_file}",
        "-cp", classpath,
        "MetasecDump",
    ]
    print("[*] driving unidbg harness with bundled JRE (~3-6s) ...", flush=True)
    proc = subprocess.run(cmd, cwd=HERE, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=600)
    out = proc.stdout.decode("utf-8", "replace")
    line = None
    for ln in out.splitlines():
        if ln.startswith("__HEADERS_JSON__"):
            line = ln[len("__HEADERS_JSON__"):]
    if not line:
        sys.stderr.write(out[-3000:] + "\n")
        raise RuntimeError("harness did not emit __HEADERS_JSON__ (see log above)")
    headers = json.loads(line)
    return {k.lower(): v for k, v in headers.items()}


def assemble_headers(sec: dict, rticket_ms: int, body: str):
    req_ticket = str(rticket_ms + 8)
    reading_req = f"{req_ticket}-{random.randint(10**9, 2*10**9)}"
    stub = hashlib.md5(body.encode("utf-8")).hexdigest().upper()
    cookie_value = "; ".join(f"{k}={v}" for k, v in COOKIES)
    headers = [
        ("cookie", cookie_value),
        ("accept", "application/json; charset=utf-8,application/x-protobuf"),
        ("x-xs-from-web", "0"), ("x-ss-req-ticket", req_ticket),
        ("x-reading-request", reading_req),
        ("x-vc-bdturing-sdk-version", "4.0.3.cn"), ("lc", "101"), ("sdk-version", "2"),
        ("passport-sdk-version", "5051452"),
        ("content-type", "application/json; charset=utf-8"),
        ("x-ss-stub", stub), ("x-tt-store-region", "cn-sc"),
        ("x-tt-store-region-src", "did"), ("x-ss-dp", "8662"),
        ("x-tt-trace-id", gen_trace_id()),
        ("user-agent",
         "com.phoenix.read/72432 (Linux; U; Android 13; zh_CN; 23076RA4BC; "
         "Build/TKQ1.221114.001; Cronet/TTNetVersion:04657795 2026-01-23 "
         "QuicVersion:c67e9834 2025-09-08)"),
        ("accept-encoding", "gzip, deflate, br"),
        ("x-argus", sec["x-argus"]), ("x-gorgon", sec["x-gorgon"]),
        ("x-helios", sec["x-helios"]), ("x-khronos", sec["x-khronos"]),
        ("x-ladon", sec["x-ladon"]), ("x-medusa", sec["x-medusa"]),
    ]
    return headers, stub


def decode_response(raw: bytes) -> str:
    import gzip, io
    try:
        s = raw.decode("utf-8")
        if s.lstrip().startswith("{"):
            return s
    except Exception:
        pass
    try:
        import brotli
        return brotli.decompress(raw).decode("utf-8")
    except Exception:
        pass
    try:
        return gzip.GzipFile(fileobj=io.BytesIO(raw)).read().decode("utf-8")
    except Exception:
        pass
    return raw.decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser(description="绿色版 metasec 签名器")
    ap.add_argument("--video-id", default="7650889194310470681")
    ap.add_argument("--pump", type=int, default=2, help="worker 线程泵秒数(默认2)")
    ap.add_argument("--send", action="store_true",
                    help="额外用签名头真实 POST 到服务端(需要 httpx + 有效 cookie)")
    ap.add_argument("--out", default=None, help="输出 json 路径(默认 <video_id>.json)")
    args = ap.parse_args()

    rticket_ms = int(time.time() * 1000)
    url = build_url(rticket_ms)
    body = build_body(args.video_id)
    out_path = args.out or os.path.join(HERE, f"{args.video_id}.json")

    print(f"[*] java     = {JAVA}")
    print(f"[*] video_id = {args.video_id}")

    sec = run_harness(url, body, args.pump)
    headers, stub = assemble_headers(sec, rticket_ms, body)

    result = {
        "video_id": args.video_id,
        "_rticket": rticket_ms,
        "url": url,
        "body": body,
        "x-ss-stub": stub,
        "security_headers": {
            "x-argus": sec["x-argus"], "x-gorgon": sec["x-gorgon"],
            "x-helios": sec["x-helios"], "x-khronos": sec["x-khronos"],
            "x-ladon": sec["x-ladon"], "x-medusa": sec["x-medusa"],
        },
        "request_headers": dict(headers),
    }

    print("\n[*] 6 security headers:")
    for k in ("x-argus", "x-gorgon", "x-helios", "x-khronos", "x-ladon", "x-medusa"):
        print(f"      {k}: {sec.get(k)}")

    if args.send:
        try:
            import httpx
        except ImportError:
            print("[!] --send 需要 httpx：pip install \"httpx[http2]\" brotli ；本次跳过发送。")
        else:
            print(f"\n[*] POST https://{HOST}{PATH} (HTTP/2) ...", flush=True)
            with httpx.Client(http2=True, timeout=30, verify=True) as client:
                req = client.build_request("POST", url, headers=headers,
                                           content=body.encode("utf-8"))
                resp = client.send(req)
            text = decode_response(resp.content)
            result["response"] = {
                "http_version": resp.http_version,
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": text,
            }
            print(f"[*] HTTP {resp.http_version} status {resp.status_code}")
            print("[*] response body (first 800 chars):")
            print(text[:800])

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n[+] wrote {out_path}")


if __name__ == "__main__":
    main()
