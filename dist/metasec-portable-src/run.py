#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
绿色版 metasec 签名器 —— 解压即用，无需安装 Java / Maven / 联网。

它做什么：
  用【内置的 JRE】(jre/) 驱动【混淆后的 MetasecDump-obf.jar】+ unidbg 依赖(deps/)
  在本地模拟执行 libs/libmetasec_ml.so，对给定 url+body 生成 6 个番茄/抖音安全头：
      x-argus / x-gorgon / x-helios / x-khronos / x-ladon / x-medusa
  并把"请求 URL + body + 6 个签名头 + x-ss-stub + 完整请求头"写进 json。

支持两条接口（默认两条都跑）：
  * video_model (play)  —— 传 --video-id，取播放地址，输出 <video_id>.video_model.json
  * video_detail        —— 传 --series-id，取详情，输出 <series_id>.video_detail.json
                           （按抓包，video_detail 的 body 走 gzip + content-encoding: gzip）

用法（解压后在本目录运行）：
    python run.py                                   # 用默认 id，两条接口都离线生成 json
    python run.py --video-id 7650889194310470681 --series-id 7650887007270341694
    python run.py --api detail --series-id 7650887007270341694
    python run.py --api both --send                 # 额外用签名头真实 POST(需 httpx + 有效 cookie)

注意：
  * 默认【离线】只生成签名 json，不联网、不需要第三方库，一定能出 json。
  * --send 需要 `pip install "httpx[http2]" brotli`，且服务端 cookie 未过期才会返回有效数据。
  * 本目录结构不要改名：jre/  deps/  libs/  MetasecDump-obf.jar  都要在同一目录。
"""

import argparse
import gzip
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
PATH_PLAY = "/novel/player/video_model/v1/"
PATH_DETAIL = "/novel/player/video_detail/v1/"

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

# video_detail 抓包里固定的图片裁剪参数（base64，按原样保留，含换行）
_IMG_SHRINK = ("W3siaW1hZ2VfdHlwZSI6MywiaW1hZ2Vfd2lkdGgiOjEwNzgsInNocmlua190eXBlIjozfSx7Imlt"
               "\nYWdlX3R5cGUiOjQsImltYWdlX3dpZHRoIjo5OSwic2hyaW5rX3R5cGUiOjR9XQ==\n")


def build_url(path: str, rticket_ms: int) -> str:
    params = dict(QUERY_PARAMS)
    params["_rticket"] = str(rticket_ms)
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    return f"https://{HOST}{path}?{qs}"


def build_play_body(video_id: str) -> str:
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


def build_detail_body(series_id: str) -> str:
    body = {
        "biz_param": {
            "detail_page_version": 1, "disable_digg_stat": False,
            "disable_video_relate_book": False, "image_shrink_datas_str": _IMG_SHRINK,
            "need_all_video_definition": False, "need_mp4_align": False,
            "screen_width_px": "1078", "source": 5, "use_os_player": False,
            "use_server_dns": False, "video_id_type": 1,
        },
        "series_id": series_id,
    }
    return json.dumps(body, separators=(",", ":"))


def gen_trace_id() -> str:
    a = "%032x" % random.getrandbits(128)
    b = "%016x" % random.getrandbits(64)
    return f"00-{a}-{b}-01"


def run_harness(url: str, body: str, pump: int, tag: str) -> dict:
    """用内置 JRE 驱动混淆后的 jar，对 url+body 返回解析出的 6 个安全头。"""
    if not os.path.exists(OBF_JAR):
        raise RuntimeError("missing MetasecDump-obf.jar next to run.py")
    if not os.path.exists(SO_PATH):
        raise RuntimeError("missing libs/libmetasec_ml.so")

    url_file = os.path.join(HERE, f".req_url_{tag}.txt")
    body_file = os.path.join(HERE, f".req_body_{tag}.txt")
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
    print(f"[*] [{tag}] driving unidbg harness with bundled JRE (~3-6s) ...", flush=True)
    proc = subprocess.run(cmd, cwd=HERE, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=600)
    out = proc.stdout.decode("utf-8", "replace")
    line = None
    for ln in out.splitlines():
        if ln.startswith("__HEADERS_JSON__"):
            line = ln[len("__HEADERS_JSON__"):]
    if not line:
        sys.stderr.write(out[-3000:] + "\n")
        raise RuntimeError(f"[{tag}] harness did not emit __HEADERS_JSON__ (see log above)")
    headers = json.loads(line)
    return {k.lower(): v for k, v in headers.items()}


def assemble_headers(sec: dict, rticket_ms: int, body: str, gzip_body: bool):
    """组装完整请求头。x-ss-stub = md5(未压缩 body)；gzip_body=True 时加 content-encoding: gzip。"""
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
    ]
    if gzip_body:
        headers.append(("content-encoding", "gzip"))
    headers += [
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
    import io
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


def sign_one(api: str, path: str, body: str, ident_key: str, ident_val: str,
             pump: int, gzip_body: bool, send: bool, out_path: str):
    """对单条接口：生成签名头 -> 组装请求头 -> 写 json (-> 可选真实发送)。"""
    rticket_ms = int(time.time() * 1000)
    url = build_url(path, rticket_ms)
    sec = run_harness(url, body, pump, api)
    headers, stub = assemble_headers(sec, rticket_ms, body, gzip_body)

    result = {
        "api": api,
        ident_key: ident_val,
        "_rticket": rticket_ms,
        "url": url,
        "body": body,
        "content_encoding": "gzip" if gzip_body else None,
        "x-ss-stub": stub,
        "security_headers": {
            "x-argus": sec["x-argus"], "x-gorgon": sec["x-gorgon"],
            "x-helios": sec["x-helios"], "x-khronos": sec["x-khronos"],
            "x-ladon": sec["x-ladon"], "x-medusa": sec["x-medusa"],
        },
        "request_headers": dict(headers),
    }

    print(f"\n[*] [{api}] 6 security headers:")
    for k in ("x-argus", "x-gorgon", "x-helios", "x-khronos", "x-ladon", "x-medusa"):
        print(f"      {k}: {sec.get(k)}")

    if send:
        try:
            import httpx
        except ImportError:
            print("[!] --send 需要 httpx：pip install \"httpx[http2]\" brotli ；本次跳过发送。")
        else:
            content = gzip.compress(body.encode("utf-8")) if gzip_body else body.encode("utf-8")
            print(f"\n[*] [{api}] POST https://{HOST}{path} (HTTP/2"
                  f"{', gzip body' if gzip_body else ''}) ...", flush=True)
            with httpx.Client(http2=True, timeout=30, verify=True) as client:
                req = client.build_request("POST", url, headers=headers, content=content)
                resp = client.send(req)
            text = decode_response(resp.content)
            result["response"] = {
                "http_version": resp.http_version,
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": text,
            }
            print(f"[*] [{api}] HTTP {resp.http_version} status {resp.status_code}")
            print(f"[*] [{api}] response body (first 800 chars):")
            print(text[:800])

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"[+] [{api}] wrote {out_path}")
    return result


def main():
    ap = argparse.ArgumentParser(description="绿色版 metasec 签名器（video_model + video_detail）")
    ap.add_argument("--api", choices=["play", "detail", "both"], default="both",
                    help="跑哪条接口：play=video_model, detail=video_detail, both=两条都跑(默认)")
    ap.add_argument("--video-id", default="7650889194310470681", help="video_model(play) 的 video_id")
    ap.add_argument("--series-id", default="7650887007270341694", help="video_detail 的 series_id")
    ap.add_argument("--pump", type=int, default=2, help="worker 线程泵秒数(默认2)")
    ap.add_argument("--send", action="store_true",
                    help="额外用签名头真实 POST 到服务端(需要 httpx + 有效 cookie)")
    ap.add_argument("--out-play", default=None, help="play 输出 json 路径(默认 <video_id>.video_model.json)")
    ap.add_argument("--out-detail", default=None, help="detail 输出 json 路径(默认 <series_id>.video_detail.json)")
    args = ap.parse_args()

    print(f"[*] java      = {JAVA}")

    if args.api in ("play", "both"):
        print(f"[*] video_id  = {args.video_id}")
        out = args.out_play or os.path.join(HERE, f"{args.video_id}.video_model.json")
        sign_one("play", PATH_PLAY, build_play_body(args.video_id),
                 "video_id", args.video_id, args.pump, False, args.send, out)

    if args.api in ("detail", "both"):
        print(f"[*] series_id = {args.series_id}")
        out = args.out_detail or os.path.join(HERE, f"{args.series_id}.video_detail.json")
        sign_one("detail", PATH_DETAIL, build_detail_body(args.series_id),
                 "series_id", args.series_id, args.pump, True, args.send, out)


if __name__ == "__main__":
    main()
