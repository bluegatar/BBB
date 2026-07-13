#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
绿色版 metasec 签名器 —— 解压即用，无需安装 Java / Maven / 联网。

它做什么：
  用【内置的 JRE】(jre/) 驱动【混淆后的 MetasecDump-obf.jar】+ unidbg 依赖(deps/)
  在本地模拟执行 libs/libmetasec_ml.so，对给定 url+body 生成 6 个番茄/抖音安全头：
      x-argus / x-gorgon / x-helios / x-khronos / x-ladon / x-medusa
  并把"请求 URL + body + 6 个签名头 + x-ss-stub + 完整请求头"写进 json。

两条接口（各对应一个命令，没有 both）：
  * -vid <video_id>   取 play(video_model)，输出 <video_id>.video_model.json
  * -sid <series_id>  取 detail(video_detail)，输出 <series_id>.video_detail.json

用法（解压后在本目录运行）：
    python run.py -vid 7650889194310470681          # play：签名并真实发送，写 json
    python run.py -sid 7650887007270341694          # detail：签名并真实发送，写 json
    python run.py -vid 7650889194310470681 -nosend  # 只本地生成签名 json，不发请求

注意：
  * 默认【会真实发送】(需 `pip install "httpx[http2]" brotli` 且 cookie 未过期)；
    没装 httpx 时会跳过发送但仍写出签名 json。想纯离线就加 -nosend。
  * 两条接口都按【明文 JSON body】发送 —— 抓包里 video_detail 的 content-encoding: gzip
    并非必需，实测带 gzip 反而被服务端判 110001「未知异常」，明文发送返回 200。
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

# 控制台默认编码(如 Windows 的 cp1252/gbk)可能无法输出中文，导致 print 抛 UnicodeEncodeError。
# 统一把 stdout/stderr 切到 utf-8 且对无法编码的字符做替换，确保任何分支的打印都不会中断流程。
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# --- 内置 JRE：优先用 jre/，没有就退回 PATH 上的 java ---
_JAVA = os.path.join(HERE, "jre", "bin", "java.exe" if IS_WINDOWS else "java")
JAVA = _JAVA if os.path.exists(_JAVA) else ("java.exe" if IS_WINDOWS else "java")

OBF_JAR = os.path.join(HERE, "MetasecDump-obf.jar")
DEPS_GLOB = os.path.join(HERE, "deps", "*")
SO_PATH = os.path.join(HERE, "libs", "libmetasec_ml.so")

HOST = "api5-normal-sinfonlinea.fqnovel.com"
PATH_PLAY = "/novel/player/video_model/v1/"
PATH_DETAIL = "/novel/player/video_detail/v1/"
PATH_SEARCH = "/reading/bookapi/search/tab/v"

# search 是 GET、无 body、无 x-ss-stub。下面是“全新搜索（点搜索按钮、第一页）”的 query 模板：
#   * {query}   = 本次搜索词(url-encoded)；由 build_search_url 填入
#   * {rticket} = 本次时间戳(ms)；由 build_search_url 填入
#   * last_search_page_query 留空(首次搜索)；offset=0、不带翻页/会话上下文(passback/last_book_id/
#     last_chapter_id/search_id/corrected_query 等)，所以每次都是干净的一次新搜索。
# query 串原样发送，签名按整串算。
_SEARCH_RAW_Q = (
    "bookshelf_search_plan=4&live_room_id=0&user_is_login=0&bookstore_tab=16"
    "&last_search_page_query=&clicked_content=page_search_button&report_info&use_lynx=false"
    "&tab_type=11&last_book_consume_time=0&product_id=0&line_words_num=0&tab_name=feed"
    "&last_consume_interval=0&pad_column_cover=0&only_feed=false&offset=0&from_rs=false"
    "&only_large_card=false&query={query}&count=0&search_source=1&search_source_id=clks%23%23%23"
    "&use_correct=false&last_search_page_interval=0&seed_product_id=0&from_half_screen=false"
    "&is_first_enter_search=false&iid=1518852408614281&device_id=1518852408610185"
    "&ac=wifi&channel=huawei_8662_64&aid=8662&app_name=novelread&version_code=72432"
    "&version_name=7.2.4.32&device_platform=android&os=android&ssmix=a&device_type=23076RA4BC"
    "&device_brand=Redmi&language=zh&os_api=33&os_version=13&manifest_version_code=72432"
    "&resolution=1080*2226&dpi=440&update_version_code=72432&_rticket={rticket}"
    "&normal_session_cnt_in_day=402&gender=2&cold_start_session_cnt_in_day=5&host_abi=arm64-v8a"
    "&dragon_device_type=phone&sys_mini_window=0&pv_player=72432&app_mini_window=0"
    "&normal_session_id=d0fe323e-1030-4dd8-a72f-11e141ce2c83%238&compliance_status=0&har_status=0"
    "&cold_start_session_id=cca83779-c82f-4366-afc0-1980fff6181c&cold_start_session_cnt_in_life=62"
    "&charging=0&normal_session_cnt_in_life=4337&is_power_save_mode=0&app_dark_mode=0"
    "&screen_brightness=1&battery_pct=0&down_speed=34538&sys_dark_mode=0&need_personal_recommend=1"
    "&player_so_load=1&font_scale=100&is_android_pad_screen=0&network_type=4"
    "&rom_version=miui_V140_V14.0.10.0.TMWEUXM&current_volume=1"
    "&cdid=6e297aec-fb86-48ed-98cc-289027ea46dd"
    "&client_ab_info=%7B%22middle_style_from_video%22%3Afalse%2C%22result_style_from_video%22%3Afalse%7D"
)

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


def build_search_url(keyword: str, rticket_ms: int, offset: int = 0, passback: str = "") -> str:
    from urllib.parse import quote
    kw = quote(keyword, safe="")
    q = _SEARCH_RAW_Q.format(query=kw, rticket=rticket_ms)
    if offset:
        q = q.replace("&offset=0&", f"&offset={offset}&")
    if passback:
        # 翻页时把 passback 游标补在 query 前面（与抓包顺序一致）
        q = q.replace("&query=", f"&passback={passback}&query=")
    return f"https://{HOST}{PATH_SEARCH}?{q}"


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


def assemble_headers(sec: dict, rticket_ms: int, body: str):
    """组装完整请求头。x-ss-stub = md5(body)。两条接口都按明文 body 发送(实测服务端接受;
    抓包里 video_detail 的 content-encoding: gzip 不是必需的, 反而会被服务端判 110001)。"""
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


def assemble_search_headers(sec: dict, rticket_ms: int):
    """search 是 GET：无 body / 无 x-ss-stub / 无 content-type，多一个空的 authorization: Bearer。"""
    req_ticket = str(rticket_ms + 8)
    reading_req = f"{req_ticket}-{random.randint(10**9, 2*10**9)}"
    cookie_value = "; ".join(f"{k}={v}" for k, v in COOKIES)
    return [
        ("cookie", cookie_value),
        ("accept", "application/json; charset=utf-8,application/x-protobuf"),
        ("x-xs-from-web", "0"), ("x-ss-req-ticket", req_ticket),
        ("x-reading-request", reading_req),
        ("x-vc-bdturing-sdk-version", "4.0.3.cn"),
        ("authorization", "Bearer "),
        ("lc", "101"), ("sdk-version", "2"), ("passport-sdk-version", "5051452"),
        ("x-tt-store-region", "cn-sc"), ("x-tt-store-region-src", "did"), ("x-ss-dp", "8662"),
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


def sign_one(api: str, method: str, url: str, rticket_ms: int, body: str,
             ident_key: str, ident_val: str, pump: int, send: bool, out_path: str,
             search: bool = False):
    """对单条接口：生成签名头 -> 组装请求头 -> 写 json (-> 默认真实发送)。
    search=True 时为 GET：无 body、无 x-ss-stub，用 search 专属请求头。"""
    sec = run_harness(url, body, pump, api)
    if search:
        headers = assemble_search_headers(sec, rticket_ms)
        stub = None
    else:
        headers, stub = assemble_headers(sec, rticket_ms, body)

    result = {
        "api": api,
        ident_key: ident_val,
        "_rticket": rticket_ms,
        "method": method,
        "url": url,
        "security_headers": {
            "x-argus": sec["x-argus"], "x-gorgon": sec["x-gorgon"],
            "x-helios": sec["x-helios"], "x-khronos": sec["x-khronos"],
            "x-ladon": sec["x-ladon"], "x-medusa": sec["x-medusa"],
        },
        "request_headers": dict(headers),
    }
    if not search:
        result["body"] = body
        result["x-ss-stub"] = stub

    print(f"\n[*] [{api}] 6 security headers:")
    for k in ("x-argus", "x-gorgon", "x-helios", "x-khronos", "x-ladon", "x-medusa"):
        print(f"      {k}: {sec.get(k)}")

    if send:
        try:
            import httpx
        except ImportError:
            print("[!] 发送需要 httpx：pip install \"httpx[http2]\" brotli ；本次跳过发送(json 已写出)。")
        else:
            print(f"\n[*] [{api}] {method} https://{HOST}{url.split(HOST,1)[-1].split('?',1)[0]} (HTTP/2) ...",
                  flush=True)
            with httpx.Client(http2=True, timeout=30, verify=True) as client:
                if method == "GET":
                    req = client.build_request("GET", url, headers=headers)
                else:
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
            print(f"[*] [{api}] HTTP {resp.http_version} status {resp.status_code}")
            print(f"[*] [{api}] response body (first 800 chars):")
            print(text[:800])

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"[+] [{api}] wrote {out_path}")
    return result


def _primary_tab(body: dict):
    """取响应里的主结果 tab（selected_tab_idx 指向的那个，通常是“综合”）。"""
    tabs = body.get("search_tabs") or []
    if not tabs:
        return {}
    idx = body.get("selected_tab_idx", 0) or 0
    return tabs[idx] if 0 <= idx < len(tabs) else tabs[0]


def _item_key(it: dict):
    return it.get("book_id") or it.get("search_result_id") or it.get("cell_id") or id(it)


def sign_search(keyword: str, pages: int, pump: int, send: bool, out_path: str):
    """search(GET)：默认 1 页(6 条)。pages>1 时按响应里的 next_offset/passback 逐页翻，
    把主 tab 的结果去重合并到 result.json 的 items；每页的原始请求/响应也保留在 pages 里。"""
    httpx = None
    if send:
        try:
            import httpx as _httpx
            httpx = _httpx
        except ImportError:
            print("[!] 发送需要 httpx：pip install \"httpx[http2]\" brotli ；本次跳过发送(只签第 1 页)。")

    page_records, items, seen = [], [], set()
    offset, passback = 0, ""
    fetched = 0

    for p in range(max(1, pages)):
        rt = int(time.time() * 1000)
        url = build_search_url(keyword, rt, offset, passback)
        sec = run_harness(url, "", pump, "search")
        headers = assemble_search_headers(sec, rt)
        rec = {
            "page": p, "offset": offset, "passback": passback,
            "_rticket": rt, "url": url,
            "security_headers": {k: sec[k] for k in
                ("x-argus", "x-gorgon", "x-helios", "x-khronos", "x-ladon", "x-medusa")},
            "request_headers": dict(headers),
        }
        print(f"\n[*] [search] page {p} offset={offset} -> 6 security headers ok")

        if not httpx:
            page_records.append(rec)
            break  # 离线/无 httpx：只能签第 1 页(翻页需要服务端响应里的游标)

        print(f"[*] [search] GET page {p} (HTTP/2) ...", flush=True)
        with httpx.Client(http2=True, timeout=30, verify=True) as client:
            resp = client.send(client.build_request("GET", url, headers=headers))
        text = decode_response(resp.content)
        rec["response"] = {"http_version": resp.http_version, "status": resp.status_code,
                           "headers": dict(resp.headers), "body": text}
        page_records.append(rec)
        fetched += 1

        try:
            body = json.loads(text)
        except Exception:
            print(f"[!] [search] page {p} 响应非 JSON，停止翻页"); break
        tab = _primary_tab(body)
        data = tab.get("data") or []
        for it in data:
            k = _item_key(it)
            if k not in seen:
                seen.add(k); items.append(it)
        print(f"[*] [search] page {p}: status {resp.status_code} 本页 {len(data)} 条, "
              f"累计 {len(items)} 条, has_more={tab.get('has_more')}")
        if not tab.get("has_more"):
            print("[*] [search] 服务端已无更多结果，停止翻页"); break
        offset = tab.get("next_offset", offset)
        passback = str(tab.get("passback", "") or "")

    result = {
        "api": "search", "query": keyword, "method": "GET",
        "pages_requested": pages, "pages_fetched": fetched,
        "total_items": len(items),
        "items": items,
        "pages": page_records,
    }
    # 顶层镜像第 1 页，兼容旧的 result.json 用法
    first = page_records[0]
    result["url"] = first["url"]
    result["security_headers"] = first["security_headers"]
    result["request_headers"] = first["request_headers"]
    if "response" in first:
        result["response"] = first["response"]

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"[+] [search] wrote {out_path}  (pages_fetched={fetched}, total_items={len(items)})")
    return result


def main():
    ap = argparse.ArgumentParser(
        description="绿色版 metasec 签名器：-vid 出 play(video_model)，-sid 出 detail(video_detail)，-search 出 search 结果(result.json)",
        usage="python run.py -vid <video_id> | -sid <series_id> | -search <关键词>   [-nosend] [-pump N]")
    ap.add_argument("-vid", dest="vid", default=None, help="video_model(play) 的 video_id，给了就出 <vid>.video_model.json")
    ap.add_argument("-sid", dest="sid", default=None, help="video_detail 的 series_id，给了就出 <sid>.video_detail.json")
    ap.add_argument("-search", dest="search", default=None, help="搜索关键词(GET search/tab/v)，给了就出 result.json")
    ap.add_argument("-pages", dest="pages", type=int, default=1, help="search 翻几页合并(默认1；每页约6~10条，需发送才能翻页)")
    ap.add_argument("-nosend", dest="nosend", action="store_true", help="只本地生成签名 json，不真实发请求（默认会发）")
    ap.add_argument("-pump", dest="pump", type=int, default=2, help="worker 线程泵秒数(默认2)")
    ap.add_argument("-out", dest="out", default=None, help="自定义输出 json 路径")
    args = ap.parse_args()

    if not args.vid and not args.sid and not args.search:
        ap.error("请用 -vid <video_id>(play) / -sid <series_id>(detail) / -search <关键词>(搜索)，至少给一个")

    send = not args.nosend
    print(f"[*] java = {JAVA}  send = {send}")

    if args.vid:
        print(f"[*] video_id  = {args.vid}")
        out = args.out or os.path.join(HERE, f"{args.vid}.video_model.json")
        rt = int(time.time() * 1000)
        sign_one("play", "POST", build_url(PATH_PLAY, rt), rt, build_play_body(args.vid),
                 "video_id", args.vid, args.pump, send, out)

    if args.sid:
        print(f"[*] series_id = {args.sid}")
        out = args.out or os.path.join(HERE, f"{args.sid}.video_detail.json")
        rt = int(time.time() * 1000)
        sign_one("detail", "POST", build_url(PATH_DETAIL, rt), rt, build_detail_body(args.sid),
                 "series_id", args.sid, args.pump, send, out)

    if args.search:
        print(f"[*] search    = {args.search}  pages = {args.pages}")
        out = args.out or os.path.join(HERE, "result.json")
        sign_search(args.search, args.pages, args.pump, send, out)


if __name__ == "__main__":
    main()
