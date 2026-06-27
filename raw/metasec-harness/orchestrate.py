#!/usr/bin/env python3
"""
End-to-end validator for the metasec_ml unidbg harness.

Flow:
  1. Generate fresh timestamps (_rticket / x-ss-req-ticket / x-reading-request /
     x-tt-trace-id) so the request is not replayed with a stale clock.
  2. Build the exact request URL (with the fresh _rticket) and body.
  3. Drive the unidbg harness (run.sh -> MetasecDump) to sign that URL+body,
     producing the 6 security headers (x-argus / x-gorgon / x-helios /
     x-khronos / x-ladon / x-medusa).
  4. Assemble the full HTTP/2 request in the captured header order and POST it
     to the real ByteDance endpoint.
  5. Print the response and judge whether the signature was accepted.

Usage:
    python3 orchestrate.py
    python3 orchestrate.py --video-id 7650889194310470681
    python3 orchestrate.py --no-send        # only generate + print headers
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

HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
IS_WINDOWS = platform.system().lower().startswith("win")
RUN_SCRIPT = os.path.join(HARNESS_DIR, "run.bat" if IS_WINDOWS else "run.sh")

HOST = "api5-normal-sinfonlinea.fqnovel.com"
PATH = "/novel/player/video_model/v1/"

# Device / app params captured from the real client (novelread 7.2.4.32).
QUERY_PARAMS = {
    "iid": "1518852408614281",
    "device_id": "1518852408610185",
    "ac": "wifi",
    "channel": "huawei_8662_64",
    "aid": "8662",
    "app_name": "novelread",
    "version_code": "72432",
    "version_name": "7.2.4.32",
    "device_platform": "android",
    "os": "android",
    "ssmix": "a",
    "device_type": "23076RA4BC",
    "device_brand": "Redmi",
    "language": "zh",
    "os_api": "33",
    "os_version": "13",
    "manifest_version_code": "72432",
    "resolution": "1080*2226",
    "dpi": "440",
    "update_version_code": "72432",
    "_rticket": None,  # filled with a fresh timestamp at runtime
    "host_abi": "arm64-v8a",
    "dragon_device_type": "phone",
    "pv_player": "72432",
    "compliance_status": "0",
    "need_personal_recommend": "1",
    "player_so_load": "1",
    "is_android_pad_screen": "0",
    "rom_version": "miui_V140_V14.0.10.0.TMWEUXM",
    "cdid": "6e297aec-fb86-48ed-98cc-289027ea46dd",
}

# Static cookies / auth captured from the real device session. These can expire
# independently of the signature; if so the server returns an auth error rather
# than a signature error.
COOKIES = [
    ("store-region", "cn-sc"),
    ("store-region-src", "did"),
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
    # Compact JSON with the exact key order the client uses (no spaces).
    body = {
        "biz_param": {
            "detail_page_version": 0,
            "device_level": 2,
            "disable_digg_stat": False,
            "disable_video_relate_book": False,
            "from_video_id": "",
            "need_all_video_definition": True,
            "need_mp4_align": False,
            "source": 4,
            "use_os_player": False,
            "use_server_dns": False,
            "video_platform": 3,
        },
        "content_type": 1004,
        "video_id": video_id,
    }
    return json.dumps(body, separators=(",", ":"))


def gen_trace_id() -> str:
    a = "%032x" % random.getrandbits(128)
    b = "%016x" % random.getrandbits(64)
    return f"00-{a}-{b}-01"


def run_harness(url: str, body: str) -> dict:
    """Drive the unidbg harness and return the parsed security headers."""
    url_file = os.path.join(HARNESS_DIR, ".req_url.txt")
    body_file = os.path.join(HARNESS_DIR, ".req_body.txt")
    with open(url_file, "w") as f:
        f.write(url)
    with open(body_file, "w") as f:
        f.write(body)

    env = dict(os.environ)
    # Do NOT set FAKE_TIME: we want the native code to use the real current
    # clock so x-khronos matches "now".
    env["JVM_OPTS"] = f"-Dreq.url.file={url_file} -Dreq.body.file={body_file}"

    if IS_WINDOWS:
        cmd = ["cmd", "/c", RUN_SCRIPT]
    else:
        cmd = ["bash", RUN_SCRIPT]

    print(f"[*] driving unidbg harness (this takes ~1-2 min) ...", flush=True)
    proc = subprocess.run(
        cmd,
        cwd=HARNESS_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=600,
    )
    out = proc.stdout.decode("utf-8", "replace")
    m = None
    for line in out.splitlines():
        if line.startswith("__HEADERS_JSON__"):
            m = line[len("__HEADERS_JSON__"):]
    if not m:
        sys.stderr.write(out[-3000:])
        raise RuntimeError("harness did not emit __HEADERS_JSON__ (see log above)")
    headers = json.loads(m)
    return {k.lower(): v for k, v in headers.items()}


def assemble_headers(sec: dict, rticket_ms: int, body: str) -> list:
    """Build the full header list in the captured order (HTTP/2)."""
    req_ticket = str(rticket_ms + 8)            # client sends ~ +8ms vs _rticket
    reading_req = f"{req_ticket}-{random.randint(10**9, 2*10**9)}"
    stub = hashlib.md5(body.encode("utf-8")).hexdigest().upper()

    cookie_value = "; ".join(f"{k}={v}" for k, v in COOKIES)

    headers = [
        ("cookie", cookie_value),
        ("accept", "application/json; charset=utf-8,application/x-protobuf"),
        ("x-xs-from-web", "0"),
        ("x-ss-req-ticket", req_ticket),
        ("x-reading-request", reading_req),
        ("x-vc-bdturing-sdk-version", "4.0.3.cn"),
        ("lc", "101"),
        ("sdk-version", "2"),
        ("passport-sdk-version", "5051452"),
        ("content-type", "application/json; charset=utf-8"),
        ("x-ss-stub", stub),
        ("x-tt-store-region", "cn-sc"),
        ("x-tt-store-region-src", "did"),
        ("x-ss-dp", "8662"),
        ("x-tt-trace-id", gen_trace_id()),
        ("user-agent",
         "com.phoenix.read/72432 (Linux; U; Android 13; zh_CN; 23076RA4BC; "
         "Build/TKQ1.221114.001; Cronet/TTNetVersion:04657795 2026-01-23 "
         "QuicVersion:c67e9834 2025-09-08)"),
        ("accept-encoding", "gzip, deflate, br"),
        ("x-argus", sec["x-argus"]),
        ("x-gorgon", sec["x-gorgon"]),
        ("x-helios", sec["x-helios"]),
        ("x-khronos", sec["x-khronos"]),
        ("x-ladon", sec["x-ladon"]),
        ("x-medusa", sec["x-medusa"]),
    ]
    return headers, stub


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--video-id", default="7650889194310470681")
    ap.add_argument("--no-send", action="store_true",
                    help="generate signature + print headers, do not POST")
    args = ap.parse_args()

    rticket_ms = int(time.time() * 1000)
    url = build_url(rticket_ms)
    body = build_body(args.video_id)

    print(f"[*] _rticket  = {rticket_ms}")
    print(f"[*] video_id  = {args.video_id}")
    print(f"[*] url       = {url}")
    print(f"[*] body      = {body}")

    sec = run_harness(url, body)
    print("\n[*] security headers from unidbg:")
    for k in ("x-argus", "x-gorgon", "x-helios", "x-khronos", "x-ladon", "x-medusa"):
        print(f"      {k}: {sec.get(k)}")

    headers, stub = assemble_headers(sec, rticket_ms, body)
    print(f"\n[*] x-ss-stub (md5 of body, upper) = {stub}")
    print(f"[*] x-khronos vs _rticket/1000     = {sec['x-khronos']} vs {rticket_ms // 1000}")

    if args.no_send:
        print("\n[*] --no-send: skipping the real request.")
        return

    import httpx
    print(f"\n[*] POST https://{HOST}{PATH} (HTTP/2) ...", flush=True)
    with httpx.Client(http2=True, timeout=30, verify=True) as client:
        req = client.build_request(
            "POST", url, headers=headers,
            content=body.encode("utf-8"),
        )
        resp = client.send(req)

    print(f"\n[*] HTTP {resp.http_version} status {resp.status_code}")
    print("[*] response headers:")
    for k, v in resp.headers.items():
        print(f"      {k}: {v}")

    raw = resp.content  # httpx already undoes gzip/deflate/br transport encoding
    with open(os.path.join(HARNESS_DIR, ".resp.bin"), "wb") as f:
        f.write(raw)

    text = decode_response(raw)
    print("\n[*] response body (decoded, first 1500 chars):")
    print(text[:1500])

    # Verdict
    verdict(resp.status_code, text)


def decode_response(raw: bytes) -> str:
    """Best-effort decode: utf-8 JSON, then brotli, then gzip, then replace.

    NOTE: the endpoint replies content-encoding: br (brotli). If the `brotli`
    package is installed, httpx already decompresses resp.content for us, so
    `raw` is plain JSON. This fallback handles the case where it isn't.
    """
    import gzip
    import io
    # try plain text / already-decompressed JSON
    try:
        s = raw.decode("utf-8")
        if s.lstrip().startswith("{"):
            return s
    except Exception:
        pass
    # try brotli
    try:
        import brotli
        return brotli.decompress(raw).decode("utf-8")
    except Exception:
        pass
    # try gzip
    try:
        return gzip.GzipFile(fileobj=io.BytesIO(raw)).read().decode("utf-8")
    except Exception:
        pass
    try:
        return raw.decode("utf-8", "replace")
    except Exception:
        return repr(raw[:1500])


def verdict(status: int, text: str):
    print("\n" + "=" * 60)
    try:
        j = json.loads(text)
    except Exception:
        j = None
    code = None
    if isinstance(j, dict):
        code = j.get("code", j.get("Code"))
    if status == 200 and isinstance(j, dict) and "data" in j and j.get("data"):
        print("VERDICT: PASS - server returned video_model data. Signature accepted.")
    elif code in (0,):
        print("VERDICT: PASS - server returned code 0.")
    elif code is not None:
        # Map a few known buckets
        msg = j.get("message", j.get("Message", ""))
        print(f"VERDICT: server rejected. code={code} message={msg!r}")
        print("         (110001 'unknown error' = malformed/empty; other codes "
              "usually mean signature or auth/cookie rejection)")
    else:
        print(f"VERDICT: unclear. status={status}")
    print("=" * 60)


if __name__ == "__main__":
    main()
