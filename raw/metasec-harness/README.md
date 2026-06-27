# metasec-unidbg **full** — 开箱即用版（下载即可跑出 JSON）

这是一个**自包含**的目录：已经把打过补丁的 unidbg 全部依赖 jar 都打进了 `deps/`，
所以**不需要联网、不需要 maven、不需要自己编译 unidbg**。你只要装好 JDK8 和 Python，
直接运行 `orchestrate.py` 就能：

> 生成新鲜时间戳 → 用 unidbg 跑 `libmetasec_ml.so` 产出 6 个安全头
> → 按抓包 header 顺序拼出完整请求 → POST 到番茄真实接口 → 拿回 `video_model` 的 JSON。

产出的 6 个头：`X-Argus / X-Gorgon / X-Helios / X-Khronos / X-Ladon / X-Medusa`
（此接口/此版本 metasec 只产这 6 个，没有 x-perseus，和你抓包一致）。

---

## 目录结构

```
full/
├── deps/                 # 打过补丁的 unidbg + 全部依赖 jar（21 个，约 40MB）—— 已编译好，无需 maven
├── libs/
│   └── libmetasec_ml.so  # arm64-v8a 签名库
├── src/
│   └── MetasecDump.java  # 唯一的 harness 源码（运行时由 run.bat 自动编译）
├── orchestrate.py        # Python 端到端编排：生成→签名→发请求→判定
├── requirements.txt      # httpx[http2] + brotli
├── run.bat               # Windows：编译+运行 harness（被 orchestrate.py 调用）
├── run.sh                # Linux/macOS 同上
├── unidbg-patches.diff   # 仅供查阅：对 unidbg 基础库打的 4 处补丁（已编译进 deps/）
└── 总结.md               # 补环境踩坑全过程记录
```

---

## Windows 运行步骤（你要的）

### 0. 前置
- **JDK 8**（unidbg 必须 JDK8）。下载安装后记下它的 `bin` 路径，例如
  `C:\Program Files\Java\jdk1.8.0_401\bin`。
- **Python 3**（3.8+）。

### 1. 装 Python 依赖
```bat
cd full
pip install -r requirements.txt
```

### 2. 告诉脚本 JDK8 在哪
打开 `run.bat`，把第 11 行的 `JAVA8` 改成你的 JDK8 bin 目录：
```bat
if "%JAVA8%"=="" set JAVA8=C:\Program Files\Java\jdk1.8.0_401\bin
```
（如果你的 `java -version` 本来就是 1.8，可不改，脚本会自动回退到 PATH 上的 java。）

### 3. 一键跑通，拿 JSON
```bat
python orchestrate.py
```
约 1～2 分钟（unidbg 启动 + 跑签名）后，末尾会打印：
```
[*] HTTP HTTP/2 status 200
[*] response body (decoded, first 1500 chars):
{"BaseResp":{"StatusCode":0,"StatusMessage":"success"},"code":0,"data":{"video_model":"{...video_list...main_url...}", ...}}
============================================================
VERDICT: PASS - server returned video_model data. Signature accepted.
============================================================
```
看到 `VERDICT: PASS` 即表示签名被服务端接受、协议模拟成功，拿到了真实 `video_model` JSON。

### 常用参数
```bat
python orchestrate.py --video-id 7650889194310470681   :: 换 video_id
python orchestrate.py --no-send                        :: 只生成并打印 6 个头，不发请求
```

---

## 只想看 6 个头（不发网络请求）
直接跑 harness：
```bat
run.bat
```
输出里会有 6 行 `X-xxx = ...`，以及一行机器可解析的 `__HEADERS_JSON__{...}`。

复现历史抓包时刻（验证签名管线正确性）：
```bat
set FAKE_TIME=1782306314000
run.bat
```
此时 `X-Khronos = 1782306314`，与你抓包的参考值逐字节一致。

---

## Linux / macOS
```bash
cd full
pip install -r requirements.txt
export JAVA8=/usr/lib/jvm/java-8-openjdk-amd64/bin   # 改成你的 JDK8
python3 orchestrate.py
```

---

## 重要说明 / 注意事项

1. **headers 顺序**：HTTP/2 下 header 有顺序要求，`orchestrate.py` 严格按抓包顺序构造
   （cookie → 标准头 → x-argus…x-medusa），用 `httpx` 的 HTTP/2 客户端发送。
2. **cookie / 鉴权会过期**：脚本内置的 `odin_tt`、`passport_csrf_token` 等是抓包那台设备的会话
   凭据。如果它们过期，服务端可能即使签名正确也返回鉴权错误（与"签名错误"可从返回码区分）。
   如遇此情况，用你自己的新 cookie 替换 `orchestrate.py` 顶部的 `COOKIES`。
3. **每次值都不同是正常的**：x-gorgon / x-ladon / x-argus / x-medusa / x-helios 每次调用都带
   一次性随机 nonce，所以两次运行不会逐字节相同——这是 SDK 设计，属于"每次新鲜生成、服务端可验"。
   只有 x-khronos 是时间戳，钉死时钟时可精确复现。
4. **本项目只补环境，不分析/不实现任何 native 协议算法**；`libmetasec_ml.so` 原样使用，签名全部由它自己算。
5. 详细的补环境踩坑与解决思路见 **`总结.md`**。
