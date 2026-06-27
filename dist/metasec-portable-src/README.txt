============================================================
 绿色版 metasec 签名器（解压即用，内置 JRE，无需装 Java）
============================================================

【这是什么】
  对给定的 video_id，在本地用 unidbg 模拟执行 libmetasec_ml.so，
  生成番茄/抖音的 6 个安全头(x-argus/x-gorgon/x-helios/x-khronos/
  x-ladon/x-medusa)，并把结果写入  <video_id>.json 。
  核心 Java(MetasecDump) 已用 ZKM 做了【控制流平坦化 + 字符串加密】
  混淆 —— 反编译(jadx 等)看到的是被打散的状态机和加密字符串，
  逆向难度很高。

【目录结构 —— 不要改名、不要拆开】
  metasec-portable/
  ├─ run.py                 ← 你运行的入口
  ├─ MetasecDump-obf.jar    ← 混淆后的签名 harness
  ├─ jre/                   ← 内置 JDK8 运行时(green, 不依赖系统 Java)
  ├─ deps/                  ← unidbg / jna / fastjson 等依赖 jar
  ├─ libs/libmetasec_ml.so  ← 被模拟执行的原生库(算法黑盒)
  └─ README.txt

【怎么用】（在本目录下打开终端）
  1) 离线生成签名 json（默认，最稳，不联网/不需要第三方库）：
        python run.py --video-id 7650889194310470681
     → 生成 7650889194310470681.json（含 url/body + 6 个签名头 + x-ss-stub）

  2) 不带参数 = 用内置默认 video_id：
        python run.py

  3) 额外真实发请求到服务端，把服务端响应也写进 json：
        pip install "httpx[http2]" brotli
        python run.py --video-id 7650889194310470681 --send
     注意：--send 需要服务端 cookie 未过期才会返回有效数据；
           cookie 在 run.py 顶部 COOKIES 里，过期就自行替换。

  4) 其它可选参数：
        --pump N     worker 线程泵秒数(默认 2；偶发出错可调到 3)
        --out PATH   自定义输出 json 路径

【对 Python 的要求】
  * 只用到标准库，Python 3.7+ 即可；离线模式无需 pip 安装任何东西。
  * 只有 --send 真实发请求时才需要 httpx / brotli。
  * Java 不用装：脚本自动用本目录 jre/bin/java。

【常见问题】
  * "did not emit __HEADERS_JSON__"：多半是目录被拆散/改名，确认
    jre、deps、libs、MetasecDump-obf.jar 都在 run.py 同级目录。
  * 速度：每次约 3~6 秒（瓶颈是 native 指令模拟 + 2 秒线程泵，属正常）。
  * 杀软误报 .so/.dll：unidbg 会把后端 dll 解压到临时目录加载，属正常行为。
============================================================
