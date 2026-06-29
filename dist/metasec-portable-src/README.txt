============================================================
 绿色版 metasec 签名器（解压即用，内置 JRE，无需装 Java）
============================================================

【这是什么】
  在本地用 unidbg 模拟执行 libmetasec_ml.so，生成番茄/抖音的 6 个安全头
  (x-argus/x-gorgon/x-helios/x-khronos/x-ladon/x-medusa)，并把结果写成 json。
  三条接口，各对应一个命令（没有 both）：
    * -vid <video_id>    取 play(video_model)，POST，输出 <video_id>.video_model.json
    * -sid <series_id>   取 detail(video_detail)，POST，输出 <series_id>.video_detail.json
    * -search <关键词>   取 search(search/tab/v)，GET，输出 result.json
  核心 Java(MetasecDump) 已用 ZKM 做了【控制流平坦化 + 异常混淆 + 字符串加密】
  混淆 —— 反编译(jadx 等)看到的是被打散的状态机和加密字符串，逆向难度很高。

【目录结构 —— 不要改名、不要拆开】
  metasec-portable/
  ├─ run.py                 ← 你运行的入口(-vid play / -sid detail / -search 搜索)
  ├─ MetasecDump-obf.jar    ← 混淆后的签名 harness
  ├─ jre/                   ← 内置 JDK8 运行时(green, 不依赖系统 Java)
  ├─ deps/                  ← unidbg / jna / fastjson 等依赖 jar
  ├─ libs/libmetasec_ml.so  ← 被模拟执行的原生库(算法黑盒)
  └─ README.txt

【怎么用】（在本目录下打开终端）
  1) 取 play 的 json（默认会真实发请求并把响应写进 json）：
        python run.py -vid 7650889194310470681
     → 7650889194310470681.video_model.json

  2) 取 detail 的 json：
        python run.py -sid 7650887007270341694
     → 7650887007270341694.video_detail.json

  3) 取 search 的 json（GET，关键词带空格/中文请用引号包起来）：
        python run.py -search "家里家外2"
     → result.json

  4) 只本地生成签名 json、不发请求（纯离线，不需第三方库）：
        python run.py -vid 7650889194310470681 -nosend
        python run.py -sid 7650887007270341694 -nosend
        python run.py -search "家里家外2" -nosend

  5) 其它可选参数：
        -pump N     worker 线程泵秒数(默认 2；偶发出错可调到 3)
        -out PATH   自定义输出 json 路径

  POST 接口(-vid/-sid)的 json 含：url / body / x-ss-stub / 6 个签名头 / request_headers；
  GET 接口(-search)的 json 含：method / url / 6 个签名头 / request_headers(无 body、
  无 x-ss-stub、无 content-type，多一个空的 authorization: Bearer)。
  默认发送成功时还会多一个 response 字段(服务端返回的数据)。

【对 Python 的要求】
  * 默认会真实发送，需：pip install "httpx[http2]" brotli（且 cookie 未过期）。
    没装 httpx 也不报错：会跳过发送但仍写出签名 json；想纯离线就加 -nosend。
  * cookie 在 run.py 顶部 COOKIES 里，过期就自行替换。
  * Python 3.7+；Java 不用装，脚本自动用本目录 jre/bin/java。
  * 两条接口都按明文 JSON body 发送；抓包里 video_detail 的 content-encoding: gzip
    实测会被服务端判 110001「未知异常」，明文发送才返回 200。

【常见问题】
  * "did not emit __HEADERS_JSON__"：多半是目录被拆散/改名，确认
    jre、deps、libs、MetasecDump-obf.jar 都在 run.py 同级目录。
  * 速度：每次约 3~6 秒（瓶颈是 native 指令模拟 + 2 秒线程泵，属正常）。
  * 杀软误报 .so/.dll：unidbg 会把后端 dll 解压到临时目录加载，属正常行为。
============================================================
