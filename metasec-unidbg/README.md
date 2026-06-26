# metasec-unidbg — 用 unidbg 模拟 libmetasec_ml.so 产出请求签名参数

对给定的请求（URL + body），通过 unidbg 加载番茄小说 / novelread 7.2.4.32（aid=8662）的
`libmetasec_ml.so`（ByteDance Argus / metasec SDK），产出以下 6 个安全头：

```
X-Argus  X-Gorgon  X-Helios  X-Khronos  X-Ladon  X-Medusa
```

> 说明：你抓包的那条真实请求里也只有这 6 个头（没有 `x-perseus`）。`x-perseus` 不是这个接口、
> 这版 `libmetasec_ml.so` 经 `getFeatureHash` 产出的，所以这里产 6 个即为完整。

本项目**只补环境、不实现/不分析任何 native 协议算法**。签名完全由 `libmetasec_ml.so` 自己计算，
harness 仅负责：加载 .so、应答它的 JNI/环境回调、按 SDK 的初始化顺序把它驱动起来、再调用签名入口。

---

## 一、原理（为什么需要这些改动）

1. **anti-emulation**：这版库检测到模拟器后，会拒绝在 worker 线程里用 `RegisterNatives` 注册签名
   分发函数 `ms/bd/c/y2.a`。我们用静态反汇编定位到它的 JNI trampoline 偏移 **`base + 0x26e684`**，
   在 harness 里用反射直接写进 `DvmClass.nativesMap`，绕过被拦截的自注册（见 `MetasecDump.registerNative`）。
2. **signal 混淆**：worker 线程用 `tgkill(self, SIGRTxx)` 给自己发信号做反调试，unidbg 还原上下文有 bug
   会崩。补丁让 `unidbg.tgkill.drop=true` 时静默丢弃自发信号。
3. **GetSuperClass(java/lang/Object)**：native 调用此 JNI 时 unidbg 抛异常，补丁改为按规范返回 NULL(0)。
4. **环境变量**：`n3.java` 静态初始化会读一个环境变量，补丁在 ELF 环境里加 `28d7fdd567361198183fa7b8e=a7`。
5. **可钉时钟（仅用于验证）**：补丁支持 `unidbg.fake.time.ms` 固定模拟器时钟，用来复现历史抓包时刻。

签名入口与调用链（取自反编译的 Java SDK，`com.bytedance.mobsec.metasec.core.*`）：

| 步骤 | y2.a cmd            | 含义 |
|------|---------------------|------|
| 1    | `16777219`          | context init (`g.c`) |
| 2    | `67108865`          | 注册 config（`toNativeValue()` JSON 数组），返回 true |
| 3    | `67108866`          | 取 handle，返回 Long |
| 4    | `33554434/33554435` | setDeviceID / setInstallID |
| 5    | `33554438`          | **getFeatureHash(url, body)** → 返回 `String[]`（key/value 交替），即 6 个安全头 |

（App 侧对应 `NsCommonDependImpl.getSecHeader(z, url, body)` → `MSManager.getFeatureHash`。）

---

## 二、改动文件清单（只给变动的，不含 unidbg 基础文件）

```
metasec-unidbg/
├── src/MetasecDump.java     # 主 harness（唯一新写的代码）
├── unidbg-patches.diff      # 对 unidbg 基础库的 4 处小补丁（统一 diff）
├── run.sh                   # Linux/macOS 运行脚本
├── run.bat                  # Windows 运行脚本
└── README.md
```

`unidbg-patches.diff` 改动的 3 个 unidbg 文件：
- `unidbg-android/.../linux/AndroidSyscallHandler.java`（tgkill 丢弃 + 可钉时钟）
- `unidbg-android/.../linux/AndroidElfLoader.java`（加环境变量）
- `unidbg-android/.../linux/android/dvm/DalvikVM64.java`（GetSuperClass 返回 NULL）

---

## 三、在 Windows 上运行（生成 7 参数）

### 0. 准备
- 安装 **JDK 8**（unidbg 推荐 JDK8；jadx 反编译另说）。确认 `java -version` 显示 1.8。
- 安装 **Git**。
- 准备好 **`libmetasec_ml.so`（arm64-v8a）**，放到 `metasec-unidbg\libs\libmetasec_ml.so`。

### 1. 拉取并打补丁、编译 unidbg
```bat
git clone https://github.com/zhkl0228/unidbg.git
cd unidbg
:: 应用本仓库的补丁（在 unidbg 根目录执行）
git apply ..\AAAtest\metasec-unidbg\unidbg-patches.diff
:: 用自带 maven wrapper 编译安装到本地 .m2（跳过测试）
mvnw.cmd -pl unidbg-android -am install -DskipTests
cd ..
```

### 2. 组装 classpath
用 maven 把 unidbg-android 的依赖导出成一行 classpath：
```bat
cd unidbg
mvnw.cmd -q -pl unidbg-android dependency:build-classpath -Dmdep.outputFile=..\cp.txt
cd ..
:: 再把 unidbg-android 自己的 jar 也加进去
:: （路径形如 unidbg\unidbg-android\target\unidbg-android-0.9.10-SNAPSHOT.jar）
```
最终 classpath = `unidbg\unidbg-android\target\unidbg-android-<版本>.jar;<cp.txt 内容>`。
`run.bat` 已自动拼好，无需手动操作。

### 3. 编译并运行 harness
进入 `AAAtest\metasec-unidbg`，确认 `libs\libmetasec_ml.so` 已就位，然后：
```bat
run.bat
```
脚本会编译 `src\MetasecDump.java` 并运行，最后打印 6 个头。

> `run.bat` 里有两个变量需按你机器改：`UNIDBG_DIR`（unidbg 仓库路径）和 `JAVA8`（JDK8 路径）。

### 修改请求
要换 `video_id` 或换请求，编辑 `src/MetasecDump.java` 末尾 `main` 里的 `url` 和 `body` 两个字符串
（已默认填好 video_id=7650889194310470681 的那条），重新 `run.bat` 即可。

---

## 四、示例输出

默认用**当前系统时间**签名（真实使用就该如此，每次都是新鲜可验的值）：
```
[init] context init done
[init] config register (0x4000001) => true
[init] handle (0x4000002) => 309998016
[init] device/install id set
[sign] String[] length=12
   "X-Argus"   = "DLY+ag=="
   "X-Gorgon"  = "8404a0f00810942e2663f37834ed07eab4f84a4861fd248d7bfb"
   "X-Helios"  = "/7J0Midp75inauZSxxs2KRTpeq4XxUvZUeaOy9DyWc69HpRg"
   "X-Khronos" = "1782494732"
   "X-Ladon"   = "Noj+Cg=="
   "X-Medusa"  = "CbY+aiH9caBFwzMpMwOQRi7b8jzfYwABisqvByQpAaAG....(略)"
```

### 正确性验证（复现历史抓包的 X-Khronos）
把时钟钉到抓包时刻（参考请求 `x-khronos=1782306314`）：
```bat
set FAKE_TIME=1782306314000
run.bat
```
输出里 `X-Khronos = 1782306314`，与参考抓包**逐字节一致**，证明签名管线确实在真跑、时间输入正确。

> 其余 5 个头（gorgon/ladon/argus/medusa/helios）每次调用都包含一次性随机 nonce、且依赖设备注册态，
> **不会**和历史抓包逐字节相同（同一台机器连跑两次它们也都不同）——这是 SDK 的设计，属于"每次新鲜生成、
> 服务端可验"的值，不影响请求被接受。

---

## 五、Linux/macOS 运行
```bash
# 1) clone + patch + build unidbg（同上，命令换成 ./mvnw）
# 2) 把 libmetasec_ml.so 放到 metasec-unidbg/libs/
# 3) 编辑 run.sh 顶部的 UNIDBG_DIR / JAVA8，然后：
./run.sh
# 复现历史时刻：
FAKE_TIME=1782306314000 ./run.sh
```
