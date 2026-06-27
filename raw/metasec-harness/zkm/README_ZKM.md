# 用 ZKM 混淆保护 MetasecDump —— 使用说明

> 目标：只混淆 **MetasecDump（含其内部类）**，用 ZKM 的**控制流平坦化 + 字符串加密**把"代码逻辑"藏起来；unidbg 等开源依赖不动。混淆后仍能正常产出 6 个签名头。
>
> ✅ **已在本机用你给的 ZKM 24 实测通过**：成功混淆 11 个类，混淆后的 `MetasecDump-obf.jar` 用 dynarmic 后端运行，6 个签名头全部正常产出、退出码 0。

## ZKM 怎么知道混哪个 jar 的哪些类？（你问的关键）

靠脚本里两类语句区分：

- **`open "MetasecDump.jar";`** —— 这是"**要混淆的目标**"。ZKM 会把 open 进来的 jar 里的**所有类**都拿去混淆（除非被 `exclude`/`trimExclude` 排除）。
- **`classpath "...jar";`** —— 这些只是"**参考依赖**"，ZKM 只用它们**解析引用**（比如 MetasecDump 调用了 unidbg 的某方法，ZKM 要看得懂），**不会混淆、不会改名、也不会打进输出**。

> ⚠️ **两个实测踩到的坑（脚本里已修正）**：
> 1. **classpath 必须写成一条语句**：ZKM 的多条 `classpath` 语句是**互相覆盖**而不是追加，所以要用一条 `classpath "rt.jar" "deps/*.jar";`（多个引号串 + 通配符），否则只有最后一条生效，会报 `com.github.unidbg.Module not found`。
> 2. **3 个方法做不了控制流混淆**：`main` 和两个 VaList 版 JNI 分发方法在 aggressive/normal 下都会报 `Inconsistent stack heights / Stack mismatch`，脚本用 `obfuscateFlowExclude` 把它们排除在**控制流混淆**之外（它们仍会被**字符串加密**）；其余所有方法照常 aggressive 流混淆。

所以：**把要保护的类放进 `MetasecDump.jar` 并 `open` 它，把 unidbg/JNA/fastjson 放进 `classpath`** —— ZKM 就只混 MetasecDump。
本项目 MetasecDump 编译产物是 `MetasecDump.class` + 10 个内部类 `MetasecDump$BoolSup/$ByteSup/.../$VoidRun.class`（JNI 回调逻辑就在这些内部类里），`make-jar.bat` 会把它们全部打进 `MetasecDump.jar`。

## 三步走

```bat
REM 0) 先确认 full\build\ 下有用 JDK8 编出来的 MetasecDump.class（你现有流程已具备）

REM 1) 改脚本里的 rt.jar 路径：打开 zkm\script.zkm，把第一条 classpath 改成你本机
REM    JDK8 的 rt.jar，例如 "C:\Program Files\Java\jdk1.8.0_xxx\jre\lib\rt.jar"

REM 2) 一键混淆（会自动先打 jar 再跑 ZKM）：
zkm\run-zkm.bat  "C:\你的路径\ZKM.jar"
REM    产出 full\MetasecDump-obf.jar

REM 3) 验证混淆后仍能签名（产出 6 个头）：
zkm\verify.bat  "C:\你的JDK8\bin"
```

## 需要在 ZKM 里配置什么？

- **不需要在 ZKM GUI 里点任何东西。** 全部配置都在 `zkm\script.zkm` 里（命令行 `java -jar ZKM.jar zkm\script.zkm` 直接生效）。
- **唯一必须改**的是脚本第一条 `classpath` 的 **rt.jar 路径**（指向你本机 JDK8）。其余 deps 路径用相对 `deps\...`，从 `full\` 目录跑即可。
- license：把 ZKM 的授权文件按 Zelix 要求放好（通常放在 ZKM.jar 同目录或用 `-DZKM_...` 指定，按你 ZKM 24 的说明来）；脚本本身不涉及 license。

## 脚本里几个选项的含义

| 选项 | 作用 |
|---|---|
| `open "MetasecDump.jar"` | 指定**被混淆**的目标 jar |
| `classpath ...` | 仅供解析的依赖（**不混淆**） |
| `exclude class * { *; }` | 所有名字**不改名**（零破坏；不影响下面的流混淆/字符串加密） |
| `obfuscateFlow=aggressive` | **控制流平坦化**——ZKM 最强的逻辑保护，反编译后逻辑面目全非 |
| `encryptStringLiterals=flowObfuscate` | **字符串加密**（最强档，与流混淆绑定，运行时解密） |
| `exceptionObfuscation=heavy` | 异常表混淆，进一步干扰反编译器 |
| `lineNumbers=delete` / `localVariables=delete` | 删行号/局部变量名，断掉源码对应关系 |

## 为什么"不改名、只混逻辑+加密字符串"是最优解

MetasecDump 里很多东西会被 **JNI / 反射 / fastjson** 按名字找（比如内部类作为 JNI 回调、fastjson 序列化）。一旦改名，运行时按名查找就断了。
而你真正想保护的是**"代码逻辑"**——`obfuscateFlow`（控制流）和 `encryptStringLiterals`（字符串）恰好直接保护方法体逻辑与魔数/特征字符串，**与改名无关**。所以保留名字 + 激进流混淆 + 字符串加密 = **零运行风险 + 强逻辑保护**。

> 进阶（可选，风险自负）：若想更狠，可把 `exclude` 缩小到只保护"被 JNI/反射用到的名字"，让 ZKM 对**私有方法/字段改名**。但需要你逐一确认哪些名字被动态引用，否则可能运行期 `NoSuchMethod`。默认脚本不开这个，先求稳。

## 之后包成 exe（py 可调用，传 video_id 写 <video_id>.json）

混淆得到 `MetasecDump-obf.jar` 后，用免费的 **Launch4j** 或 **jpackage**（JDK14+）把 `MetasecDump-obf.jar + deps + 自带 JRE` 包成 `metasecdump.exe`，再由 py 调 `metasecdump.exe --video-id <id>` 写 `<video_id>.json`。这一步我可以接着帮你做（告诉我即可）。
