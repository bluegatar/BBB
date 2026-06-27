import subprocess, re, os, sys

full = "C:/Users/Administrator/repos/BBB/full"
rt   = "C:/Program Files/Eclipse Adoptium/jdk-8.0.472.8-hotspot/jre/lib/rt.jar"
java = "C:/Program Files/Eclipse Adoptium/jdk-8.0.472.8-hotspot/bin/java.exe"
zkm  = "C:/Users/Administrator/tools/zkm/ZKM24.jar"

excludes = []  # list of method signatures "name(paramtypes)" to exclude from FLOW

def build(flow):
    L = ['classpath "%s"' % rt,
         '          "%s/deps/*.jar";' % full,
         'open "%s/MetasecDump.jar";' % full,
         'exclude * and', '        * * and', '        * *(*);']
    for sig in excludes:
        L.append('obfuscateFlowExclude * %s;' % sig)
    L += ['obfuscate',
          '    obfuscateFlow         = %s' % flow,
          '    encryptStringLiterals = flowObfuscate',
          '    lineNumbers           = delete',
          '    localVariables        = delete',
          '    ;',
          'saveAll "%s/MetasecDump-obf.jar";' % full]
    p = full + "/zkm/_solve.zkm"
    open(p, "w", encoding="utf-8").write("\n".join(L) + "\n")
    return p

# error format: Method '<name>(<params>)' in class '...MetasecDump.class' appears to be invalid
rx = re.compile(r"Method '([^']+)' in class '[^']*MetasecDump\.class' appears to be invalid")

flow = sys.argv[1] if len(sys.argv) > 1 else "aggressive"
for it in range(60):
    try:
        os.remove(full + "/MetasecDump-obf.jar")
    except OSError:
        pass
    sp = build(flow)
    out = subprocess.run([java, "-jar", zkm, sp], capture_output=True, text=True)
    log = out.stdout + out.stderr
    if os.path.exists(full + "/MetasecDump-obf.jar"):
        print("SUCCESS after excluding %d methods (flow=%s):" % (len(excludes), flow))
        for s in excludes:
            print("   ", s)
        sys.exit(0)
    m = rx.search(log)
    if not m:
        print("FAILED, no parseable method. Last log tail:")
        print(log[-1500:])
        sys.exit(1)
    sig = m.group(1)
    # convert "ret name(params)"? error gives "name(params)" already w/o return type
    if sig in excludes:
        print("Re-reported same method, stuck:", sig)
        print(log[-1200:])
        sys.exit(1)
    excludes.append(sig)
    print("[%d] excluding from flow: %s" % (it + 1, sig))
print("Too many iterations")
sys.exit(1)
