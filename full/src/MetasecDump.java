import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.VaList;
import com.github.unidbg.linux.android.dvm.wrapper.DvmLong;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.util.Map;

/**
 * Environment-supplement harness for libmetasec_ml.so.
 * native -> Java callbacks all arrive via MS.b(cmd,i2,j,str,obj); we answer the
 * environment queries (mirroring ms.bd.c.u2.a) so the native registers y2.a and
 * proceeds. No native protocol logic is implemented here.
 */
public class MetasecDump extends AbstractJni {

    private final VM vm;
    private MetasecDump(VM vm) { this.vm = vm; }

    private DvmObject<?> dispatch(int cmd, int a2, long a3, DvmObject<?> str, DvmObject<?> obj) {
        switch (cmd) {
            case 268435470: // GetABSwitch
                return DvmLong.valueOf(vm, Long.getLong("ab", 2L));
            case 268435471: // GetDelayTime
                return DvmLong.valueOf(vm, 0L);
            case 268435458:
            case 268435459:
                return new StringObject(vm, "np");
            case 268435461:
                return new StringObject(vm, "");
            case 268435463:
                return new StringObject(vm, "[]");
            case 268435464:
                return new StringObject(vm, "null[<!>]null[<!>]0[<!>]");
            default:
                return null;
        }
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "android/content/Context->getPackageName()Ljava/lang/String;":
                return new StringObject(vm, "com.phoenix.read");
            case "android/content/Context->getApplicationContext()Landroid/content/Context;":
                return dvmObject;
            case "android/content/Context->getContentResolver()Landroid/content/ContentResolver;":
                return vm.resolveClass("android/content/ContentResolver").newObject(null);
            case "android/content/Context->getPackageManager()Landroid/content/pm/PackageManager;":
                return vm.resolveClass("android/content/pm/PackageManager").newObject(null);
            case "android/content/Context->getFilesDir()Ljava/io/File;":
                return vm.resolveClass("java/io/File").newObject("/data/data/com.phoenix.read/files");
            case "android/content/Context->getCacheDir()Ljava/io/File;":
                return vm.resolveClass("java/io/File").newObject("/data/data/com.phoenix.read/cache");
            case "java/io/File->getAbsolutePath()Ljava/lang/String;":
            case "java/io/File->getCanonicalPath()Ljava/lang/String;":
                return new StringObject(vm, (String) dvmObject.getValue());
            case "android/content/Context->getSystemService(Ljava/lang/String;)Ljava/lang/Object;": {
                // device fingerprinting fetches managers (audio, window, ...); return a
                // non-null stub object so the subsequent method calls have a receiver.
                String svc = vaList.getObjectArg(0) == null ? "" : String.valueOf(vaList.getObjectArg(0).getValue());
                String cls;
                switch (svc) {
                    case "audio":     cls = "android/media/AudioManager"; break;
                    case "window":    cls = "android/view/WindowManager"; break;
                    case "phone":     cls = "android/telephony/TelephonyManager"; break;
                    case "wifi":      cls = "android/net/wifi/WifiManager"; break;
                    case "activity":  cls = "android/app/ActivityManager"; break;
                    case "sensor":    cls = "android/hardware/SensorManager"; break;
                    case "power":     cls = "android/os/PowerManager"; break;
                    case "connectivity": cls = "android/net/ConnectivityManager"; break;
                    default:          cls = "java/lang/Object"; break;
                }
                return vm.resolveClass(cls).newObject(null);
            }
            default:
                return stubObject(vm, signature, () -> super.callObjectMethodV(vm, dvmObject, signature, vaList));
        }
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        // device-fingerprint instance int getters (audio volumes etc.) -> plausible defaults
        switch (signature) {
            case "android/media/AudioManager->getStreamVolume(I)I":    return 7;
            case "android/media/AudioManager->getStreamMaxVolume(I)I": return 15;
            case "android/media/AudioManager->getStreamMinVolume(I)I": return 0;
            case "android/media/AudioManager->getRingerMode()I":       return 2; // RINGER_MODE_NORMAL
            case "android/media/AudioManager->getMode()I":             return 0; // MODE_NORMAL
        }
        return stubInt(signature, () -> super.callIntMethodV(vm, dvmObject, signature, vaList));
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        return stubBool(signature, () -> super.callBooleanMethodV(vm, dvmObject, signature, vaList));
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        return stubInt(signature, () -> super.getIntField(vm, dvmObject, signature));
    }

    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if ("java/lang/Long->longValue()J".equals(signature)) {
            return ((Number) dvmObject.getValue()).longValue();
        }
        try {
            return super.callLongMethodV(vm, dvmObject, signature, vaList);
        } catch (UnsupportedOperationException e) {
            System.out.println("[stub] callLongMethodV " + signature + " -> 0");
            return 0L;
        }
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        System.out.println("[callStaticVoid] " + signature);
        // MS.a()V / i2.Louis()V / i2.Zeoy()V are init/ready callbacks from the native
        // worker threads; they are empty on the Java side, so just return.
        if (signature.startsWith("com/bytedance/mobsec/metasec/ml/MS->")
                || signature.startsWith("ms/bd/c/")) {
            return;
        }
        try {
            super.callStaticVoidMethodV(vm, dvmClass, signature, vaList);
        } catch (UnsupportedOperationException e) {
            System.out.println("[stub] callStaticVoidMethodV " + signature + " -> noop");
        }
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        // native boxes primitives via JNI on the autobox helpers
        if ("java/lang/Boolean->valueOf(Z)Ljava/lang/Boolean;".equals(signature)) {
            return com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean.valueOf(vm, vaList.getIntArg(0) != 0);
        }
        if ("java/lang/Integer->valueOf(I)Ljava/lang/Integer;".equals(signature)) {
            return com.github.unidbg.linux.android.dvm.wrapper.DvmInteger.valueOf(vm, vaList.getIntArg(0));
        }
        if ("java/lang/Long->valueOf(J)Ljava/lang/Long;".equals(signature)) {
            return DvmLong.valueOf(vm, vaList.getLongArg(0));
        }
        if ("java/lang/System->getProperty(Ljava/lang/String;)Ljava/lang/String;".equals(signature)) {
            String key = (String) vaList.getObjectArg(0).getValue();
            String val;
            switch (key) {
                case "os.arch":        val = "aarch64"; break;
                case "os.version":     val = "4.14.180"; break;
                case "os.name":        val = "Linux"; break;
                case "java.vm.version":val = "2.1.0"; break;
                case "http.agent":     val = "Dalvik/2.1.0 (Linux; U; Android 13; 23076RA4BC Build/TKQ1.221114.001)"; break;
                default:               val = ""; break;
            }
            System.out.println("[System.getProperty] " + key + " => " + val);
            return new StringObject(vm, val);
        }
        if (signature.startsWith("com/bytedance/mobsec/metasec/ml/MS->b(")) {
            int cmd = vaList.getIntArg(0);
            int a2 = vaList.getIntArg(1);
            long a3 = vaList.getLongArg(2);
            DvmObject<?> s = vaList.getObjectArg(3);
            DvmObject<?> o = vaList.getObjectArg(4);
            DvmObject<?> ret = dispatch(cmd, a2, a3, s, o);
            System.out.printf("[MS.b] cmd=0x%x(%d) a2=0x%x a3=0x%x str=%s -> %s%n",
                    cmd, cmd, a2, a3, s == null ? "null" : s.getValue(),
                    ret == null ? "null" : ret.getValue());
            return ret;
        }
        // Settings.{System,Secure,Global}.getString(resolver, key[, ...]) used during
        // device fingerprinting. We have no real device, so answer with an empty string
        // (the values feed freshly-generated headers; the server validates those, not the
        // exact fingerprint bytes), keeping the native running instead of crashing.
        if (signature.startsWith("android/provider/Settings$System->getString(")
                || signature.startsWith("android/provider/Settings$Secure->getString(")
                || signature.startsWith("android/provider/Settings$Global->getString(")) {
            return new StringObject(vm, "");
        }
        return stubObject(vm, signature, () -> super.callStaticObjectMethodV(vm, dvmClass, signature, vaList));
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        // Settings.* String name constants (e.g. SCREEN_BRIGHTNESS) that the library reads
        // for device fingerprinting. unidbg has no value for these, so return the well-known
        // setting key strings so the subsequent ContentResolver lookup has a sane key.
        switch (signature) {
            case "android/provider/Settings$System->SCREEN_BRIGHTNESS:Ljava/lang/String;":
                return new StringObject(vm, "screen_brightness");
            case "android/provider/Settings$System->SCREEN_BRIGHTNESS_MODE:Ljava/lang/String;":
                return new StringObject(vm, "screen_brightness_mode");
            case "android/provider/Settings$System->SCREEN_OFF_TIMEOUT:Ljava/lang/String;":
                return new StringObject(vm, "screen_off_timeout");
            case "android/provider/Settings$Secure->ANDROID_ID:Ljava/lang/String;":
                return new StringObject(vm, "android_id");
            default:
                return stubObject(vm, signature, () -> super.getStaticObjectField(vm, dvmClass, signature));
        }
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        // common AudioManager stream-type constants read right after Context.AUDIO_SERVICE
        switch (signature) {
            case "android/media/AudioManager->STREAM_VOICE_CALL:I":   return 0;
            case "android/media/AudioManager->STREAM_SYSTEM:I":       return 1;
            case "android/media/AudioManager->STREAM_RING:I":         return 2;
            case "android/media/AudioManager->STREAM_MUSIC:I":        return 3;
            case "android/media/AudioManager->STREAM_ALARM:I":        return 4;
            case "android/media/AudioManager->STREAM_NOTIFICATION:I": return 5;
            case "android/media/AudioManager->STREAM_DTMF:I":         return 8;
        }
        return stubInt(signature, () -> super.getStaticIntField(vm, dvmClass, signature));
    }

    @Override
    public long getStaticLongField(BaseVM vm, DvmClass dvmClass, String signature) {
        try {
            return super.getStaticLongField(vm, dvmClass, signature);
        } catch (UnsupportedOperationException e) {
            System.out.println("[stub] getStaticLongField " + signature + " -> 0");
            return 0L;
        }
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        // Settings.{System,Secure,Global}.getInt(resolver, key[, def]) -> return a plausible
        // default (also avoids SettingNotFoundException for the no-default overload).
        if (signature.startsWith("android/provider/Settings$System->getInt(")
                || signature.startsWith("android/provider/Settings$Secure->getInt(")
                || signature.startsWith("android/provider/Settings$Global->getInt(")) {
            return 102;
        }
        return stubInt(signature, () -> super.callStaticIntMethodV(vm, dvmClass, signature, vaList));
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        return stubBool(signature, () -> super.callStaticBooleanMethodV(vm, dvmClass, signature, vaList));
    }

    // ---- generic "never crash into the debugger" fallbacks -------------------------------
    // The library probes a wide, host-dependent set of device-fingerprint fields/methods
    // (brightness, audio volumes, sensors, ...). unidbg's AbstractJni throws
    // UnsupportedOperationException for anything it doesn't implement, which drops the
    // emulator into its interactive debugger (looks like a hang). We can't enumerate every
    // probe, so any unimplemented query returns a type-appropriate default instead of
    // throwing. The values only feed freshly-generated headers (server validates
    // self-consistency + timestamp, not exact fingerprint bytes), so defaults are safe.
    private interface ObjSup { DvmObject<?> get(); }
    private interface IntSup { int get(); }
    private interface BoolSup { boolean get(); }

    private DvmObject<?> stubObject(BaseVM vm, String signature, ObjSup real) {
        try {
            return real.get();
        } catch (UnsupportedOperationException e) {
            DvmObject<?> def = signature.endsWith("Ljava/lang/String;") ? new StringObject(vm, "") : null;
            System.out.println("[stub] object " + signature + " -> " + (def == null ? "null" : "\"\""));
            return def;
        }
    }

    private int stubInt(String signature, IntSup real) {
        try {
            return real.get();
        } catch (UnsupportedOperationException e) {
            System.out.println("[stub] int " + signature + " -> 0");
            return 0;
        }
    }

    private boolean stubBool(String signature, BoolSup real) {
        try {
            return real.get();
        } catch (UnsupportedOperationException e) {
            System.out.println("[stub] bool " + signature + " -> false");
            return false;
        }
    }

    /** Manually bind a native method to a function pointer (the library declines to
     *  RegisterNatives under emulation, so we populate DvmClass.nativesMap directly). */
    @SuppressWarnings("unchecked")
    private static void registerNative(DvmClass clazz, String methodAndSig,
                                       com.github.unidbg.pointer.UnidbgPointer fnPtr) throws Exception {
        java.lang.reflect.Field f = DvmClass.class.getDeclaredField("nativesMap");
        f.setAccessible(true);
        Map<String, com.github.unidbg.pointer.UnidbgPointer> m =
                (Map<String, com.github.unidbg.pointer.UnidbgPointer>) f.get(clazz);
        m.put(methodAndSig, fnPtr);
    }

    /** Unwrap a returned array element (DvmObject/StringObject) into a plain String. */
    private static String asStr(Object o) {
        if (o == null) return null;
        if (o instanceof String) return (String) o;
        if (o instanceof DvmObject) {
            Object inner = ((DvmObject<?>) o).getValue();
            if (inner instanceof String) return (String) inner;
            if (inner != null) return String.valueOf(inner);
        }
        return String.valueOf(o);
    }

    /** Minimal JSON string quoting (no org.json on the unidbg classpath). */
    private static String jq(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n");  break;
                case '\r': b.append("\\r");  break;
                case '\t': b.append("\\t");  break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    /**
     * Resolve an input string from (in priority order): a file pointed to by the
     * {@code fileProp} system property, the inline {@code valProp} system property,
     * or the supplied default. Lets the Python orchestrator inject a fresh
     * url/body (with a current timestamp) without recompiling.
     */
    private static String readSource(String fileProp, String valProp, String def) {
        try {
            String fp = System.getProperty(fileProp);
            if (fp != null && fp.length() > 0) {
                byte[] data = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(fp));
                String s = new String(data, java.nio.charset.StandardCharsets.UTF_8);
                // strip a single trailing newline if present
                if (s.endsWith("\r\n")) s = s.substring(0, s.length() - 2);
                else if (s.endsWith("\n")) s = s.substring(0, s.length() - 1);
                return s;
            }
            String v = System.getProperty(valProp);
            if (v != null && v.length() > 0) return v;
        } catch (Exception e) {
            System.out.println("[input] readSource(" + fileProp + ") failed: " + e + " -> using default");
        }
        return def;
    }

    public static void main(String[] args) throws Exception {
        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.phoenix.read")
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        // preemptive thread switching: switch threads every N instructions so the
        // worker threads spawned in JNI_OnLoad interleave with the main thread and
        // complete the lazy RegisterNatives of y2.a (canonical unidbg ThreadTest pattern).
        emulator.getBackend().registerEmuCountHook(100000);
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        VM vm = emulator.createDalvikVM();
        vm.setVerbose(true);
        MetasecDump harness = new MetasecDump(vm);
        vm.setJni(harness);

        DvmClass cObject = vm.resolveClass("java/lang/Object");
        vm.resolveClass("com/bytedance/mobsec/metasec/ml/MS", cObject);

        System.out.println("==== loading libmetasec_ml.so ====");
        DalvikModule dm = vm.loadLibrary(new File("libs/libmetasec_ml.so"), false);
        Module module = dm.getModule();
        System.out.println("==== module base=0x" + Long.toHexString(module.base) + " ====");

        final long base = module.base;

        System.out.println("==== calling JNI_OnLoad ====");
        dm.callJNI_OnLoad(emulator);
        System.out.println("==== JNI_OnLoad done; pumping worker threads ====");
        try {
            emulator.getThreadDispatcher().runThreads(15, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Throwable t) {
            System.out.println("[runThreads] " + t);
        }
        System.out.println("==== worker threads pumped ====");

        // ---- Plan A: the library refuses to RegisterNatives y2.a under the emulator
        // (anti-emulation). We located its JNI trampoline statically at base+0x26e684
        // and bind it manually into the DvmClass nativesMap so callStaticJniMethod* can
        // dispatch to it like a normally-registered native. (No protocol logic here.)
        DvmClass y2 = vm.resolveClass("ms/bd/c/y2");
        final String Y2_SIG = "a(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;";
        registerNative(y2, Y2_SIG, com.github.unidbg.pointer.UnidbgPointer.pointer(emulator, base + 0x26e684));
        System.out.println("==== manually registered ms/bd/c/y2.a => base+0x26e684 ====");

        // smoke test: string-decrypt (cmd 0x1000001 = 16777217) -> should yield d4.a
        String d4a = "v04.09.09.01-bugfix";
        try {
            DvmObject<?> r = y2.callStaticJniMethodObject(emulator, Y2_SIG,
                    16777217, 0, 0L, new StringObject(vm, "797c4e"),
                    new com.github.unidbg.linux.android.dvm.array.ByteArray(vm,
                        new byte[]{48,107,16,89,91,43,122,72,63,125,118,106,9,21,30,117,50,17,126}));
            if (r != null && r.getValue() instanceof String) d4a = (String) r.getValue();
            System.out.println("[smoke decrypt] d4.a => " + d4a);
        } catch (Throwable t) {
            System.out.println("[smoke decrypt] call failed: " + t);
            t.printStackTrace();
        }

        // ---- drive the SDK init + sign sequence (mirrors com.bytedance.mobsec.metasec.core.g) ----
        // device/app params captured from the real novelread 7.2.4.32 request + MSConfig (app launch task w1.l)
        final String APP_ID  = "8662";
        final String LICENSE = "10CS/42gNkYsyh4LRwuHcdVaVjG2i5BUsDfHUqCVBaxa/Bx60+MQutso9T7Ps/7BndgAAaVpcAAujIDjnIJHII740GgosokBd09F6HCAKmqaazJTJ2rc04TNl663tZDc6cEiCsesc73XvCq/XcM0s5BbW8VhXBjzutaaL+a9WT3a5mtor2CRVX3DT5KKaSSVqNXsH9JW+LnbyzIZeLlzHvvhhigsIgRC0K4ANnZAR49HZswPeF73VDxugL2v8aWxtx2jAA0wuFsx6fN5oMDk5aG0RMVzgu0RIyoMGQaF3LK7ezON";
        final String CHANNEL = "huawei_8662_64";
        final String DEVICE_ID  = "1518852408610185";
        final String INSTALL_ID = "1518852408614281";

        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);

        try {
            // 1) context init (g.c -> cmd 0x1000003)
            y2.callStaticJniMethodObject(emulator, Y2_SIG, 16777219, 0, 0L, null, context);
            System.out.println("[init] context init done");

            // 2) register config (g.f -> cmd 0x4000001) with toNativeValue() JSON array
            StringBuilder sb = new StringBuilder("[");
            sb.append(jq(APP_ID)).append(',');   // mAppID
            sb.append(jq("")).append(',');        // mSubAppID
            sb.append(jq("")).append(',');        // mSDKID
            sb.append(jq(LICENSE)).append(',');   // mLicensetStr
            sb.append(jq(d4a)).append(',');       // d4.a
            sb.append(jq(CHANNEL)).append(',');   // mChannel
            sb.append(jq("")).append(',');        // mDeviceID (set later)
            sb.append(jq("")).append(',');        // mBDDeviceID
            sb.append(jq("")).append(',');        // mInstallID (set later)
            sb.append(jq("")).append(',');        // mSessionID
            sb.append(jq("0")).append(',');       // mClientType
            sb.append(jq("-1")).append(',');      // mOVRegionType
            sb.append(jq("99999")).append(',');   // mCollectMode
            sb.append(jq(DEVICE_ID)).append(','); // mFetchedDid
            sb.append(jq("1")).append(',');       // mOrigin
            sb.append("[],[]");                    // customInfo, advanceInfo
            sb.append("]");
            String nativeValue = sb.toString();
            DvmObject<?> ok = y2.callStaticJniMethodObject(emulator, Y2_SIG,
                    67108865, 0, 0L, new StringObject(vm, nativeValue), null);
            System.out.println("[init] config register (0x4000001) => " + (ok == null ? "null" : ok.getValue()));

            // 3) get handle (g.a -> cmd 0x4000002)
            DvmObject<?> h = y2.callStaticJniMethodObject(emulator, Y2_SIG, 67108866, 0, 0L, null, null);
            long handle = (h != null && h.getValue() instanceof Long) ? (Long) h.getValue() : -1L;
            System.out.println("[init] handle (0x4000002) => " + handle);

            if (handle != -1L) {
                // 4) push device_id / install_id onto the handle (c.setDeviceID/​setInstallID)
                y2.callStaticJniMethodObject(emulator, Y2_SIG, 33554434, 0, handle, new StringObject(vm, DEVICE_ID), context);
                y2.callStaticJniMethodObject(emulator, Y2_SIG, 33554435, 0, handle, new StringObject(vm, INSTALL_ID), context);
                System.out.println("[init] device/install id set");

                // 5) getFeatureHash (c.getFeatureHash -> cmd 0x2000002 = 33554438) => the 7 security headers
                // url/body are taken from -Dreq.url.file / -Dreq.body.file when provided
                // (so the Python orchestrator can inject a fresh timestamp), else defaults below.
                String url = readSource("req.url.file", "req.url",
                        "https://api5-normal-sinfonlinea.fqnovel.com/novel/player/video_model/v1/?iid=1518852408614281&device_id=1518852408610185&ac=wifi&channel=huawei_8662_64&aid=8662&app_name=novelread&version_code=72432&version_name=7.2.4.32&device_platform=android&os=android&ssmix=a&device_type=23076RA4BC&device_brand=Redmi&language=zh&os_api=33&os_version=13&manifest_version_code=72432&resolution=1080*2226&dpi=440&update_version_code=72432&_rticket=1782306317500&host_abi=arm64-v8a&dragon_device_type=phone&pv_player=72432&compliance_status=0&need_personal_recommend=1&player_so_load=1&is_android_pad_screen=0&rom_version=miui_V140_V14.0.10.0.TMWEUXM&cdid=6e297aec-fb86-48ed-98cc-289027ea46dd");
                String body = readSource("req.body.file", "req.body",
                        "{\"biz_param\":{\"detail_page_version\":0,\"device_level\":2,\"disable_digg_stat\":false,\"disable_video_relate_book\":false,\"from_video_id\":\"\",\"need_all_video_definition\":true,\"need_mp4_align\":false,\"source\":4,\"use_os_player\":false,\"use_server_dns\":false,\"video_platform\":3},\"content_type\":1004,\"video_id\":\"7650889194310470681\"}");
                com.github.unidbg.linux.android.dvm.array.ByteArray bodyArr =
                        new com.github.unidbg.linux.android.dvm.array.ByteArray(vm, body.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                DvmObject<?> sign = y2.callStaticJniMethodObject(emulator, Y2_SIG, 33554438, 0, handle, new StringObject(vm, url), bodyArr);
                System.out.println("[sign] getFeatureHash (0x2000006) class => " + (sign == null ? "null" : sign.getClass().getName()));
                if (sign != null) {
                    Object val = sign.getValue();
                    System.out.println("[sign] value type => " + (val == null ? "null" : val.getClass().getName()));
                    if (val instanceof Object[]) {
                        Object[] arr = (Object[]) val;
                        System.out.println("[sign] String[] length=" + arr.length);
                        StringBuilder js = new StringBuilder("{");
                        boolean first = true;
                        for (int i = 0; i + 1 < arr.length; i += 2) {
                            String k = asStr(arr[i]);
                            String v2 = asStr(arr[i + 1]);
                            System.out.println("   " + k + " = " + v2);
                            if (k == null || v2 == null) continue;
                            if (!first) js.append(',');
                            js.append(jq(k)).append(':').append(jq(v2));
                            first = false;
                        }
                        js.append('}');
                        // Stable marker line so an external orchestrator can parse the headers.
                        System.out.println("__HEADERS_JSON__" + js);
                    } else {
                        System.out.println("[sign] raw => " + val);
                    }
                }
            }
        } catch (Throwable t) {
            System.out.println("[init/sign] failed: " + t);
            t.printStackTrace();
        }

        emulator.close();
    }
}
