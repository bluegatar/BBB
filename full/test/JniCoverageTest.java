import com.github.unidbg.linux.android.dvm.AbstractJni;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

/**
 * Coverage gate for the harness's JNI catch-all.
 *
 * unidbg's {@link AbstractJni} dispatches every native JNI callback to a String-signature
 * variant (getXField / callXMethod[V] / newObject[V] / allocObject / setXField). Those
 * String variants throw {@code UnsupportedOperationException} by default, which drops the
 * emulator into its interactive debugger (the "hang" the user kept hitting). MetasecDump must
 * therefore OVERRIDE every one of those String-signature entry points so an unimplemented
 * device-fingerprint probe returns a default instead of crashing.
 *
 * This test enumerates those entry points on AbstractJni via reflection and asserts each is
 * overridden by MetasecDump. It runs on any host (no VM / no .so needed), so it verifies the
 * net is complete without depending on which probes a given machine happens to trigger.
 */
public class JniCoverageTest {

    private static boolean isJniEntry(Method m) {
        if (!Modifier.isPublic(m.getModifiers())) return false;
        String n = m.getName();
        boolean named = n.startsWith("call") || n.startsWith("getStatic") || n.startsWith("setStatic")
                || n.startsWith("getObject") || n.startsWith("getInt") || n.startsWith("getLong")
                || n.startsWith("getBoolean") || n.startsWith("getByte") || n.startsWith("getShort")
                || n.startsWith("getChar") || n.startsWith("getFloat") || n.startsWith("getDouble")
                || n.startsWith("setObject") || n.startsWith("setInt") || n.startsWith("setLong")
                || n.startsWith("setBoolean") || n.startsWith("setByte") || n.startsWith("setShort")
                || n.startsWith("setChar") || n.startsWith("setFloat") || n.startsWith("setDouble")
                || n.startsWith("newObject") || n.equals("allocObject");
        if (!named) return false;
        for (Class<?> p : m.getParameterTypes()) {
            if (p == String.class) return true; // the String-signature dispatch variant
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        Class<?> harness = Class.forName("MetasecDump");
        List<String> missing = new ArrayList<>();
        int checked = 0;
        for (Method m : AbstractJni.class.getMethods()) {
            if (!isJniEntry(m)) continue;
            checked++;
            Method override;
            try {
                override = harness.getDeclaredMethod(m.getName(), m.getParameterTypes());
            } catch (NoSuchMethodException e) {
                override = null;
            }
            if (override == null) {
                missing.add(m.getName() + "(" + sig(m.getParameterTypes()) + ")");
            }
        }
        System.out.println("[JniCoverageTest] String-signature JNI entry points: " + checked);
        if (missing.isEmpty()) {
            System.out.println("[JniCoverageTest] PASS - all " + checked + " entry points overridden by MetasecDump");
        } else {
            System.out.println("[JniCoverageTest] FAIL - " + missing.size() + " NOT overridden (would crash into debugger):");
            for (String s : missing) System.out.println("    - " + s);
            System.exit(1);
        }
    }

    private static String sig(Class<?>[] params) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < params.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append(params[i].getSimpleName());
        }
        return sb.toString();
    }
}
