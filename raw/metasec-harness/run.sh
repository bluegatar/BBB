#!/bin/bash
# ===================================================================
#  Self-contained metasec unidbg harness (Linux/macOS).
#  All unidbg jars are bundled in deps/ -- no maven / internet needed.
#  Only requirement: JDK 8 (set JAVA8 below or have javac/java on PATH).
# ===================================================================
set -e
cd "$(dirname "$0")"

# --- JDK 8 location. If javac/java on PATH are JDK8, leave as-is. ---
JAVA8="${JAVA8:-}"
# --------------------------------------------------------------------
if [ -n "$JAVA8" ] && [ -x "$JAVA8/javac" ]; then
  JAVAC="$JAVA8/javac"; JAVA="$JAVA8/java"
else
  JAVAC=javac; JAVA=java
fi

if [ ! -f libs/libmetasec_ml.so ]; then
  echo "ERROR: missing libs/libmetasec_ml.so (arm64-v8a)" >&2
  exit 1
fi

# classpath = every jar in deps/  (Java expands the trailing /* )
CP='deps/*'

mkdir -p build
"$JAVAC" -encoding UTF-8 -cp "$CP" -d build src/MetasecDump.java
"$JAVA" -Dunidbg.tgkill.drop=true ${FAKE_TIME:+-Dunidbg.fake.time.ms=$FAKE_TIME} $JVM_OPTS -cp "build:$CP" MetasecDump "$@"
