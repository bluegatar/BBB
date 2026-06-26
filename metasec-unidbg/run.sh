#!/bin/bash
# Compile + run the metasec unidbg harness (Linux/macOS).
# Edit the two vars below for your machine.
set -e

# --- configure these ---
UNIDBG_DIR="${UNIDBG_DIR:-$HOME/unidbg}"          # path to the patched unidbg checkout
JAVA8="${JAVA8:-/usr/lib/jvm/java-8-openjdk-amd64/bin}"   # JDK8 bin dir
# -----------------------

cd "$(dirname "$0")"

if [ ! -f libs/libmetasec_ml.so ]; then
  echo "ERROR: put libmetasec_ml.so (arm64-v8a) into $(pwd)/libs/" >&2
  exit 1
fi

# Build classpath: unidbg-android jar + all its maven deps.
UA_JAR="$(ls "$UNIDBG_DIR"/unidbg-android/target/unidbg-android-*.jar 2>/dev/null | grep -v sources | grep -v javadoc | head -n1)"
if [ -z "$UA_JAR" ]; then
  echo "ERROR: unidbg-android jar not found. Build unidbg first:" >&2
  echo "  cd $UNIDBG_DIR && ./mvnw -pl unidbg-android -am install -DskipTests" >&2
  exit 1
fi
( cd "$UNIDBG_DIR" && ./mvnw -q -pl unidbg-android dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt )
CP="$UA_JAR:$(cat /tmp/cp.txt)"

mkdir -p build
"$JAVA8/javac" -cp "$CP" -d build src/MetasecDump.java
"$JAVA8/java" -Dunidbg.tgkill.drop=true ${FAKE_TIME:+-Dunidbg.fake.time.ms=$FAKE_TIME} -cp "build:$CP" MetasecDump "$@"
