#!/usr/bin/env bash
# Regenerates tests/fixtures/sparrow<version>_*.psbt with that Sparrow release's
# own code. Usage: generate.sh [2.2.3|2.5.5]   (default 2.2.3)
# See scripts/sparrow/README.md for what this does and does not prove.
# Needs: curl, gpg, a JDK 21 (javac + java launcher), python3 with embit.
set -euo pipefail
cd "$(dirname "$0")"
V=${1:-2.2.3}
case "$V" in
  2.2.3) DRIVER=SparrowPsbt ;;
  2.5.5) DRIVER=SparrowPsbt255 ;;
  *) echo "unsupported version $V (2.2.3 or 2.5.5)"; exit 2 ;;
esac
PREFIX="sparrow$(echo "$V" | tr -d .)_"
W="work-$V"
mkdir -p "$W" && cd "$W"
R="https://github.com/sparrowwallet/sparrow/releases/download/$V"
[ -f sparrow.tgz ] || curl -sSL -o sparrow.tgz "$R/sparrowwallet-$V-x86_64.tar.gz"
curl -sSL -o manifest.txt "$R/sparrow-$V-manifest.txt"
curl -sSL -o manifest.txt.asc "$R/sparrow-$V-manifest.txt.asc"

# 1. The manifest is signed by Craig Raw (Sparrow's author) ...
export GNUPGHOME="$PWD/gnupg"; mkdir -p -m700 "$GNUPGHOME"
curl -sSL -o craig.asc "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xD4D0D3202FC06849A257B38DE94618334C674B40"
gpg -q --import craig.asc 2>/dev/null || true   # verified below; a missing gpg-agent can fail the exit status
gpg --verify manifest.txt.asc manifest.txt 2>&1 | grep -q "Good signature" || { echo "BAD SIGNATURE"; exit 1; }
gpg --verify manifest.txt.asc manifest.txt 2>&1 | grep -q "D4D0 D320 2FC0 6849 A257  B38D E946 1833 4C67 4B40" || { echo "WRONG KEY"; exit 1; }
# 2. ... and lists the tarball's hash.
grep "sparrowwallet-$V-x86_64.tar.gz" manifest.txt | awk '{print $1"  sparrow.tgz"}' | sha256sum -c -

tar -xzf sparrow.tgz
RT="$PWD/Sparrow/lib/runtime"
# The bundled runtime (Java 22) ships without a plain `java` launcher; borrow one.
[ -e "$RT/bin/java" ] || cp "$(readlink -f "$(command -v java)")" "$RT/bin/java"

# Compile-time only: a copy of drongo's classes with the class-file version
# lowered so a JDK 21 javac can read them. The run uses Sparrow's real runtime.
rm -rf stubs && jimage extract --dir stubs --include 'regex:/com.sparrowwallet.drongo/.*' "$RT/lib/modules"
python3 - <<'PY'
import pathlib
for p in pathlib.Path("stubs").rglob("*.class"):
    b = bytearray(p.read_bytes()); b[6:8] = b"\x00\x41"; p.write_bytes(b)   # -> Java 21
PY
rm -rf classes && javac -d classes -cp stubs/com.sparrowwallet.drongo "../$DRIVER.java"
# Sparrow's own debug logging goes to stdout too: keep only "name<TAB>data" lines.
"$RT/bin/java" --add-modules com.sparrowwallet.drongo -cp classes "$DRIVER" 2>/dev/null \
  | grep -P '^[a-z0-9_]+\t' > out.tsv

PREFIX="$PREFIX" python3 - <<'PY'
import os, pathlib
fx = pathlib.Path("../../../tests/fixtures")
for line in open("out.tsv"):
    name, data = line.rstrip("\n").split("\t")
    path = fx / f"{os.environ['PREFIX']}{name}.psbt"
    if name.endswith("_file"):
        path.write_bytes(bytes.fromhex(data))
    else:
        path.write_text(data + "\n")
    print("wrote", path.name)
PY
