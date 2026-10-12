#!/usr/bin/env bash
# Would this .ko load on that kernel, and is it the RIGHT one for it?
#
# usage: ko-gate.sh <module.ko> [<devcrc.txt|Module.symvers>] [adb|<release>]
#
# Three independent refusals, cheapest first. On a device whose OEM resets the
# box on a bad out-of-tree load there is no error message to read afterwards,
# so every one of these has to be checked BEFORE insmod.
set -uo pipefail
NM="${NM:-llvm-nm}"
READELF="${READELF:-llvm-readelf}"
KO="${1:?module.ko}"; REF="${2:-}"; WANTREL="${3:-}"

rc=0

# 1. GOT relocations. The arm64 module loader has no GOT to fix up, so a
# R_AARCH64_*GOT* reloc is rejected at insmod even though the link succeeded.
# A weak-undefined symbol is the usual way to end up with one.
echo "-- GOT relocations"
got=$("$READELF" -r "$KO" 2>/dev/null | awk '$3 ~ /GOT/ {s=$NF; sub(/\+.*/,"",s); print s}' | sort -u | grep -v '^$')
if [ -n "$got" ]; then
  while read -r s; do
    kind=$("$NM" "$KO" 2>/dev/null | awk -v s="$s" '$NF==s {print $(NF-1); exit}')
    printf '   %-32s nm=%s%s\n' "$s" "${kind:-?}" \
      "$([ "$kind" = "w" ] && echo '  <-- weak undefined: this is the cause')"
  done <<< "$got"
  echo "   GATE FAIL: arm64 rejects GOT relocs at insmod (links fine, insmod does not)"
  rc=1
else
  echo "   none"
fi

# 2. vermagic release. Catches the ABI-GROUP error (e.g. 6.12.23 vs 6.12.58).
# It cannot identify the BUILD: our kernels reuse the stock scmversion, so the
# release string is identical between our build and stock. For build identity
# md5 susfs_guard_lkm.ko against /data/adb/lkm/persistent.ko.
if [ -n "$WANTREL" ]; then
  echo "-- vermagic release"
  case "$WANTREL" in
    adb) want=$(adb shell uname -r 2>/dev/null | tr -d '\r\n') ;;
    *)   want="$WANTREL" ;;
  esac
  got_rel=$(modinfo -F vermagic "$KO" 2>/dev/null | awk '{print $1}')
  printf '   module=%s\n   kernel=%s\n' "${got_rel:-?}" "${want:-?}"
  if [ -z "$want" ]; then
    echo "   GATE FAIL: could not read the target's release (adb down?) -- failing closed"; rc=1
  elif [ "$got_rel" != "$want" ]; then
    echo "   GATE FAIL: different ABI group -- do NOT insmod"; rc=1
  fi
fi

# 3. Imported-symbol CRCs. This is what the loader actually enforces, because
# same_magic() skips the release field whenever the module carries CRCs.
if [ -n "$REF" ]; then
  echo "-- imported symbol CRCs"
  ok=0; bad=0
  while read -r s; do
    [ -n "$s" ] || continue
    m=$(modprobe --dump-modversions "$KO" 2>/dev/null | awk -v s="$s" '$2==s{print $1; exit}')
    k=$(awk -F'\t' -v s="$s" '$2==s{print $1; exit}' "$REF")
    if [ -n "$k" ] && [ "$m" = "$k" ]; then ok=$((ok+1))
    else bad=$((bad+1)); printf '   %-32s module=%-12s kernel=%-12s\n' "$s" "${m:-NONE}" "${k:-ABSENT}"; fi
  done < <("$NM" -u "$KO" 2>/dev/null | awk '{print $NF}')
  echo "   $ok match, $bad differ"
  [ "$bad" -eq 0 ] || { echo "   GATE FAIL: built against different source/config"; rc=1; }
fi

echo
[ "$rc" -eq 0 ] && echo "GATE PASS: safe to insmod" || echo "GATE FAIL: do NOT insmod"
exit "$rc"
