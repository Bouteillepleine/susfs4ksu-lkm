#!/usr/bin/env bash
# Is each probe target actually CALLED, or did the compiler inline it away?
#
# usage: callsite-audit.sh <Image|vmlinux.elf> [symbol...]
#
# register_kprobe() succeeding proves only that a symbol exists. Under LTO the
# kernel's own call sites get inlined, leaving the out-of-line symbol to serve
# whichever callers were left -- so the probe is "live", the hit count climbs,
# and the events you wanted are not in it. That is a property of the linked
# kernel, so read it out of the kernel instead of measuring on the device:
# count the `bl <sym>` edges and look at who they come from.
#
# A raw Image is converted with vmlinux-to-elf first.
#
# What this can and cannot decide. ABSENT from the symbol table is conclusive:
# register_kprobe() will fail. N direct call sites is conclusive the other way.
# ZERO call sites is INCONCLUSIVE and is not failed on -- the symbol may be
# inlined, or it may be reached indirectly, which a bl count cannot see:
# syscall wrappers go through sys_call_table, and seq_file ->show, inode_op
# ->get_link and any other vtable member go through a function pointer. An
# EXPORT_SYMBOL'd helper with no in-tree caller also lands here. Classifying
# those by whether the address appears as a data word does NOT work on a
# vmlinux-to-elf reconstruction: it guesses the load base, so the stored
# pointers do not match the symbol addresses. Check those few by hand.
set -uo pipefail
IMG="${1:?Image or vmlinux ELF}"; shift
OBJDUMP="${OBJDUMP:-llvm-objdump}"
NM="${NM:-llvm-nm}"
V2E="${V2E:-vmlinux-to-elf}"

# With no symbols given, take them from this module's own sources, so the list
# cannot drift away from what the code actually attaches to.
SRC="${SRC:-$(cd "$(dirname "$0")/../kernel" 2>/dev/null && pwd)}"
SYMS=("$@")
if [ ${#SYMS[@]} -eq 0 ]; then
  [ -n "$SRC" ] && [ -d "$SRC" ] || { echo "no symbols given and no kernel/ source dir found" >&2; exit 2; }
  mapfile -t SYMS < <(grep -rhoE '(symbol_name|\.sym)[[:space:]]*=[[:space:]]*"[a-zA-Z_0-9]+"' "$SRC" \
                      | grep -oE '"[a-zA-Z_0-9]+"' | tr -d '"' | sort -u)
  [ ${#SYMS[@]} -gt 0 ] || { echo "no attach points found in $SRC" >&2; exit 2; }
  echo ":: ${#SYMS[@]} attach points taken from $SRC"
fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

ELF="$IMG"
if [ "$(head -c4 "$IMG" | od -An -tx1 | tr -d ' \n')" != "7f454c46" ]; then
  command -v "$V2E" >/dev/null || { echo "need $V2E to read a raw Image" >&2; exit 2; }
  echo ":: $IMG is not an ELF -- reconstructing with $V2E"
  "$V2E" "$IMG" "$TMP/vmlinux.elf" >/dev/null 2>&1 || { echo "vmlinux-to-elf failed" >&2; exit 2; }
  ELF="$TMP/vmlinux.elf"
fi

ver=$(strings -a "$IMG" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+-[-a-zA-Z0-9.]+' | head -1)
lto=$("$NM" "$ELF" 2>/dev/null | grep -c '\.llvm\.')
echo ":: kernel  ${ver:-unknown}"
echo ":: .llvm.-suffixed symbols: $lto  (>0 means LTO; 0 proves NOTHING on a"
echo "   vmlinux-to-elf reconstruction -- it rebuilds symbols from kallsyms and"
echo "   does not preserve the suffixes. The bl counts below are the evidence.)"
echo

"$OBJDUMP" -d --no-show-raw-insn "$ELF" 2>/dev/null \
  | grep -E '^[0-9a-f]+ <[^>]+>:|[[:space:]]bl[[:space:]]' > "$TMP/bl.txt"
[ -s "$TMP/bl.txt" ] || { echo "no disassembly from $OBJDUMP" >&2; exit 2; }

fail=0; inconclusive=0
for s in "${SYMS[@]}"; do
  if [ "$("$NM" "$ELF" 2>/dev/null | grep -cE " (t|T) $s\$")" -eq 0 ]; then
    printf '%-26s ABSENT from the symbol table -- register_kprobe() would fail\n' "$s"
    fail=1; continue
  fi
  n=$(awk -v s="$s" '/[[:space:]]bl[[:space:]]/ {t=$NF; gsub(/[<>]/,"",t); sub(/\+.*/,"",t); if (t==s) c++} END{print c+0}' "$TMP/bl.txt")
  callers=$(awk -v s="$s" '
    /^[0-9a-f]+ <[^>]+>:/ { cur=$2; gsub(/[<>:]/,"",cur); next }
    /[[:space:]]bl[[:space:]]/ { t=$NF; gsub(/[<>]/,"",t); sub(/\+.*/,"",t); if (t==s) print cur }
  ' "$TMP/bl.txt" | sort | uniq -c | sort -rn | awk '{printf "%s%s", sep, $2 ($1>1 ? "x" $1 : ""); sep=" "} END{print ""}')

  case "$s" in
    __arm64_sys_*|__arm64_compat_sys_*)
      printf '%-26s present (sys_call_table dispatch, bl=%d as expected)\n' "$s" "$n" ;;
    *)
      if [ "$n" -eq 0 ]; then
        printf '%-26s callsites=0  INCONCLUSIVE: inlined, or indirect (vtable/seq_file/export-only) -- check by hand\n' "$s"
        inconclusive=$((inconclusive+1))
      else
        printf '%-26s callsites=%-3d %s\n' "$s" "$n" "$callers"
      fi ;;
  esac
done

echo
[ "$inconclusive" -gt 0 ] && echo "$inconclusive target(s) inconclusive -- see above, verify those by hand"
[ "$fail" -eq 0 ] && echo "AUDIT PASS: no probe target is missing from the symbol table" \
                  || { echo "AUDIT FAIL: a probe target is ABSENT -- register_kprobe() will fail"; exit 1; }
