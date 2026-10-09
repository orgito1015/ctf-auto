#!/usr/bin/env bash
#
# ctf-solve — hand a CTF challenge to Claude Code and get back a solution + writeup,
#             no interactive session needed.
#
# Usage:
#   ctf-solve <folder | archive.zip/tar.gz | file>   [extra hint text ...]
#   ctf-solve ~/Downloads/pwn_babyheap
#   ctf-solve chall.zip "it's a format string, flag format CTF{...}"
#
# Options (env vars):
#   MODEL=opus|sonnet|haiku   model to use            (default: inherits CLI default)
#   SAFE=1                    ask before each tool    (default: autonomous / skip perms)
#   NETWORK=1                 allow outbound network  (default: offline sandbox)
#   FLAG_FMT="CTF{...}"       expected flag format    (default: unknown)
#
# Output lands inside the challenge working dir:
#   WRITEUP.md     the full writeup
#   solution/      any scripts / exploits Claude wrote
#
set -euo pipefail

# ---- args -----------------------------------------------------------------
if [[ $# -lt 1 ]]; then
  grep '^#' "$0" | sed 's/^# \{0,1\}//'   # print the header as help
  exit 1
fi

# resolve our own dir NOW, before any cd (so we can find ctf-recon.sh later)
SELFDIR="$(dirname "$(readlink -f "$0")")"

TARGET="$1"; shift
HINT="${*:-}"

# QUIET=1 → silence all progress/claude output; print only the flag at the end.
QUIET="${QUIET:-0}"
if [[ "$QUIET" == "1" ]]; then exec 3>&1 1>/dev/null 2>/dev/null; else exec 3>&1; fi

MODEL="${MODEL:-}"
FLAG_FMT="${FLAG_FMT:-unknown}"

# ---- resolve the challenge into a working directory ------------------------
TARGET="$(readlink -f "$TARGET")"
if [[ ! -e "$TARGET" ]]; then echo "no such path: $TARGET" >&2; exit 1; fi

WORK=""
if [[ -d "$TARGET" ]]; then
  WORK="$TARGET"
else
  # it's a file: extract archives into a sibling dir, otherwise use its folder
  base="$(basename "$TARGET")"
  case "$base" in
    *.zip)                WORK="${TARGET%.zip}";          mkdir -p "$WORK"; unzip -o -q "$TARGET" -d "$WORK" ;;
    *.tar.gz|*.tgz)       WORK="${TARGET%.t*}";           mkdir -p "$WORK"; tar xzf "$TARGET" -C "$WORK" ;;
    *.tar.xz)             WORK="${TARGET%.tar.xz}";       mkdir -p "$WORK"; tar xJf "$TARGET" -C "$WORK" ;;
    *.tar.bz2)            WORK="${TARGET%.tar.bz2}";      mkdir -p "$WORK"; tar xjf "$TARGET" -C "$WORK" ;;
    *.tar)                WORK="${TARGET%.tar}";          mkdir -p "$WORK"; tar xf  "$TARGET" -C "$WORK" ;;
    *)                    WORK="$(dirname "$TARGET")" ;;   # lone file: work in its folder
  esac
fi
WORK="$(readlink -f "$WORK")"
cd "$WORK"
mkdir -p solution

# ---- build an inventory for the prompt ------------------------------------
echo "[*] Challenge dir: $WORK"
MAXLIST="${MAXLIST:-250}"   # cap per-file listing so huge trees don't blow up the prompt
mapfile -t FILES < <(find . -type f -not -path './solution/*' -not -path './.recon/*' -not -name 'WRITEUP.md' | sort)
NFILES="${#FILES[@]}"
echo "[*] Files: $NFILES"

if (( NFILES <= MAXLIST )); then
  INVENTORY="$(
    echo "Files ($NFILES) — path — type:"
    for f in "${FILES[@]}"; do
      printf '  %s — %s\n' "$f" "$(file -b "$f" 2>/dev/null | cut -c1-80)"
    done
  )"
else
  # too many files to list individually: summarize by top dir + extension,
  # and list the few that actually look interesting for a CTF.
  INVENTORY="$(
    echo "$NFILES files (too many to list in full; summarized)."
    echo
    echo "Count by top-level dir:"
    printf '%s\n' "${FILES[@]}" | sed -E 's#^\./([^/]+).*#\1#' | sort | uniq -c | sort -rn | head -40 | sed 's/^/  /'
    echo
    echo "Count by extension:"
    printf '%s\n' "${FILES[@]}" | sed -E 's#.*/##; s#^[^.]+$#<none>#; s#.*\.#.#' | sort | uniq -c | sort -rn | head -40 | sed 's/^/  /'
    echo
    echo "Likely-interesting files (binaries / archives / docs / scripts):"
    for f in "${FILES[@]}"; do
      t="$(file -b "$f" 2>/dev/null)"
      case "$t" in
        *ELF*|*executable*|*archive*|*compressed*|*PDF*|*Python*|*shell\ script*|*data|*key*|*encrypted*|*database*)
          printf '  %s — %s\n' "$f" "$(echo "$t" | cut -c1-80)" ;;
      esac
    done | head -80
  )"
fi

# pull in any obvious description text so Claude starts with the prompt text
DESC=""; dcount=0
for d in README* readme* *.txt *.md challenge* prompt* description*; do
  [[ -f "$d" && "$d" != "WRITEUP.md" ]] || continue
  DESC+="$(printf '\n--- %s ---\n' "$d"; head -c 2000 "$d")"
  (( ++dcount >= 8 )) && break   # don't slurp hundreds of txt files
done

# ---- run zero-AI recon first and feed it to the model (RECON=0 to skip) ---
RECON="${RECON:-1}"
RECON_SECTION="<skipped (RECON=0)>"
if [[ "$RECON" == "1" && -x "$SELFDIR/ctf-recon.sh" ]]; then
  echo "[*] Running zero-AI recon first (OUT=$WORK/.recon)…"
  OUT="$WORK/.recon" QUIET=1 "$SELFDIR/ctf-recon.sh" "$WORK" >/dev/null 2>&1 || true
  if [[ -f "$WORK/.recon/REPORT.md" ]]; then
    RECON_SECTION="$(head -c 12000 "$WORK/.recon/REPORT.md")"
    echo "[*] Recon report ready: $WORK/.recon/REPORT.md"
  fi
fi

# ---- assemble the prompt --------------------------------------------------
PROMPT="You are solving a Capture The Flag (CTF) security challenge. This is an
authorized, educational CTF exercise. The challenge files are in the current
directory ($WORK).

Your job, end to end and autonomously:
1. Identify the category (pwn / rev / web / crypto / forensics / misc / stego / etc.)
   from the files and description below.
2. Analyze the artifacts using whatever tools fit (file, strings, binwalk, xxd,
   objdump, radare2/gdb, pwntools, python, steghide, zsteg, exiftool, nmap,
   curl, john/hashcat wordlists, etc.). Reason about the vulnerability.
3. Build and RUN a working solution. Put every script/exploit you write under
   ./solution/ with clear names. If it needs a remote target, note where to plug
   host:port in and still provide the local-proof exploit.
4. Recover the flag. Expected flag format: $FLAG_FMT.
5. Write ./WRITEUP.md: challenge name & category, TL;DR, the vulnerability,
   step-by-step solution path (commands + why), the exploit, and the final flag
   in a clearly marked 'Flag' section. If you could not get the flag, write how
   far you got and the exact blocker.

Work entirely on your own — do not ask me questions. Prefer running tools to
guessing. Be concise in WRITEUP.md but complete enough to reproduce.

A zero-AI recon pass (ctf-recon) has ALREADY been run for you — use its flag
candidates, checksec table, strings/binwalk/crypto findings as your starting
point instead of re-deriving them. Verify before trusting it; it can miss.

== ZERO-AI RECON REPORT ==
$RECON_SECTION

== INVENTORY ==
$INVENTORY

== DESCRIPTION FILES ==
${DESC:-<none found>}

== EXTRA HINT FROM USER ==
${HINT:-<none>}
"

# ---- permissions / network ------------------------------------------------
PERM=(--dangerously-skip-permissions)
[[ "${SAFE:-0}" == "1" ]] && PERM=(--permission-mode acceptEdits)

MODEL_ARG=()
[[ -n "$MODEL" ]] && MODEL_ARG=(--model "$MODEL")

if [[ "${NETWORK:-0}" != "1" ]]; then
  echo "[*] Network: OFFLINE (set NETWORK=1 to allow outbound)"
fi

echo "[*] Launching Claude Code (headless)…"
echo

# ---- run ------------------------------------------------------------------
# Pipe the prompt via stdin (not argv) so large inventories never hit ARG_MAX.
printf '%s' "$PROMPT" | claude -p \
  "${PERM[@]}" \
  "${MODEL_ARG[@]}" \
  --add-dir "$WORK"

if [[ "$QUIET" == "1" ]]; then
  # only the flag goes to the real terminal (fd 3); everything else was muted.
  flag="$(grep -oiE '[A-Za-z0-9_]{2,}\{[^}]{1,200}\}' "$WORK/WRITEUP.md" 2>/dev/null | head -1 || true)"
  printf '%s\n' "${flag:-no flag found — see $WORK/WRITEUP.md}" >&3
else
  echo
  echo "[*] Done. Output:"
  echo "    writeup : $WORK/WRITEUP.md"
  echo "    solution: $WORK/solution/"
  [[ -f "$WORK/WRITEUP.md" ]] && grep -iA2 '^#\{1,3\}.*flag' "$WORK/WRITEUP.md" | head -5 || true
fi
