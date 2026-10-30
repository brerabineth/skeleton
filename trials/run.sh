#!/usr/bin/env bash
# trials/run.sh — end-to-end checks for skeleton.
# usage: trials/run.sh [path-to-skeleton-binary]
# every command runs from trials/ with relative paths, so outputs never
# carry absolute machine paths; exits non-zero on any failed check.
set -u
cd "$(dirname "$0")"

BIN="${1:-../bin/Release/net8.0/linux-x64/publish/skeleton}"
if [ ! -x "$BIN" ]; then
  echo "no binary at $BIN — build first: dotnet publish -c Release -r linux-x64"
  exit 1
fi
BIN="$(readlink -f "$BIN")"
SCRATCH=".scratch-$$"
trap 'rm -rf "$SCRATCH"' EXIT
mkdir -p "$SCRATCH"

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf 'ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
assert_exit() { local want="$1" desc="$2"; shift 2; "$@" >/dev/null 2>&1; local got=$?;
  if [ "$got" = "$want" ]; then ok "$desc"; else bad "$desc (exit $got, want $want)"; fi; }
assert_has() { local id="$1" desc="$2" file="$3";
  if grep -q "$id" "$file"; then ok "$desc"; else bad "$desc (missing $id)"; fi; }
assert_hasnt() { local id="$1" desc="$2" file="$3";
  if grep -q "$id" "$file"; then bad "$desc (unexpected $id)"; else ok "$desc"; fi; }

# ---------- meta ----------
[ "$("$BIN" version)" = "skeleton 26.10.1" ] && ok "version string" || bad "version string"
assert_exit 0 "help exits 0" "$BIN" help
assert_exit 64 "no args exits 64" "$BIN"
assert_exit 64 "unknown command exits 64" "$BIN" telepathy
assert_exit 64 "bad flag value exits 64" "$BIN" sweep fixtures --fresh
assert_exit 1 "missing key path lands in watch band" "$BIN" keys fixtures/does-not-exist

# ---------- fp ----------
"$BIN" fp fixtures/id_ed25519.pub > "$SCRATCH/fp.txt" 2>&1
FPREAL="$(python3 - fixtures/id_ed25519.pub <<'PY'
import base64, hashlib, sys
tok = open(sys.argv[1]).read().split()
blob = base64.b64decode(tok[1] + '=' * (-len(tok[1]) % 4))
print('SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('='))
PY
)"
grep -q "$FPREAL" "$SCRATCH/fp.txt" && ok "fp matches ssh wire sha256" || bad "fp matches ssh wire sha256 (want $FPREAL)"
grep -q "256 bits" "$SCRATCH/fp.txt" && ok "fp reports bits" || bad "fp reports bits"
assert_exit 1 "fp on junk exits 1" "$BIN" fp fixtures/sshd_ok

# ---------- keys ----------
"$BIN" keys fixtures/id_ed25519 > "$SCRATCH/keys_plain.txt" 2>&1
assert_has "KEY_UNENCRYPTED" "unencrypted private key flagged" "$SCRATCH/keys_plain.txt"
"$BIN" keys fixtures/id_enc > "$SCRATCH/keys_enc.txt" 2>&1
assert_has "KEY_ENC_SAFE" "passphrase-protected key passes" "$SCRATCH/keys_enc.txt"
assert_hasnt "KEY_UNENCRYPTED" "no false unencrypted on protected key" "$SCRATCH/keys_enc.txt"
"$BIN" keys fixtures/id_rsa1024.pub > "$SCRATCH/keys_weak.txt" 2>&1
assert_has "KEY_RSA_WEAK" "1024-bit rsa flagged" "$SCRATCH/keys_weak.txt"
"$BIN" keys fixtures/weak_blob.pub > "$SCRATCH/keys_blob.txt" 2>&1
assert_has "KEY_RSA_WEAK" "512-bit wire blob flagged" "$SCRATCH/keys_blob.txt"
assert_has "KEY_DSA" "dss key flagged" "$SCRATCH/keys_blob.txt"
"$BIN" keys fixtures/id_ed25519.pub > "$SCRATCH/keys_pub.txt" 2>&1
assert_has "KEY_ED25519" "ed25519 inventoried clean" "$SCRATCH/keys_pub.txt"
"$BIN" keys fixtures/missing > "$SCRATCH/keys_missing.txt" 2>&1
assert_has "IO_MISSING" "missing path reported" "$SCRATCH/keys_missing.txt"
"$BIN" keys fixtures/id_ed25519 fixtures/id_enc --json > "$SCRATCH/keys.json" 2>/dev/null
python3 -c "import json;d=json.load(open('$SCRATCH/keys.json'));assert d['command']=='keys';assert d['count']>=2" \
  && ok "keys json parses with count" || bad "keys json parses with count"

# ---------- authorized ----------
"$BIN" authorized fixtures/ak_clean > "$SCRATCH/ak_clean.txt" 2>&1
assert_exit 0 "honest authorized_keys exits clean" "$BIN" authorized fixtures/ak_clean
assert_has "AUTH_UNCAGED" "uncaged lines inventoried" "$SCRATCH/ak_clean.txt"
assert_has "KEY_ECDSA" "key types inventoried" "$SCRATCH/ak_clean.txt"
assert_exit 3 "backdoor wrapper forces hostile" "$BIN" authorized fixtures/ak_min
"$BIN" authorized fixtures/ak_min > "$SCRATCH/ak_min.txt" 2>&1
assert_has "AUTH_CAGED_NET" "curl|sh wrapper caught" "$SCRATCH/ak_min.txt"
"$BIN" authorized fixtures/ak_jail > "$SCRATCH/ak_jail.txt" 2>&1
assert_has "AUTH_RESTRICT" "restrict option recognized" "$SCRATCH/ak_jail.txt"
"$BIN" authorized fixtures/ak_git > "$SCRATCH/ak_git.txt" 2>&1
assert_has "AUTH_CAGED_JAIL" "SSH_ORIGINAL_COMMAND jail recognized" "$SCRATCH/ak_git.txt"
"$BIN" authorized fixtures/ak_broad > "$SCRATCH/ak_broad.txt" 2>&1
assert_has "AUTH_FROM_BROAD" "from=* flagged" "$SCRATCH/ak_broad.txt"
assert_has "AUTH_NOPTY_ONLY" "bare no-pty flagged" "$SCRATCH/ak_broad.txt"
"$BIN" authorized fixtures/ak_badline > "$SCRATCH/ak_badline.txt" 2>&1
assert_has "AUTH_BADLINE" "tampered line flagged" "$SCRATCH/ak_badline.txt"
"$BIN" authorized fixtures/ak_ca > "$SCRATCH/ak_ca.txt" 2>&1
assert_has "AUTH_CA" "cert-authority noted" "$SCRATCH/ak_ca.txt"
"$BIN" authorized fixtures/ak_expired > "$SCRATCH/ak_expired.txt" 2>&1
assert_has "AUTH_EXPIRED" "expired key noted" "$SCRATCH/ak_expired.txt"
"$BIN" authorized fixtures/ak_dupA fixtures/ak_dupB > "$SCRATCH/ak_dup.txt" 2>&1
assert_has "AUTH_DUP" "same key across files flagged" "$SCRATCH/ak_dup.txt"

# ---------- config ----------
"$BIN" config fixtures/sshd_weak > "$SCRATCH/sshd_weak.txt" 2>&1
assert_exit 3 "weak sshd config exits hostile" "$BIN" config fixtures/sshd_weak
for id in CFG_ROOT_ANY CFG_PW_AUTH CFG_EMPTY_PW CFG_AKF_ODD CFG_AKCMD CFG_USERENV \
          CFG_WEAK_CIPHER CFG_WEAK_KEX CFG_WEAK_MAC CFG_X11 CFG_GATEWAY CFG_INCLUDE_ODD CFG_UNKNOWN; do
  assert_has "$id" "sshd_weak catches $id" "$SCRATCH/sshd_weak.txt"
done
assert_exit 0 "hardened sshd config exits clean" "$BIN" config fixtures/sshd_ok
"$BIN" config fixtures/client_bad > "$SCRATCH/client_bad.txt" 2>&1
assert_exit 3 "bad client config exits hostile" "$BIN" config fixtures/client_bad
for id in CFG_STRICT_NO CFG_KNOWN_DEVNULL CFG_FWDAGENT CFG_PROXY_ODD; do
  assert_has "$id" "client_bad catches $id" "$SCRATCH/client_bad.txt"
done
assert_exit 0 "clean client config exits clean" "$BIN" config fixtures/client_ok

# ---------- known ----------
"$BIN" known fixtures/known_hashed --check gitlab.com > "$SCRATCH/kh_h.txt" 2>&1
assert_has "KH_MATCH" "hashed hostname verifies via hmac" "$SCRATCH/kh_h.txt"
assert_hasnt "KH_PLAINTEXT" "hashed-only file leaks nothing" "$SCRATCH/kh_h.txt"
"$BIN" known fixtures/known_full > "$SCRATCH/kh_full.txt" 2>&1
for id in KH_CA KH_REVOKED KH_PLAINTEXT KH_CONFLICT KH_DUP KH_PORT; do
  assert_has "$id" "known_full catches $id" "$SCRATCH/kh_full.txt"
done
"$BIN" known fixtures/known_full --check nowhere.invalid > "$SCRATCH/kh_miss.txt" 2>&1
assert_has "no pinned record" "unseen host reported" "$SCRATCH/kh_miss.txt"

# ---------- sweep ----------
TREE="$SCRATCH/tree"
mkdir -p "$TREE/home/alice/.ssh" "$TREE/home/bob/.ssh" "$TREE/tmp/planted"
cp fixtures/id_ed25519 "$TREE/home/alice/.ssh/id_ed25519";        chmod 600 "$TREE/home/alice/.ssh/id_ed25519"
cp fixtures/id_rsa2048 "$TREE/home/alice/.ssh/id_rsa";            chmod 644 "$TREE/home/alice/.ssh/id_rsa"
cp fixtures/id_ecdsa.pub "$TREE/home/alice/.ssh/authorized_keys"; chmod 600 "$TREE/home/alice/.ssh/authorized_keys"
cp fixtures/id_ecdsa.pub "$TREE/home/bob/.ssh/authorized_keys2";  chmod 600 "$TREE/home/bob/.ssh/authorized_keys2"
cp fixtures/id_ecdsa.pub "$TREE/tmp/planted/authorized_keys";     chmod 600 "$TREE/tmp/planted/authorized_keys"
printf '#!/bin/sh\nlogger login\n' > "$TREE/home/alice/.ssh/rc";  chmod 600 "$TREE/home/alice/.ssh/rc"
"$BIN" sweep "$TREE/home" "$TREE/tmp" > "$SCRATCH/sweep.txt" 2>&1
assert_exit 3 "planted tree exits hostile" "$BIN" sweep "$TREE/home" "$TREE/tmp"
for id in SWP_TMP_PLANT SWP_KEY_WORLD_READ SWP_RC SWP_AK2 SWP_AK_TWIN; do
  assert_has "$id" "sweep catches $id" "$SCRATCH/sweep.txt"
done
assert_hasnt "SWP_WORLD_WRITE" "no false world-write on 600 files" "$SCRATCH/sweep.txt"
"$BIN" sweep "$TREE/home/alice/.ssh/id_ed25519" > "$SCRATCH/sweep_one.txt" 2>&1
assert_hasnt "SWP_" "well-placed 600 key sweeps silent" "$SCRATCH/sweep_one.txt"
touch -d "2 days ago" "$TREE/home/alice/.ssh/authorized_keys"
"$BIN" sweep "$TREE/home" --fresh 7 > "$SCRATCH/sweep_fresh.txt" 2>&1
assert_has "SWP_FRESH" "fresh mtime noted" "$SCRATCH/sweep_fresh.txt"
grep -q "3 authorized" "$SCRATCH/sweep.txt" && ok "inventory counts authorized files" || bad "inventory counts authorized files"

# ---------- output discipline ----------
env -u NO_COLOR SKELETON_FORCE_COLOR=1 "$BIN" authorized fixtures/ak_min > "$SCRATCH/color.txt" 2>/dev/null
grep -q $'\033\[' "$SCRATCH/color.txt" && ok "forced color emits ansi" || bad "forced color emits ansi"
"$BIN" authorized fixtures/ak_min > "$SCRATCH/plain.txt" 2>/dev/null
grep -q $'\033\[' "$SCRATCH/plain.txt" && bad "redirected output stays plain" || ok "redirected output stays plain"
NO_COLOR=1 "$BIN" authorized fixtures/ak_min > "$SCRATCH/nocolor.txt" 2>/dev/null
grep -q $'\033\[' "$SCRATCH/nocolor.txt" && bad "NO_COLOR honored" || ok "NO_COLOR honored"
"$BIN" sweep "$TREE/home" "$TREE/tmp" --json > "$SCRATCH/sweep.json" 2>/dev/null
python3 - "$SCRATCH" <<'PY' && ok "sweep json fields complete" || bad "sweep json fields complete"
import json, sys
d = json.load(open(sys.argv[1] + "/sweep.json"))
assert d["tool"] == "skeleton"
assert d["band"] == "hostile"
assert d["forced"] is True
for f in d["findings"]:
    assert set(f) == {"id", "sev", "weight", "where", "note"}
PY
! grep -rq "/home/z" "$SCRATCH" 2>/dev/null && ok "no host paths in any output" || bad "no host paths in any output"
! grep -rq "github_pat" "$SCRATCH" 2>/dev/null && ok "no token-shaped strings in outputs" || bad "no token-shaped strings in outputs"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
