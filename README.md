# skeleton

first-hour autopsy for ssh artifacts — keys, authorized_keys backdoors, weakened
configs, known_hosts ghosts. one static binary, zero dependencies, nothing
leaves the machine.

late october 2026: a malicious extension riding a commercial AI code editor
planted ssh backdoors on developer machines while their owners watched a
coding agent work. that is not an exotic story. ssh keys are the persistence
layer that survives every cleanup — kill the extension, rotate the tokens,
wipe the profile, and the one line an intruder added to `authorized_keys`
still opens the door at 3am.

skeleton is the tool you reach for in that first hour. it reads the artifacts,
scores what it finds, and hands you a verdict — offline, read-only, with no
agent, no daemon and no network calls of its own.

## the instruments

| command | what it pulls out of the body |
| --- | --- |
| `keys PATH...` | inventory every key: algorithm, bits, sha256 fingerprint, passphrase state, file permissions. flags dsa, sub-2048 rsa, unencrypted identities, world-readable privates |
| `authorized FILE...` | authorized_keys audit per line: caged vs uncaged keys, forced-command analysis (jails, interpreters, network pullers), `from=` breadth, option tampering, cross-file duplicate keys |
| `config FILE...` | sshd_config and ssh_config: relocated `AuthorizedKeysFile`, external key commands, empty passwords, weak ciphers/kex/macs, disabled host checking, `/dev/null` known hosts, suspicious `Include` paths |
| `known FILE... [--check HOST,...]` | known_hosts: verifies `|1|` hashed entries by hmac, lists cas and revoked keys, catches torn tofu resets (same host, different key), duplicate pins, plaintext hostname sprawl |
| `sweep ROOT... [--fresh N]` | filesystem hunt: authorized_keys outside any `.ssh`, identities planted in scratch space, `.ssh/rc` login hooks, legacy `authorized_keys2`, world-writable directories, twin files, recently-touched artifacts |
| `fp PATH...` | one fingerprint line per key, for timelines and tickets |

every run ends in a scored verdict:

```
clean        0-9      exit 0
watch       10-29     exit 1
suspicious  30-59     exit 2
hostile     60+       exit 3   (or any forced-hostile finding)
```

forced-hostile rules fire on shapes that should not exist on a healthy
machine: `curl|sh` forced commands, empty passwords, `/dev/null` known hosts,
world-writable `.ssh` directories, identities in `/tmp`.

## quick start

grab a release binary for linux-x64, linux-arm64, osx-arm64 or win-x64 —
each is self-contained, no runtime to install:

```
./skeleton sweep /home /etc/ssh --fresh 3
./skeleton authorized ~/.ssh/authorized_keys
./skeleton config /etc/ssh/sshd_config
./skeleton known ~/.ssh/known_hosts --check bastion.corp
```

build from source instead (needs any .net 8 sdk):

```
dotnet publish -c Release -r linux-x64
trials/run.sh
```

## machine output

`--json` on any instrument emits one line: score, band, forced flag, and
every finding with id, severity, weight, location and note — built for
pipes, timelines and log shipping.

```
{"tool":"skeleton","version":"26.10.1","command":"authorized","score":90,
 "band":"hostile","forced":true,"count":2,"findings":[{"id":"AUTH_CAGED_NET",...}]}
```

## scope, honestly

skeleton reads artifacts that already exist on disk. it does not scan
networks, does not talk to agents, does not attempt live brute force, and
does not replace a full forensic platform — it answers one question fast:
*what keys can open this machine, and which of them look planted?*

the findings map to mitre att&ck: t1098.004 (ssh authorized keys),
t1021.004 (ssh lateral movement), plus the account-manipulation and
persistence families around them.

## trials

`trials/run.sh` is the end-to-end suite: forged fixtures (openssh keys,
hand-built wire blobs, hashed known_hosts, planted trees) and 77 checks
covering every instrument, the verdict bands, the exit codes, json shape,
color discipline and output hygiene. `trials/forge.sh` re-derives every
fixture from scratch.

## license

isc — see LICENSE.
