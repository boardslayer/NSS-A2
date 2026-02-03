# NSS Assignment 2 - CTF Security Challenges

This is a Networks & System Security course assignment containing 4 progressive penetration testing challenges (P1-P4) designed as a capture-the-flag (CTF) competition.

## Architecture Overview

**Single VM Setup**: All challenges run on one Ubuntu 22.04 VM managed through VirtualBox/Vagrant
- VM accessible via SSH on port 2222 and HTTP on port 8000  
- Problems are interconnected: P1 → P2 → P3 → P4 (each builds on previous)
- Flags are dynamically generated per VM boot using a key system

**Key Components**:
- `/build/`: VM provisioning and setup infrastructure
- `/p1/` - `/p4/`: Individual problem directories with challenges and solutions
- `/solution/`: Reference solutions and testing procedures

## Critical Workflows

**VM Setup & Testing**:
```bash
# Initial VM creation (host)
vagrant up                          # Start VM with Vagrantfile
scp -P 2222 p1/provision_p1.sh ctfadmin@localhost:~/

# Inside VM - provision each problem
sudo bash /home/ctfadmin/provision_p1.sh
sudo bash /home/ctfadmin/provision_p2.sh
sudo bash /home/ctfadmin/provision_p3.sh
```

**Challenge Testing Flow**:
```bash
# P1: Information disclosure → SSH access
curl http://localhost:8000/robots.txt
ssh -i id_rsa -p 2222 p1@localhost

# Inside VM: Generate flags
ctf-extract  # Generates flag.txt and key.txt per problem
```

**Solution Validation**:
- Use `verify_p*.py` scripts to validate extracted flags
- Flags depend on per-boot key stored in P1 user profile
- Submit as tarballs: `[EntryNumber]-P[1-4].tar.gz`

## Problem-Specific Patterns

**P1 (Gain Access)**: Information disclosure vulnerability
- Nginx serves leaked SSH keys at `/backup/id_rsa`
- SSH key authentication to user `p1`

**P2 (Become Super)**: SUID privilege escalation
- Vulnerable binary `/home/p1/p2/p2` with stack overflow
- Contains `win()` function for privilege escalation

**P3-P4 (Buffer Overflow Exploitation)**: 
- Classic stack buffer overflows using `gets()`
- P3: Return address overwrite to `win()` function
- P4: ROP/library reuse under execution protections

## Development Conventions

**File Organization**:
- Provision scripts: `provision_p*.sh` (run as root in VM)
- Verification: `verify_p*.py` (validate extracted flags)
- Source code: `p*.c` (vulnerable binaries for exploitation)
- Solutions: Tarball format with `flag.txt` and `key.txt`

**Security Testing Approach**:
- All challenges use real vulnerabilities (buffer overflow, info disclosure, SUID)
- Flags are regenerated on each VM boot to prevent static solutions
- Use `nm`, `gdb`, `file` commands to analyze binaries
- Exploit development uses pwntools for payload generation

**VM Network Configuration**:
- Port forwarding: 2222→22 (SSH), 8000→80 (HTTP)
- Decoy ports 9001, 9002 for reconnaissance training
- All services run locally within single VM

## Integration Points

**Boot-time Key Generation**: 
- P1 user profile contains master key for flag generation
- `ctf-extract` command generates problem-specific flags using this key
- Verification scripts validate flag-to-key relationships

**Cross-Problem Dependencies**:
- P1 access required for P2 binary location
- P2 root access needed for P3/P4 flag extraction
- Each problem's solution enables access to next challenge

**Build System**: Vagrant + VirtualBox for consistent VM deployment across ARM64/AMD64 hosts