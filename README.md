# Networks & System Security

**SIL765 & COL7165 - Assignment 2**  
**Deadline:** January 29, 2026

**Instructions**
- This assignment is a capture-the-flag problem.
- You will be given one single Ubuntu Linux image.
- There are five problem sets, each dependent on the previous.
- For each problem, you need to create a file in the stated format only.

## Problem 1: Gain Access

You are a penetration tester tasked with checking the system deployment of the national security agency. You have been made aware that not all users are following the security guidelines given to them. Try and find a way inside the system.

**Goal:** Obtain an unprivileged shell. Extract the flag stored inside the home folder.  
**Hint:** Think of ways that information may leak on a public server. How does one connect to the server to work?

**Solution Format**  
Submit a single zip file named `[EntryNumber]-P1.zip`, e.g., `2022CSZ228227-P1.zip`. The file should contain `public.txt`, `private.txt`, and `flag.txt`.

```text
[EntryNumber]-P1.zip
|-- public.txt
|-- private.txt
`-- flag.txt
```

## Problem 2: Become Super

Now that you have gained initial access to the NSA systems, your next task is to determine whether a local attacker can escalate privileges and gain administrative control of the machine.

**Goal:** Obtain a privileged (root) shell and extract the flag stored inside the root user's home directory.

**Hint:** You are provided with several executable programs inside the vulnerable user's home directory. Can they be used somehow?

**Solution Format**  
Submit a single zip file named `[EntryNumber]-P2.zip`, e.g., `2022CSZ228228-P2.zip`. The file should contain `public.txt`, `private.txt`, and `flag.txt`.

```text
[EntryNumber]-P2.zip
|-- public.txt
|-- private.txt
`-- flag.txt
```

## Problem 3: Changing the Flow

In this problem, you are provided with a standalone program that processes user input and makes internal decisions based on it. While the program appears to function normally, subtle implementation flaws may allow an attacker to redirect its execution.

**Goal:** Manipulate the program's execution flow to obtain the first protected flag.

**Hint:** Programs do not always execute instructions in the order intended by the developer. Carefully analyze how the program stores and returns control during execution.

**Solution Format**  
Submit a single zip file named `[EntryNumber]-P3.zip`, e.g., `2022CSZ228229-P3.zip`. The file should contain `public.txt`, `private.txt`, and `flag.txt`.

```text
[EntryNumber]-P3.zip
|-- public.txt
|-- private.txt
`-- flag.txt
```

## Problem 4: Trusted Code Reuse

In the previous problem, you explored how program execution can be redirected when control data is corrupted. The provided program incorporates additional execution protections to prevent attackers from injecting their own code. While direct code injection may no longer be possible, the program still relies on trusted system libraries during execution.

**Goal:** Leverage the existing code available on the system to obtain the second protected flag.

**Hint:** Even when new code cannot be executed, previously loaded code may still be invoked in unintended ways. Understanding how programs interact with system libraries may be helpful.

**Solution Format**  
Submit a single zip file named `[EntryNumber]-P4.zip`, e.g., `2022CSZ228230-P4.zip`. The file should contain `public.txt`, `private.txt`, and `flag.txt`.

```text
[EntryNumber]-P4.zip
|-- public.txt
|-- private.txt
`-- flag.txt
```

---

## Using VirtualBox on Linux, macOS, and Windows

### Overview

This section describes how to install **VirtualBox** as the virtualisation backend on Windows, Linux, and macOS systems.

- **VirtualBox** acts as the hypervisor responsible for running virtual machines.

### Architecture Overview

```text
+------------------+
| Host Operating   |
| System           |
| (Windows/Linux/  |
|  macOS)          |
+------------------+
|
v
+------------------+
| VirtualBox       |
| - Hypervisor     |
| - Runs VMs       |
+------------------+
|
v
+------------------+
| Guest OS         |
| (Linux VM, etc.) |
+------------------+
```

### System Requirements

#### Hardware Requirements

- 64-bit CPU with virtualisation support (Intel VT-x or AMD-V)
- Hardware virtualisation enabled in BIOS or UEFI
- Minimum 8 GB RAM recommended
- At least 20 GB of free disk space

#### Supported Host Operating Systems

- Windows 10 or Windows 11 (64-bit)
- Linux (modern distributions such as Ubuntu, Debian, Fedora, Arch)
- macOS (Intel and Apple Silicon; see notes below)

### Installing VirtualBox

VirtualBox must be installed before Vagrant, as Vagrant relies on an existing hypervisor.

#### Windows Installation

1. Download the Windows installer from the official VirtualBox website.
2. Run the `.exe` installer.
3. Accept default options unless specific networking restrictions apply.
4. Approve driver installation prompts when requested.
5. Reboot the system after installation if prompted.

#### Linux Installation

Most Linux distributions provide VirtualBox through their package manager.

**Debian / Ubuntu:**

```bash
sudo apt update
sudo apt install virtualbox
```

**Fedora:**

```bash
sudo dnf install VirtualBox
```

After installation, add your user to the `vboxusers` group:

```bash
sudo usermod -aG vboxusers $USER
```

Log out and back in for group changes to take effect.

#### macOS Installation

1. Download the macOS installer package from the VirtualBox website.
2. Open the `.dmg` file and run the installer.
3. Approve system extensions in `System Settings -> Security & Privacy` if prompted.
4. Reboot the system if required.

**Note:** On Apple Silicon systems (M1/M2/M3), VirtualBox support is limited. Linux ARM64 guests are required.
