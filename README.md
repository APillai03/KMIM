# KMIM - Kernel Module Integrity Monitor

A kernel integrity monitoring tool built with eBPF for detecting rootkits, malicious kernel modules, and runtime anomalies.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Security Considerations](#security-considerations)
- [Development](#development)
- [Author](#author)

---

## 🎯 Overview

KMIM is a security tool that monitors the integrity of Linux kernel modules. Unlike traditional file integrity checkers, KMIM uses **eBPF (Extended Berkeley Packet Filter)** to safely introspect kernel activity in real-time without loading kernel modules or risking system stability.

**Use Cases:**
- Detect rootkits and malicious kernel modules
- Monitor kernel module load/unload events in real-time
- Verify kernel module integrity against a trusted baseline
- Detect hidden modules that hide from `/proc/modules`
- Track syscall table modifications

---

## ✨ Features

### 1. **Baseline Capture**
- Snapshot all loaded kernel modules
- Calculate SHA256 hashes of module files
- Extract ELF sections and compiler information
- Capture syscall table addresses

### 2. **Integrity Scanning**
- Compare current kernel state against baseline
- Detect added, removed, or modified modules
- Identify hash mismatches
- Compare syscall table addresses

### 3. **Hidden Module Detection**
- Cross-reference `/proc/modules` with `/proc/kallsyms`
- Detect modules hiding from standard interfaces
- Identify potential rootkit behavior

### 4. **Real-time Monitoring (eBPF)**
- Live monitoring of module load/unload events
- No kernel module required (uses eBPF)
- Captures module name, timestamp, PID, and process name
- Safe and verified by kernel

### 5. **Detailed Inspection**
- View module metadata (size, address, file path)
- Display ELF sections
- Show compiler information
- Calculate and verify hashes

---

## 🏗️ Architecture

### Components

```
KMIM
├── Baseline Operations
│   ├── Read /proc/modules
│   ├── Extract module metadata (modinfo)
│   ├── Calculate SHA256 hashes
│   ├── Parse ELF sections (readelf)
│   └── Capture syscall addresses (kallsyms)
│
├── Scanning Engine
│   ├── Compare modules (added/removed/modified)
│   ├── Hash verification
│   ├── Hidden module detection
│   └── Syscall table integrity check
│
├── eBPF Monitor
│   ├── Attach kprobes to kernel functions
│   │   ├── do_init_module (module load)
│   │   └── free_module (module unload)
│   ├── Capture events in kernel space
│   └── Forward to userspace via perf ring buffer
│
└── CLI Interface
    ├── baseline - Capture baseline
    ├── scan - Integrity scan
    ├── show - Module details
    └── monitor - Live eBPF monitoring
```

### Data Flow

```
┌─────────────────┐
│  Kernel Space   │
│                 │
│  ┌───────────┐  │     eBPF Program
│  │  Module   │◄─┼─────(kprobe hooks)
│  │  Loading  │  │
│  └───────────┘  │
│                 │
│  /proc/modules  │◄────┐
│  /proc/kallsyms │◄────┼─── KMIM reads
│  module files   │◄────┘
└─────────────────┘
         │
         ▼
┌─────────────────┐
│  User Space     │
│                 │
│  ┌───────────┐  │
│  │   KMIM    │  │
│  │    CLI    │  │
│  └───────────┘  │
│        │        │
│        ▼        │
│  baseline.json  │
└─────────────────┘
```

---

## 📦 Installation

### Prerequisites

**Operating System:**
- Linux with kernel 4.4+ (eBPF support)
- Tested on: Ubuntu 20.04+, Debian 11+, Kali Linux 2023+

**Required Packages:**

```bash
# Debian/Ubuntu/Kali
sudo apt update
sudo apt install -y \
    bpfcc-tools \
    python3-bpfcc \
    linux-headers-$(uname -r) \
    python3-pip

# Python dependencies
pip3 install rich
```

**Alternative (pip-only, may not work on all systems):**
```bash
pip3 install bcc rich
```

### Verify Installation

```bash
# Check BCC
python3 -c "from bcc import BPF; print('✓ BCC installed')"

# Check Rich
python3 -c "from rich import print; print('✓ Rich installed')"

# Check kernel headers
ls /lib/modules/$(uname -r)/build
```

### Get KMIM

```bash
# Save the Python script as kmim.py
chmod +x kmim.py

# Or create a symlink for convenience
sudo ln -s $(pwd)/kmim.py /usr/local/bin/kmim
```

---

## 🚀 Usage

### Basic Commands

```bash
# Capture baseline (requires root)
sudo python3 kmim.py baseline kmim_baseline.json

# Scan for changes
sudo python3 kmim.py scan kmim_baseline.json

# Show module details
sudo python3 kmim.py show ext4

# Live monitoring
sudo python3 kmim.py monitor
```

### Command Reference

#### 1. `baseline <file.json>`

Captures the current state of all loaded kernel modules and saves to a JSON file.

**What it captures:**
- Module names, sizes, and memory addresses
- SHA256 hashes of module files
- ELF sections (`.text`, `.data`, `.rodata`, etc.)
- Compiler information (GCC/Clang version)
- Syscall table addresses

**Example:**
```bash
sudo python3 kmim.py baseline my_baseline.json
```

**Output:**
```
Capturing kernel baseline...
Processing modules... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
Capturing syscall addresses...
✓ Captured baseline of 127 modules, 12 syscall addresses
Saved to my_baseline.json
```

---

#### 2. `scan <file.json>`

Compares the current kernel state against a previously captured baseline.

**What it detects:**
- ✅ Modules matching baseline (OK)
- ⚠️ Removed modules (WARNING)
- 🚨 Added modules (ALERT)
- 🚨 Modified modules - size or hash mismatch (ALERT)
- 🚨 Hidden modules - present in kallsyms but not /proc/modules (ALERT)
- 🚨 Syscall table modifications (ALERT)

**Example:**
```bash
sudo python3 kmim.py scan my_baseline.json
```

**Output (Clean System):**
```
Loading baseline...
Scanning current kernel state...
Checking for hidden modules...

============================================================
INFO All modules match baseline
INFO No hidden modules

Summary: 127 OK, 0 Suspicious
============================================================
```

**Output (Suspicious Activity):**
```
Loading baseline...
Scanning current kernel state...
Checking for hidden modules...

============================================================
ALERT Added modules: malicious_rootkit
ALERT Modified modules: usbcore
ALERT Syscall table modifications detected:
  sys_call_table: 0xffffffff81c00000 → 0xffffffff81c00100

Summary: 125 OK, 3 Suspicious
============================================================
```

---

#### 3. `show <module>`

Displays detailed information about a specific kernel module.

**Example:**
```bash
sudo python3 kmim.py show ext4
```

**Output:**
```
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Field        ┃ Value                                         ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Name         │ ext4                                          │
│ Size         │ 1048576                                       │
│ Addr         │ 0xffffffffc0a00000                            │
│ Hash         │ sha256:abc123def456...                        │
│ File         │ /lib/modules/6.12.0/kernel/fs/ext4/ext4.ko   │
│ Compiler     │ GCC (Ubuntu 11.4.0-1ubuntu1~22.04)           │
│ ELF Sections │ .text, .data, .rodata, .bss, .init.text      │
└──────────────┴───────────────────────────────────────────────┘
```

**Notes:**
- Searches baseline file first (default: `kmim_baseline.json`)
- Falls back to current system if not in baseline
- Use `--baseline <file>` to specify different baseline file

---

#### 4. `monitor`

Starts real-time eBPF-based monitoring of kernel module events.

**What it monitors:**
- Module load events (when modules are inserted)
- Module unload events (when modules are removed)
- Process information (PID, command name)
- Timestamps

**Example:**
```bash
sudo python3 kmim.py monitor
```

**Output:**
```
Starting eBPF monitoring...
Press Ctrl+C to stop
Monitoring kernel module load/unload events...

✓ Monitoring module loads via do_init_module
✓ Monitoring module unloads via free_module

Waiting for module events...
Try: sudo modprobe dummy (if available) or load/unload any module

14:23:15.123 [LOAD  ] fuse                 (PID: 1234, by: modprobe)
14:23:20.456 [UNLOAD] fuse                 (PID: 1235, by: modprobe)
14:25:10.789 [LOAD  ] usbhid               (PID: 5678, by: systemd-udevd)
```

**Stop monitoring:** Press `Ctrl+C`

---

## 🔬 How It Works

### 1. Baseline Capture

**Step-by-step:**

1. **Read `/proc/modules`**
   - Lists all currently loaded kernel modules
   - Extracts: name, size, memory address

2. **Get module file paths**
   - Uses `modinfo -n <module>` to find `.ko` file
   - Some built-in modules don't have files

3. **Calculate SHA256 hashes**
   - Reads module file in chunks
   - Generates cryptographic hash for integrity verification

4. **Extract ELF metadata**
   - Uses `readelf -S` to list ELF sections
   - Identifies code (`.text`), data (`.data`), etc.

5. **Detect compiler**
   - Uses `strings` to search for compiler signatures
   - Identifies GCC or Clang versions

6. **Capture syscall addresses**
   - Reads `/proc/kallsyms` for symbol addresses
   - Records addresses of critical syscalls

7. **Save to JSON**
   - Structured format for easy comparison
   - Timestamped for audit trail

**Example baseline JSON:**
```json
{
  "captured_at": "2025-10-10T14:30:00.000Z",
  "modules": [
    {
      "name": "ext4",
      "size": 1048576,
      "addr": "0xffffffffc0a00000",
      "file": "/lib/modules/6.12.0/kernel/fs/ext4/ext4.ko",
      "hash": "abc123def456...",
      "elf_sections": [".text", ".data", ".rodata"],
      "compiler": "GCC 11.4.0"
    }
  ],
  "syscalls": {
    "sys_call_table": "0xffffffff81c00000",
    "__x64_sys_execve": "0xffffffff810a1234"
  }
}
```

---

### 2. Integrity Scanning

**Detection mechanisms:**

**A. Module Comparison**
- Creates sets of baseline vs current modules
- Identifies added/removed modules
- Flags any differences

**B. Hash Verification**
- Recalculates SHA256 of current module files
- Compares against baseline hashes
- Detects file modifications or replacements

**C. Size Validation**
- Checks if module size changed
- Size changes indicate recompilation or tampering

**D. Hidden Module Detection**
- Reads `/proc/kallsyms` symbol table
- Extracts module names from symbols like `function_name [module_name]`
- Compares with `/proc/modules` list
- **Hidden modules** appear in kallsyms but not in /proc/modules

**E. Syscall Table Integrity**
- Re-reads `/proc/kallsyms`
- Compares syscall addresses with baseline
- Detects syscall table hooking (common rootkit technique)

---

### 3. eBPF Monitoring

**How eBPF works:**

1. **Compilation**
   - eBPF C program compiled to bytecode
   - Verified by kernel (no crashes, no infinite loops)

2. **Kernel Function Hooking**
   - Attaches kprobes to:
     - `do_init_module` - called when module loads
     - `free_module` - called when module unloads

3. **Event Capture**
   - Runs in kernel context (very fast)
   - Captures module pointer from function arguments
   - Reads module name from `struct module`
   - Records timestamp, PID, process name

4. **Userspace Forwarding**
   - Events sent via perf ring buffer
   - Minimal overhead (<1% CPU)
   - Python callback processes events

5. **Display**
   - Real-time output with color coding
   - Shows what's happening in the kernel

**Why eBPF is safe:**
- Cannot crash the kernel (verified)
- Cannot access arbitrary memory
- Cannot write to kernel memory
- Cannot run forever (bounded loops)
- Sandboxed execution environment

---

## 📚 Examples

### Example 1: Initial System Baseline

```bash
# Fresh system, create baseline
sudo python3 kmim.py baseline baseline_clean.json

# Check what was captured
ls -lh baseline_clean.json
cat baseline_clean.json | jq '.modules | length'
# Output: 127

# All modules should be OK
sudo python3 kmim.py scan baseline_clean.json
# INFO All modules match baseline
# INFO No hidden modules
# Summary: 127 OK, 0 Suspicious
```

---

### Example 2: Detecting New Module

```bash
# Capture baseline
sudo python3 kmim.py baseline before.json

# Load a new module
sudo modprobe loop

# Scan for changes
sudo python3 kmim.py scan before.json
# ALERT Added modules: loop
# Summary: 127 OK, 1 Suspicious

# Remove module
sudo modprobe -r loop

# Scan again - should detect removal
sudo python3 kmim.py scan before.json
# WARNING Removed modules: loop
# Summary: 127 OK, 1 Suspicious
```

---

### Example 3: Real-time Monitoring

```bash
# Terminal 1: Start monitoring
sudo python3 kmim.py monitor

# Terminal 2: Load/unload modules
sudo modprobe fuse
sudo modprobe -r fuse
sudo modprobe usbhid
sudo modprobe -r usbhid

# Terminal 1 will show:
# 14:30:00.123 [LOAD  ] fuse      (PID: 1234, by: modprobe)
# 14:30:05.456 [UNLOAD] fuse      (PID: 1235, by: modprobe)
# 14:30:10.789 [LOAD  ] usbhid    (PID: 1236, by: modprobe)
# 14:30:15.012 [UNLOAD] usbhid    (PID: 1237, by: modprobe)
```

---

### Example 4: Module Inspection

```bash
# Show details of specific modules
sudo python3 kmim.py show ext4
sudo python3 kmim.py show usbcore
sudo python3 kmim.py show bluetooth

# From a specific baseline
sudo python3 kmim.py show ext4 --baseline my_baseline.json
```

---

### Example 5: Security Audit

```bash
# 1. Baseline on known-good system
sudo python3 kmim.py baseline golden_baseline.json

# 2. Deploy to production servers
scp golden_baseline.json server1:/opt/kmim/
scp kmim.py server1:/opt/kmim/

# 3. Regular scanning (cron job)
0 */4 * * * /usr/bin/python3 /opt/kmim/kmim.py scan /opt/kmim/golden_baseline.json >> /var/log/kmim.log

# 4. Alert on suspicious activity
sudo python3 kmim.py scan golden_baseline.json | grep -q "Suspicious" && \
    echo "ALERT: Kernel integrity violation detected" | mail -s "Security Alert" admin@company.com
```

---

## 🔧 Troubleshooting

### Issue: "BCC not installed"

**Error:**
```
Error: BCC not installed
Install with: apt install bpfcc-tools python3-bpfcc
```

**Solution:**
```bash
# Ubuntu/Debian/Kali
sudo apt install bpfcc-tools python3-bpfcc

# Check installation
python3 -c "from bcc import BPF; print('OK')"
```

---

### Issue: "Could not attach to any module functions"

**Error:**
```
Error: Could not attach to any module functions
```

**Diagnosis:**
```bash
# Check if kernel exposes module functions
cat /proc/kallsyms | grep -E 'do_init_module|finish_module|free_module'

# Should see lines like:
# ffffffff810b1234 T do_init_module
# ffffffff810b5678 T free_module
```

**Solutions:**
1. **Missing kernel headers:**
   ```bash
   sudo apt install linux-headers-$(uname -r)
   ```

2. **Kernel doesn't support kprobes:**
   ```bash
   # Check config
   grep CONFIG_KPROBES /boot/config-$(uname -r)
   # Should be: CONFIG_KPROBES=y
   ```

3. **Kernel too old (< 4.4):**
   - Upgrade kernel or use alternative monitoring methods

---

### Issue: "/proc/kallsyms access restricted"

**Warning:**
```
Warning: /proc/kallsyms access restricted. Syscall tracking unavailable.
```

**Cause:**
- `kptr_restrict` sysctl prevents unprivileged kallsyms access

**Check:**
```bash
cat /proc/sys/kernel/kptr_restrict
# 0 = unrestricted
# 1 = restricted to root
# 2 = completely restricted
```

**Solution:**
```bash
# Temporarily allow (until reboot)
sudo sysctl -w kernel.kptr_restrict=0

# Permanently allow (not recommended for production)
echo "kernel.kptr_restrict = 0" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

**Security Note:** Only disable `kptr_restrict` on trusted systems for testing.

---

### Issue: "This command requires root privileges"

**Error:**
```
Error: This command requires root privileges.
Please run with sudo.
```

**Solution:**
```bash
# Always use sudo
sudo python3 kmim.py baseline baseline.json
sudo python3 kmim.py scan baseline.json
sudo python3 kmim.py monitor
```

**Why root is required:**
- Reading `/proc/kallsyms`
- Accessing `/proc/modules`
- Loading eBPF programs
- Attaching kernel probes

---

### Issue: eBPF compilation errors

**Error:**
```
/virtual/main.c:27:66: error: no member named 'name' in 'struct ...'
```

**Cause:** Kernel version incompatibility

**Solution:** The current version handles this automatically. If you still get errors:

```bash
# Check kernel version
uname -r

# Update to latest kernel
sudo apt update && sudo apt upgrade

# Install kernel headers
sudo apt install linux-headers-$(uname -r)
```

---

### Issue: Module file not found

**Warning during baseline:**
```
Module 'some_module' file not found
```

**Causes:**
1. Built-in modules (compiled into kernel, no `.ko` file)
2. Module unloaded but still in /proc/modules temporarily
3. Non-standard module location

**This is usually normal** - built-in modules don't have separate files.

---

### Issue: High CPU usage during monitoring

**Symptoms:**
- `python3` process using high CPU
- System slowdown during `kmim monitor`

**Solutions:**

1. **Check event frequency:**
   ```bash
   # If modules load/unload very frequently, this is normal
   # Consider filtering events
   ```

2. **Reduce output:**
   - Redirect output to file instead of terminal
   ```bash
   sudo python3 kmim.py monitor > /var/log/kmim_monitor.log
   ```

3. **Use batch mode (future enhancement):**
   - Aggregate events and display periodically

---

## ⚠️ Limitations

### 1. **Rootkit Evasion**

**What KMIM can detect:**
- Modules appearing in /proc/modules
- Modules leaving traces in kallsyms
- File-based module modifications
- Syscall table hooking (kallsyms-visible)

**What KMIM cannot detect:**
- Rootkits that modify kernel memory structures directly
- Rootkits that hook kallsyms itself
- Hardware-level attacks (DMA, firmware)
- Hypervisor-level rootkits

**Mitigation:** Use KMIM as part of defense-in-depth strategy, not as sole protection.

---

### 2. **Kernel Configuration Dependencies**

**Required kernel features:**
- CONFIG_KPROBES=y
- CONFIG_BPF=y
- CONFIG_BPF_EVENTS=y
- CONFIG_KALLSYMS=y

**Check your kernel:**
```bash
grep -E 'CONFIG_KPROBES|CONFIG_BPF|CONFIG_KALLSYMS' /boot/config-$(uname -r)
```

---

### 3. **Performance Impact**

**eBPF Monitoring:**
- Minimal (<1% CPU) in normal conditions
- Higher if modules load/unload frequently
- Memory overhead: ~5-10 MB

**Baseline/Scan:**
- CPU: High during scan (reading files, hashing)
- I/O: Reads all module files
- Duration: ~5-30 seconds depending on module count

---

### 4. **False Positives**

**Legitimate changes that trigger alerts:**
- Kernel updates (module sizes/hashes change)
- Module parameters changed
- Dynamic module loading by system services
- USB devices (usbhid, usb_storage auto-load)

**Best practices:**
- Update baseline after kernel updates
- Whitelist known-good auto-loading modules
- Review alerts in context

---

### 5. **/proc/kallsyms Restrictions**

- `kptr_restrict=2` prevents all kallsyms access
- `kptr_restrict=1` requires root
- Some distributions hide kernel pointers by default

**Impact:** Syscall monitoring and hidden module detection may not work.

---

## 🔒 Security Considerations

### Safe by Design

1. **Read-only operations:** KMIM never modifies kernel memory
2. **eBPF verification:** Kernel ensures eBPF programs cannot crash system
3. **No kernel modules:** Doesn't load `.ko` files (safer than LKM-based tools)
4. **Sandboxed execution:** eBPF runs in restricted environment

### Threat Model

**KMIM protects against:**
- ✅ Script-kiddie rootkits (basic hiding techniques)
- ✅ Kernel module malware (unauthorized modules)
- ✅ Syscall table hooking (if visible in kallsyms)
- ✅ Module file replacement
- ✅ Supply chain attacks (detects unauthorized modules)

**KMIM does NOT protect against:**
- ❌ Advanced rootkits that hook kallsyms itself
- ❌ Kernel code injection without modules
- ❌ Hardware-based attacks
- ❌ Firmware malware
- ❌ Attacks that occur before KMIM runs

### Operational Security

1. **Secure baseline storage:**
   ```bash
   # Store baseline on read-only media
   sudo cp baseline.json /media/readonly/
   
   # Or use cryptographic signatures
   sha256sum baseline.json > baseline.json.sha256
   ```

2. **Regular scanning:**
   ```bash
   # Automated cron job
   0 */4 * * * /opt/kmim/scan_and_alert.sh
   ```

3. **Audit logging:**
   ```bash
   # Log all scan results
   sudo python3 kmim.py scan baseline.json | tee -a /var/log/kmim_audit.log
   ```

4. **Incident response:**
   - If KMIM detects anomalies, investigate immediately
   - Isolate system from network
   - Collect forensic evidence
   - Restore from known-good backup

---

## 🛠️ Development

### Extending KMIM

**Add new detection method:**

1. Edit scanning logic in `scan_against_baseline()`
2. Add new checks (e.g., check `/dev/mem` access, analyze dmesg)
3. Update output formatting

**Example - Add network module check:**
```python
def check_network_modules(baseline, current):
    net_modules = ['e1000e', 'iwlwifi', 'ath9k']
    for mod in net_modules:
        if mod in current and mod not in baseline:
            console.print(f"[red]ALERT: Network module {mod} added[/red]")
```

---

### Adding New eBPF Hooks

**Example - Monitor file operations in modules:**

```c
// In eBPF program
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    char filename[256];
    bpf_probe_read_user_str(&filename, sizeof(filename), args->filename);
    
    if (strstr(filename, ".ko") != NULL) {
        // Module file being accessed
        struct event evt = {};
        // ... capture event
        events.perf_submit(args, &evt, sizeof(evt));
    }
    return 0;
}
```

---

### Testing

**Unit tests:**
```bash
# Test baseline capture
sudo python3 kmim.py baseline test.json
test -f test.json && echo "PASS" || echo "FAIL"

# Test module detection
sudo modprobe dummy
sudo python3 kmim.py scan test.json | grep -q "dummy" && echo "PASS" || echo "FAIL"
sudo modprobe -r dummy
```

**Integration tests:**
```bash
#!/bin/bash
# tests/integration_test.sh

echo "=== KMIM Integration Tests ==="

# Test 1: Baseline creation
sudo python3 kmim.py baseline test_baseline.json
[ -f test_baseline.json ] && echo "✓ Baseline created" || exit 1

# Test 2: Clean scan
sudo python3 kmim.py scan test_baseline.json | grep -q "127 OK" && echo "✓ Clean scan" || exit 1

# Test 3: Detect new module
sudo modprobe loop
sudo python3 kmim.py scan test_baseline.json | grep -q "Added modules: loop" && echo "✓ Detected new module" || exit 1
sudo modprobe -r loop

# Cleanup
rm test_baseline.json
echo "=== All tests passed ==="
```

---

### Future Enhancements

**Planned features:**
- [ ] Module whitelist/blacklist configuration
- [ ] Web dashboard for monitoring
- [ ] Distributed scanning across multiple hosts
- [ ] Integration with SIEM systems (Splunk, ELK)
- [ ] Automated alerting (email, Slack, PagerDuty)
- [ ] Historical trend analysis
- [ ] Machine learning for anomaly detection
- [ ] Support for Windows drivers (future)

---

## 📖 Man Page

```
KMIM(1)                    User Commands                    KMIM(1)

NAME
       kmim - Kernel Module Integrity Monitor

SYNOPSIS
       kmim baseline <file.json>
       kmim scan <file.json>
       kmim show <module> [--baseline <file.json>]
       kmim monitor

DESCRIPTION
       KMIM  is  a  kernel integrity monitoring tool built with eBPF.
       It captures metadata about kernel modules and  syscalls,  builds
       a trusted baseline, and compares live state against the baseline
       to detect tampering, hidden modules, or runtime anomalies.

COMMANDS
       baseline <file.json>
              Capture the current kernel state and save to a  baseline
              file. Includes module hashes, ELF sections, and syscall
              addresses.

       scan <file.json>
              Compare  the  live  kernel  modules  and  syscalls  with
              the baseline file. Detects added, removed, or  mismatched
              modules and hidden modules.

       show <module> [--baseline <file.json>]
              Display  detailed  metadata of the specified kernel module.
              Searches baseline file (default: kmim_baseline.json) or
              current system.

       monitor
              Start  real-time  eBPF monitoring of module load and unload
              events. Press Ctrl+C to stop.

FILES
       kmim_baseline.json
              Default baseline file created by baseline command.

EXAMPLES
       Capture a baseline:
              sudo kmim baseline my_baseline.json

       Scan for changes:
              sudo kmim scan my_baseline.json

       Show module details:
              sudo kmim show ext4

       Live monitoring:
              sudo kmim monitor

AUTHOR
       Software Security Lab (HPRCSE Group)

SEE ALSO
       modprobe(8), lsmod(8), modinfo(8), bpftool(8)

KMIM 1.0                    October 2025                    KMIM(1)
```

---

## 📄 License

Educational/Research Use - Part of Software Security Lab

**Disclaimer:** This tool is provided for educational and research purposes. Use responsibly and only on systems you own or have permission to test.

---

## 👤 Author

**Software Security Lab (HPRCSE Group Aditya Pillai(CS22B1063))**

For questions, issues, or contributions:
- Open an issue on the project repository
- Contact the lab administrators
- Refer to course materials

---

## 🎓 Conclusion

KMIM provides a powerful, safe, and efficient way to monitor kernel module integrity using modern eBPF technology. By combining baseline comparison, real-time monitoring, and hidden module detection, KMIM helps security teams detect rootkits and unauthorized kernel modifications.

**Key Takeaways:**
- ✅ eBPF enables safe kernel introspection without loading modules
- ✅ Baseline comparison detects unauthorized changes
- ✅ Real-time monitoring provides immediate visibility
- ✅ Cross-referencing multiple data sources catches hiding techniques
- ✅ KMIM is part of defense-in-depth, not a silver bullet

**Next Steps:**
1. Deploy KMIM in your test environment
2. Capture baselines of critical systems
3. Set up automated scanning
4. Integrate with your SIEM/monitoring stack
5. Develop incident response procedures for alerts


---

*Last Updated: October 2025*  
*Version: 1.0*  
*Maintainer: Software Security Lab (HPRCSE Group)*
