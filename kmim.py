#!/usr/bin/env python3
"""
KMIM - Kernel Module Integrity Monitor
Complete implementation with eBPF monitoring support

Files structure:
- cli.py                 -> Main CLI entrypoint
- ebpf_monitor.py        -> eBPF monitoring program
- core.py                -> Core functionality (baseline, scan, etc.)

Requirements:
- Python 3.8+
- sudo for kernel access
- bcc: apt install bpfcc-tools python3-bpfcc
- rich: pip install rich

Usage:
    sudo python3 kmim.py baseline kmim_baseline.json
    sudo python3 kmim.py scan kmim_baseline.json
    sudo python3 kmim.py show ext4
    sudo python3 kmim.py monitor
"""

import os
import sys
import json
import argparse
import hashlib
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
import signal

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Warning: 'rich' not installed. Install with: pip install rich")
    
    class Console:
        def print(self, *args, **kwargs):
            print(*args)
    
    class Table:
        def __init__(self, *args, **kwargs):
            self.rows = []
        def add_column(self, *args, **kwargs):
            pass
        def add_row(self, *args, **kwargs):
            self.rows.append(args)

console = Console()

# Common syscall symbols to monitor
COMMON_SYSCALL_NAMES = [
    'sys_call_table',
    '__x64_sys_execve',
    'sys_execve',
    '__x64_sys_open',
    'sys_open',
    '__x64_sys_openat',
    'sys_openat',
    '__x64_sys_read',
    '__x64_sys_write',
    'sys_read',
    'sys_write',
]


def check_root():
    """Ensure the script is running with root privileges."""
    if os.geteuid() != 0:
        console.print("[bold red]Error: This command requires root privileges.[/bold red]")
        console.print("[yellow]Please run with sudo.[/yellow]")
        sys.exit(1)


def read_proc_modules() -> List[Dict[str, Any]]:
    """Parse /proc/modules and return list of modules with metadata."""
    modules = []
    try:
        with open('/proc/modules', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 6:
                    name = parts[0]
                    size = int(parts[1])
                    # Address might be at different positions
                    addr = parts[5] if len(parts) >= 6 else None
                    modules.append({
                        'name': name,
                        'size': size,
                        'addr': addr
                    })
    except Exception as e:
        console.print(f"[red]Error reading /proc/modules: {e}[/red]")
    return modules


def mod_filename(module_name: str) -> Optional[str]:
    """Get module filename using modinfo."""
    try:
        result = subprocess.run(
            ['modinfo', '-n', module_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            path = result.stdout.strip()
            if path and os.path.exists(path):
                return path
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        pass
    return None


def file_sha256(path: str) -> Optional[str]:
    """Calculate SHA256 hash of a file."""
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def read_kallsyms() -> List[Dict[str, str]]:
    """Read /proc/kallsyms for symbol addresses."""
    syms = []
    try:
        with open('/proc/kallsyms', 'r') as f:
            for line in f:
                parts = line.strip().split(maxsplit=2)
                if len(parts) >= 3:
                    addr, typ, sym = parts[0], parts[1], parts[2]
                    syms.append({
                        'addr': addr,
                        'type': typ,
                        'symbol': sym
                    })
    except PermissionError:
        console.print("[yellow]Warning: /proc/kallsyms access restricted. Syscall tracking unavailable.[/yellow]")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not read /proc/kallsyms: {e}[/yellow]")
    return syms


def find_syscall_symbols(targets: List[str]) -> Dict[str, Optional[str]]:
    """Find specific syscall symbol addresses."""
    syms = read_kallsyms()
    result = {t: None for t in targets}
    
    if not syms:
        return result
    
    sym_map = {entry['symbol']: entry['addr'] for entry in syms}
    for target in targets:
        if target in sym_map:
            result[target] = sym_map[target]
    
    return result


def extract_elf_sections(module_file: str) -> List[str]:
    """Extract ELF section names using readelf."""
    sections = []
    try:
        result = subprocess.run(
            ['readelf', '-S', module_file],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith('[') and ']' in line:
                    parts = line.split()
                    for part in parts:
                        if part.startswith('.') and not part.endswith(','):
                            sections.append(part)
                            break
                        elif part.startswith('.') and part.endswith(','):
                            sections.append(part.rstrip(','))
                            break
            # Remove duplicates while preserving order
            seen = set()
            sections = [x for x in sections if not (x in seen or seen.add(x))]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return sections


def guess_compiler(module_file: str) -> Optional[str]:
    """Detect compiler used to build the module."""
    try:
        result = subprocess.run(
            ['strings', module_file],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if 'GCC:' in line:
                    return line.strip()
                elif 'GCC' in line and len(line) < 100:
                    return f"GCC ({line.strip()[:50]})"
                elif 'clang' in line.lower() and len(line) < 100:
                    return f"Clang ({line.strip()[:50]})"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def get_hidden_modules() -> Set[str]:
    """
    Detect potentially hidden modules by comparing /proc/modules
    with kernel symbols that suggest module presence.
    """
    proc_modules = {m['name'] for m in read_proc_modules()}
    kallsym_modules = set()
    
    syms = read_kallsyms()
    for sym in syms:
        symbol_name = sym['symbol']
        # Look for module-specific symbols (contain module name in brackets)
        if '[' in symbol_name and ']' in symbol_name:
            # Extract module name from [module_name]
            start = symbol_name.index('[')
            end = symbol_name.index(']')
            mod_name = symbol_name[start+1:end]
            kallsym_modules.add(mod_name)
    
    # Hidden modules are in kallsyms but not in /proc/modules
    hidden = kallsym_modules - proc_modules
    
    # Filter out false positives (some symbols have brackets but aren't modules)
    hidden = {m for m in hidden if len(m) > 1 and m.replace('_', '').isalnum()}
    
    return hidden


def capture_baseline(filepath: str):
    """Capture current kernel state as baseline."""
    check_root()
    
    console.print("[bold blue]Capturing kernel baseline...[/bold blue]")
    
    baseline = {
        'captured_at': datetime.utcnow().isoformat() + 'Z',
        'modules': [],
        'syscalls': {}
    }
    
    modules = read_proc_modules()
    
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Processing modules...", total=len(modules))
            
            for m in modules:
                name = m['name']
                module_entry = {
                    'name': name,
                    'size': m['size'],
                    'addr': m.get('addr')
                }
                
                filename = mod_filename(name)
                if filename:
                    module_entry['file'] = filename
                    module_entry['hash'] = file_sha256(filename)
                    module_entry['elf_sections'] = extract_elf_sections(filename)
                    module_entry['compiler'] = guess_compiler(filename)
                else:
                    module_entry['file'] = None
                    module_entry['hash'] = None
                    module_entry['elf_sections'] = []
                    module_entry['compiler'] = None
                
                baseline['modules'].append(module_entry)
                progress.advance(task)
    else:
        for m in modules:
            name = m['name']
            module_entry = {
                'name': name,
                'size': m['size'],
                'addr': m.get('addr')
            }
            
            filename = mod_filename(name)
            if filename:
                module_entry['file'] = filename
                module_entry['hash'] = file_sha256(filename)
                module_entry['elf_sections'] = extract_elf_sections(filename)
                module_entry['compiler'] = guess_compiler(filename)
            else:
                module_entry['file'] = None
                module_entry['hash'] = None
                module_entry['elf_sections'] = []
                module_entry['compiler'] = None
            
            baseline['modules'].append(module_entry)
    
    # Capture syscall addresses
    console.print("[bold blue]Capturing syscall addresses...[/bold blue]")
    baseline['syscalls'] = find_syscall_symbols(COMMON_SYSCALL_NAMES)
    
    # Count captured syscalls
    syscall_count = sum(1 for v in baseline['syscalls'].values() if v is not None)
    
    # Save baseline
    with open(filepath, 'w') as f:
        json.dump(baseline, f, indent=2)
    
    console.print(f"[bold green]✓ Captured baseline of {len(modules)} modules, {syscall_count} syscall addresses[/bold green]")
    console.print(f"[bold green]Saved to {filepath}[/bold green]")


def load_baseline(filepath: str) -> Dict[str, Any]:
    """Load baseline from JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        console.print(f"[bold red]Error: Baseline file '{filepath}' not found[/bold red]")
        sys.exit(1)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]Error: Invalid JSON in baseline file: {e}[/bold red]")
        sys.exit(1)



def scan_against_baseline(filepath: str):
    """Compare current kernel state against baseline."""
    check_root()
    
    console.print("[bold blue]Loading baseline...[/bold blue]")
    baseline = load_baseline(filepath)
    
    console.print("[bold blue]Scanning current kernel state...[/bold blue]")
    
    current_modules = read_proc_modules()
    current = {m['name']: m for m in current_modules}
    base_mods = {m['name']: m for m in baseline.get('modules', [])}
    
    ok_count = 0
    added = []
    removed = []
    modified = []
    
    # Check for added and modified modules
    for name, cur_mod in current.items():
        if name not in base_mods:
            added.append(name)
        else:
            base_mod = base_mods[name]
            mismatch = False
            
            # Check size mismatch
            if base_mod.get('size') != cur_mod.get('size'):
                mismatch = True
            
            # Check hash if available
            if base_mod.get('file') and base_mod.get('hash'):
                filename = base_mod['file']
                if os.path.exists(filename):
                    current_hash = file_sha256(filename)
                    if current_hash != base_mod['hash']:
                        mismatch = True
                else:
                    mismatch = True
            
            if mismatch:
                modified.append(name)
            else:
                ok_count += 1
    
    # Check for removed modules
    for name in base_mods:
        if name not in current:
            removed.append(name)
    
    # Check for hidden modules
    console.print("[bold blue]Checking for hidden modules...[/bold blue]")
    hidden = get_hidden_modules()
    
    # Compare syscall addresses
    current_syscalls = find_syscall_symbols(list(baseline.get('syscalls', {}).keys()))
    syscall_diffs = {}
    for key, base_addr in baseline.get('syscalls', {}).items():
        cur_addr = current_syscalls.get(key)
        if base_addr and cur_addr and base_addr != cur_addr:
            syscall_diffs[key] = {
                'baseline': base_addr,
                'current': cur_addr
            }
    
    # Calculate suspicious count
    suspicious_count = len(added) + len(modified) + len(removed) + len(hidden) + len(syscall_diffs)
    
    # Display results
    console.print("\n" + "="*60)
    
    if suspicious_count == 0:
        console.print("[bold green]INFO All modules match baseline[/bold green]")
        console.print("[bold green]INFO No hidden modules[/bold green]")
    else:
        if added:
            console.print(f"[bold red]ALERT Added modules: {', '.join(added)}[/bold red]")
        if removed:
            console.print(f"[bold yellow]WARNING Removed modules: {', '.join(removed)}[/bold yellow]")
        if modified:
            console.print(f"[bold red]ALERT Modified modules: {', '.join(modified)}[/bold red]")
        if hidden:
            console.print(f"[bold red]ALERT Hidden modules detected: {', '.join(hidden)}[/bold red]")
        if syscall_diffs:
            console.print(f"[bold red]ALERT Syscall table modifications detected:[/bold red]")
            for sym, addrs in syscall_diffs.items():
                console.print(f"  {sym}: {addrs['baseline']} → {addrs['current']}")
    
    console.print(f"\n[bold]Summary: {ok_count} OK, {suspicious_count} Suspicious[/bold]")
    console.print("="*60 + "\n")


def show_module(module_name: str, baseline_file: str = "kmim_baseline.json"):
    """Display detailed information about a specific module."""
    
    # Try to load from baseline if it exists
    baseline = None
    if os.path.exists(baseline_file):
        baseline = load_baseline(baseline_file)
    
    # Search in baseline first
    module_data = None
    if baseline:
        for m in baseline.get('modules', []):
            if m['name'] == module_name:
                module_data = m
                break
    
    # If not in baseline, try to get from current system
    if not module_data:
        current_modules = read_proc_modules()
        for m in current_modules:
            if m['name'] == module_name:
                module_data = {
                    'name': m['name'],
                    'size': m['size'],
                    'addr': m.get('addr')
                }
                filename = mod_filename(module_name)
                if filename:
                    module_data['file'] = filename
                    module_data['hash'] = file_sha256(filename)
                    module_data['elf_sections'] = extract_elf_sections(filename)
                    module_data['compiler'] = guess_compiler(filename)
                break
    
    if not module_data:
        console.print(f"[bold yellow]Module '{module_name}' not found in system or baseline[/bold yellow]")
        return
    
    # Display module information
    table = Table(title=f"Module: {module_name}", box=box.ROUNDED)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    
    table.add_row("Name", module_data.get('name', 'N/A'))
    table.add_row("Size", str(module_data.get('size', 'N/A')))
    table.add_row("Addr", str(module_data.get('addr', 'N/A')))
    table.add_row("Hash", f"sha256:{module_data.get('hash', 'N/A')}" if module_data.get('hash') else 'N/A')
    table.add_row("File", str(module_data.get('file', 'N/A')))
    table.add_row("Compiler", str(module_data.get('compiler', 'N/A')))
    
    sections = module_data.get('elf_sections', [])
    if sections:
        table.add_row("ELF Sections", ', '.join(sections))
    else:
        table.add_row("ELF Sections", "N/A")
    
    console.print(table)


# =====================================================================
# EBPF MONITORING
# =====================================================================

def run_monitor():
    """Run live eBPF-based monitoring of module load/unload events."""
    check_root()
    
    try:
        from bcc import BPF
    except ImportError:
        console.print("[bold red]Error: BCC not installed[/bold red]")
        console.print("[yellow]Install with: apt install bpfcc-tools python3-bpfcc[/yellow]")
        console.print("[yellow]Or: pip install bcc[/yellow]")
        sys.exit(1)
    
    # eBPF program using kprobes for kernel 6.x compatibility
    BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct module_event {
    u64 timestamp;
    u32 pid;
    char name[64];
    u32 event_type;  // 0=load, 1=free
    char comm[16];
};

BPF_PERF_OUTPUT(events);

// Trace module loading - attach to do_init_module
int trace_do_init_module(struct pt_regs *ctx) {
    struct module_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.event_type = 0;
    
    // Get the module pointer from first argument
    void *mod_ptr = (void *)PT_REGS_PARM1(ctx);
    
    // Module name is at offset 0 in struct module (char name[56])
    bpf_probe_read_kernel_str(&evt.name, sizeof(evt.name), mod_ptr);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// Trace module unloading - attach to free_module
int trace_free_module(struct pt_regs *ctx) {
    struct module_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.event_type = 1;
    
    void *mod_ptr = (void *)PT_REGS_PARM1(ctx);
    bpf_probe_read_kernel_str(&evt.name, sizeof(evt.name), mod_ptr);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// Alternative: trace via finish_module (fallback)
int trace_finish_module(struct pt_regs *ctx) {
    struct module_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.event_type = 0;
    
    void *mod_ptr = (void *)PT_REGS_PARM1(ctx);
    bpf_probe_read_kernel_str(&evt.name, sizeof(evt.name), mod_ptr);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""
    
    console.print("[bold green]Starting eBPF monitoring...[/bold green]")
    console.print("[yellow]Press Ctrl+C to stop[/yellow]")
    console.print("[dim]Monitoring kernel module load/unload events...[/dim]\n")
    
    # Compile and load eBPF program
    try:
        b = BPF(text=BPF_PROGRAM)
        
        # Attach kprobes to module loading functions
        load_attached = False
        free_attached = False
        
        # Try multiple attachment points for maximum compatibility
        load_functions = ["do_init_module", "finish_module", "load_module"]
        free_functions = ["free_module", "delete_module"]
        
        for func in load_functions:
            try:
                if func == "finish_module":
                    b.attach_kprobe(event=func, fn_name="trace_finish_module")
                else:
                    b.attach_kprobe(event=func, fn_name="trace_do_init_module")
                load_attached = True
                console.print(f"[green]✓ Monitoring module loads via {func}[/green]")
                break
            except Exception as e:
                continue
        
        for func in free_functions:
            try:
                b.attach_kprobe(event=func, fn_name="trace_free_module")
                free_attached = True
                console.print(f"[green]✓ Monitoring module unloads via {func}[/green]")
                break
            except Exception as e:
                continue
        
        if not load_attached and not free_attached:
            console.print("[bold red]Error: Could not attach to any module functions[/bold red]")
            console.print("\n[yellow]Troubleshooting:[/yellow]")
            console.print("1. Check available functions:")
            console.print("   cat /proc/kallsyms | grep -E 'do_init_module|finish_module|free_module'")
            console.print("2. Ensure CONFIG_KPROBES is enabled:")
            console.print("   grep CONFIG_KPROBES /boot/config-$(uname -r)")
            console.print("3. Check if kernel modules are available:")
            console.print("   lsmod | head")
            sys.exit(1)
        
        if not load_attached:
            console.print("[yellow]⚠ Module load monitoring unavailable[/yellow]")
        if not free_attached:
            console.print("[yellow]⚠ Module unload monitoring unavailable[/yellow]")
        
        console.print("\n[bold cyan]Waiting for module events...[/bold cyan]")
        console.print("[dim]Try: sudo modprobe dummy (if available) or load/unload any module[/dim]\n")
            
    except Exception as e:
        console.print(f"[bold red]Error loading eBPF program: {e}[/bold red]")
        console.print("\n[yellow]Common issues:[/yellow]")
        console.print("- BCC not properly installed: apt install bpfcc-tools python3-bpfcc")
        console.print("- Kernel headers missing: apt install linux-headers-$(uname -r)")
        console.print("- eBPF not enabled: check dmesg | grep -i bpf")
        sys.exit(1)
    
    # Event handler
    def print_event(cpu, data, size):
        event = b["events"].event(data)
        timestamp = datetime.fromtimestamp(event.timestamp / 1e9)
        event_type = "LOAD" if event.event_type == 0 else "UNLOAD"
        name = event.name.decode('utf-8', 'replace')
        
        color = "green" if event.event_type == 0 else "red"
        console.print(f"[{color}]{timestamp.strftime('%H:%M:%S.%f')[:-3]} [{event_type:6s}] Module: {name} (PID: {event.pid})[/{color}]")
    
    # Register callback
    b["events"].open_perf_buffer(print_event)
    
    # Poll for events
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Monitoring stopped[/bold yellow]")



def main():
    parser = argparse.ArgumentParser(
        prog='kmim',
        description='KMIM - Kernel Module Integrity Monitor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo kmim baseline kmim_baseline.json    # Capture baseline
  sudo kmim scan kmim_baseline.json        # Scan for changes
  sudo kmim show ext4                      # Show module details
  sudo kmim monitor                        # Live eBPF monitoring
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Baseline command
    baseline_parser = subparsers.add_parser(
        'baseline',
        help='Capture current kernel state as baseline'
    )
    baseline_parser.add_argument(
        'file',
        help='Output JSON file for baseline'
    )
    
    # Scan command
    scan_parser = subparsers.add_parser(
        'scan',
        help='Compare current state against baseline'
    )
    scan_parser.add_argument(
        'file',
        help='Baseline JSON file to compare against'
    )
    
    # Show command
    show_parser = subparsers.add_parser(
        'show',
        help='Display detailed module information'
    )
    show_parser.add_argument(
        'module',
        help='Module name to display'
    )
    show_parser.add_argument(
        '--baseline',
        default='kmim_baseline.json',
        help='Baseline file to search (default: kmim_baseline.json)'
    )
    
    # Monitor command
    monitor_parser = subparsers.add_parser(
        'monitor',
        help='Live eBPF monitoring of module events'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    # Execute commands
    if args.command == 'baseline':
        capture_baseline(args.file)
    
    elif args.command == 'scan':
        scan_against_baseline(args.file)
    
    elif args.command == 'show':
        show_module(args.module, args.baseline)
    
    elif args.command == 'monitor':
        run_monitor()


if __name__ == '__main__':
    main()
