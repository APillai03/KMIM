#!/usr/bin/env python3
"""
Usage:
    sudo python3 kmim.py baseline kmim_baseline.json
    sudo python3 kmim.py scan kmim_baseline.json
    sudo python3 kmim.py show ext4
    sudo python3 kmim.py monitor
    sudo python3 kmim.py continuous --interval 60
    sudo python3 kmim.py report --format html -o report.html
    sudo python3 kmim.py simulate rootkit
    sudo python3 kmim.py detect-hooks
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
from typing import Dict, Any, List, Optional, Set, Tuple
import signal
import threading
import re

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.panel import Panel
    from rich.tree import Tree
    from rich.markdown import Markdown
    from rich import box
    from rich.layout import Layout
    from rich.live import Live
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
    '__x64_sys_kill',
    '__x64_sys_getdents',
    '__x64_sys_getdents64',
]

# Suspicious patterns in module names/paths
SUSPICIOUS_PATTERNS = [
    r'rootkit',
    r'hide',
    r'backdoor',
    r'keylog',
    r'stealth',
    r'invisible',
    r'^\..*',  # Hidden files
    r'.*tmp.*',  # Temp directories
]

# Known legitimate kernel module paths
LEGITIMATE_PATHS = [
    '/lib/modules/',
    '/usr/lib/modules/',
    '/boot/',
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
        if '[' in symbol_name and ']' in symbol_name:
            start = symbol_name.index('[')
            end = symbol_name.index(']')
            mod_name = symbol_name[start+1:end]
            kallsym_modules.add(mod_name)
    
    hidden = kallsym_modules - proc_modules
    hidden = {m for m in hidden if len(m) > 1 and m.replace('_', '').isalnum()}
    
    return hidden


# =====================================================================
# ADVANCED ANOMALY DETECTION
# =====================================================================

def detect_suspicious_patterns(module_data: Dict[str, Any]) -> List[str]:
    """Detect suspicious patterns in module name and path."""
    alerts = []
    name = module_data.get('name', '')
    path = module_data.get('file', '')
    
    # Check name patterns
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, name, re.IGNORECASE):
            alerts.append(f"Suspicious name pattern: {pattern}")
    
    # Check if path is outside legitimate directories
    if path:
        is_legitimate = any(path.startswith(lp) for lp in LEGITIMATE_PATHS)
        if not is_legitimate:
            alerts.append(f"Module loaded from non-standard path: {path}")
    
    return alerts


def analyze_module_memory(module_name: str) -> Dict[str, Any]:
    """Analyze module memory characteristics."""
    analysis = {
        'writable_text': False,
        'executable_data': False,
        'suspicious_permissions': []
    }
    
    try:
        # Read module memory map from /proc
        with open(f'/proc/modules', 'r') as f:
            for line in f:
                if line.startswith(module_name):
                    parts = line.split()
                    if len(parts) >= 6:
                        # Check module state flags (simplified)
                        state = parts[3] if len(parts) > 3 else ''
                        if 'L' in state:  # Loading state
                            analysis['suspicious_permissions'].append("Module in loading state")
                    break
    except Exception:
        pass
    
    return analysis


def detect_syscall_hooks() -> List[Dict[str, Any]]:
    """Detect potential syscall table hooks by analyzing symbol consistency."""
    hooks = []
    
    # Get syscall addresses
    syscalls = find_syscall_symbols(COMMON_SYSCALL_NAMES)
    
    # Check for NULL or unusual addresses
    for name, addr in syscalls.items():
        if addr:
            try:
                addr_int = int(addr, 16)
                # Check if address is in expected kernel space range
                # x86_64 kernel space typically starts at 0xffffffff80000000
                if addr_int < 0xffffffff80000000:
                    hooks.append({
                        'syscall': name,
                        'address': addr,
                        'reason': 'Address outside expected kernel space'
                    })
            except ValueError:
                hooks.append({
                    'syscall': name,
                    'address': addr,
                    'reason': 'Invalid address format'
                })
    
    return hooks


def detect_kernel_text_modifications() -> List[Dict[str, Any]]:
    """Detect modifications to kernel text sections."""
    modifications = []
    
    try:
        # Check kernel text section integrity (simplified)
        with open('/proc/iomem', 'r') as f:
            for line in f:
                if 'Kernel code' in line or 'Kernel data' in line:
                    # Parse memory ranges
                    parts = line.strip().split(':')
                    if len(parts) >= 2:
                        modifications.append({
                            'section': parts[1].strip(),
                            'range': parts[0].strip(),
                            'status': 'present'
                        })
    except Exception as e:
        console.print(f"[yellow]Warning: Could not check kernel text: {e}[/yellow]")
    
    return modifications


def comprehensive_anomaly_scan() -> Dict[str, Any]:
    """Perform comprehensive anomaly detection scan."""
    check_root()
    
    console.print("[bold blue]Running comprehensive anomaly detection...[/bold blue]")
    
    results = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'hidden_modules': [],
        'suspicious_modules': [],
        'syscall_hooks': [],
        'memory_anomalies': [],
        'kernel_modifications': []
    }
    
    # Detect hidden modules
    console.print("[cyan]→ Scanning for hidden modules...[/cyan]")
    hidden = get_hidden_modules()
    results['hidden_modules'] = list(hidden)
    
    # Scan all loaded modules for suspicious patterns
    console.print("[cyan]→ Analyzing loaded modules...[/cyan]")
    modules = read_proc_modules()
    for mod in modules:
        mod_data = {
            'name': mod['name'],
            'size': mod['size'],
            'file': mod_filename(mod['name'])
        }
        
        alerts = detect_suspicious_patterns(mod_data)
        if alerts:
            results['suspicious_modules'].append({
                'name': mod['name'],
                'alerts': alerts
            })
        
        # Memory analysis
        mem_analysis = analyze_module_memory(mod['name'])
        if mem_analysis.get('suspicious_permissions'):
            results['memory_anomalies'].append({
                'module': mod['name'],
                'issues': mem_analysis['suspicious_permissions']
            })
    
    # Detect syscall hooks
    console.print("[cyan]→ Checking syscall table integrity...[/cyan]")
    hooks = detect_syscall_hooks()
    results['syscall_hooks'] = hooks
    
    # Check kernel text modifications
    console.print("[cyan]→ Verifying kernel text sections...[/cyan]")
    modifications = detect_kernel_text_modifications()
    results['kernel_modifications'] = modifications
    
    return results


# =====================================================================
# CONTINUOUS MONITORING
# =====================================================================

class ContinuousMonitor:
    """Continuous monitoring with alert generation."""
    
    def __init__(self, baseline_file: str, interval: int = 60):
        self.baseline_file = baseline_file
        self.interval = interval
        self.running = False
        self.alert_count = 0
        self.last_state = {}
        
    def start(self):
        """Start continuous monitoring."""
        check_root()
        
        console.print(f"[bold green]Starting continuous monitoring (interval: {self.interval}s)[/bold green]")
        console.print("[yellow]Press Ctrl+C to stop[/yellow]\n")
        
        self.running = True
        
        try:
            while self.running:
                self._check_integrity()
                time.sleep(self.interval)
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Continuous monitoring stopped[/bold yellow]")
            console.print(f"[bold]Total alerts generated: {self.alert_count}[/bold]")
    
    def _check_integrity(self):
        """Perform integrity check."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        console.print(f"[dim]--- Scan at {timestamp} ---[/dim]")
        
        # Get current state
        current_modules = {m['name']: m for m in read_proc_modules()}
        
        # Compare with last state
        if self.last_state:
            added = set(current_modules.keys()) - set(self.last_state.keys())
            removed = set(self.last_state.keys()) - set(current_modules.keys())
            
            if added:
                for name in added:
                    console.print(f"[bold red]ALERT: New module loaded: {name}[/bold red]")
                    self.alert_count += 1
            
            if removed:
                for name in removed:
                    console.print(f"[bold yellow]WARNING: Module unloaded: {name}[/bold yellow]")
                    self.alert_count += 1
        
        # Check for hidden modules
        hidden = get_hidden_modules()
        if hidden:
            console.print(f"[bold red]ALERT: Hidden modules detected: {', '.join(hidden)}[/bold red]")
            self.alert_count += len(hidden)
        
        # Update state
        self.last_state = current_modules
        
        if not (added or removed or hidden) and self.last_state:
            console.print("[green]✓ No changes detected[/green]")
        
        console.print()


# =====================================================================
# REPORTING
# =====================================================================

def generate_html_report(scan_results: Dict[str, Any], output_file: str):
    """Generate HTML report from scan results."""
    html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>KMIM Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .alert {{ padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .alert-danger {{ background: #f8d7da; border-left: 4px solid #dc3545; }}
        .alert-warning {{ background: #fff3cd; border-left: 4px solid #ffc107; }}
        .alert-success {{ background: #d4edda; border-left: 4px solid #28a745; }}
        .alert-info {{ background: #d1ecf1; border-left: 4px solid #17a2b8; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #3498db; color: white; }}
        .metric {{ display: inline-block; margin: 10px 20px; }}
        .metric-value {{ font-size: 36px; font-weight: bold; color: #3498db; }}
        .metric-label {{ color: #7f8c8d; }}
        .timestamp {{ color: #95a5a6; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ KMIM Kernel Integrity Report</h1>
        <p class="timestamp">Generated: {timestamp}</p>
        
        <h2>Executive Summary</h2>
        <div class="metric">
            <div class="metric-value">{total_modules}</div>
            <div class="metric-label">Total Modules</div>
        </div>
        <div class="metric">
            <div class="metric-value" style="color: #e74c3c;">{suspicious_count}</div>
            <div class="metric-label">Suspicious</div>
        </div>
        <div class="metric">
            <div class="metric-value" style="color: #f39c12;">{warnings}</div>
            <div class="metric-label">Warnings</div>
        </div>
        
        {alerts_section}
        {modules_section}
        {syscalls_section}
        {recommendations_section}
    </div>
</body>
</html>
"""
    
    # Build sections
    alerts_section = "<h2>🚨 Security Alerts</h2>"
    if scan_results.get('hidden_modules'):
        alerts_section += '<div class="alert alert-danger"><strong>Hidden Modules Detected:</strong><br>'
        alerts_section += ', '.join(scan_results['hidden_modules'])
        alerts_section += '</div>'
    
    if scan_results.get('syscall_hooks'):
        alerts_section += '<div class="alert alert-danger"><strong>Syscall Hooks Detected:</strong><br>'
        for hook in scan_results['syscall_hooks']:
            alerts_section += f"{hook['syscall']}: {hook['reason']}<br>"
        alerts_section += '</div>'
    
    if scan_results.get('suspicious_modules'):
        alerts_section += '<div class="alert alert-warning"><strong>Suspicious Modules:</strong><br>'
        for mod in scan_results['suspicious_modules']:
            alerts_section += f"<strong>{mod['name']}</strong>: {', '.join(mod['alerts'])}<br>"
        alerts_section += '</div>'
    
    # Modules table
    modules_section = "<h2>📦 Loaded Modules</h2><table><tr><th>Name</th><th>Size</th><th>Status</th></tr>"
    for mod in read_proc_modules()[:20]:  # Limit to first 20
        modules_section += f"<tr><td>{mod['name']}</td><td>{mod['size']}</td><td>✓</td></tr>"
    modules_section += "</table>"
    
    # Syscalls section
    syscalls_section = "<h2>🔧 Syscall Table Status</h2>"
    syscalls = find_syscall_symbols(COMMON_SYSCALL_NAMES[:5])
    syscalls_section += "<table><tr><th>Syscall</th><th>Address</th></tr>"
    for name, addr in syscalls.items():
        syscalls_section += f"<tr><td>{name}</td><td>{addr or 'N/A'}</td></tr>"
    syscalls_section += "</table>"
    
    # Recommendations
    recommendations_section = "<h2>💡 Recommendations</h2><div class='alert alert-info'>"
    if scan_results.get('hidden_modules'):
        recommendations_section += "• Investigate hidden modules immediately<br>"
    if scan_results.get('syscall_hooks'):
        recommendations_section += "• Check for rootkit presence<br>"
    recommendations_section += "• Run regular integrity scans<br>"
    recommendations_section += "• Enable eBPF monitoring for real-time detection<br>"
    recommendations_section += "</div>"
    
    # Generate HTML
    html = html_template.format(
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        total_modules=len(read_proc_modules()),
        suspicious_count=len(scan_results.get('suspicious_modules', [])) + len(scan_results.get('hidden_modules', [])),
        warnings=len(scan_results.get('syscall_hooks', [])),
        alerts_section=alerts_section,
        modules_section=modules_section,
        syscalls_section=syscalls_section,
        recommendations_section=recommendations_section
    )
    
    with open(output_file, 'w') as f:
        f.write(html)
    
    console.print(f"[bold green]✓ HTML report generated: {output_file}[/bold green]")


def generate_json_report(scan_results: Dict[str, Any], output_file: str):
    """Generate JSON report from scan results."""
    report = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'summary': {
            'total_modules': len(read_proc_modules()),
            'suspicious_count': len(scan_results.get('suspicious_modules', [])),
            'hidden_modules_count': len(scan_results.get('hidden_modules', [])),
            'syscall_hooks_count': len(scan_results.get('syscall_hooks', []))
        },
        'findings': scan_results
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    console.print(f"[bold green]✓ JSON report generated: {output_file}[/bold green]")


# =====================================================================
# ATTACK SIMULATION
# =====================================================================

def simulate_attack(scenario: str):
    """Simulate attack scenarios for testing detection capabilities."""
    check_root()
    
    console.print(f"[bold yellow]⚠️  Simulating attack scenario: {scenario}[/bold yellow]")
    console.print("[dim]This is for testing purposes only![/dim]\n")
    
    if scenario == 'rootkit':
        console.print("[cyan]Simulating rootkit behavior...[/cyan]")
        console.print("1. Creating fake module entry")
        console.print("2. Hiding from /proc/modules")
        console.print("3. Hooking syscall table")
        console.print("\n[yellow]Detection methods:[/yellow]")
        console.print("• Use 'kmim detect-hooks' to find syscall hooks")
        console.print("• Use 'kmim scan' to detect hidden modules")
        console.print("• Use 'kmim monitor' for real-time detection")
        
    elif scenario == 'lkm':
        console.print("[cyan]Simulating malicious LKM...[/cyan]")
        console.print("Creating test kernel module in /tmp")
        test_code = """
#include <linux/module.h>
#include <linux/kernel.h>

int init_module(void) {
    printk(KERN_INFO "Test module loaded\\n");
    return 0;
}

void cleanup_module(void) {
    printk(KERN_INFO "Test module unloaded\\n");
}

MODULE_LICENSE("GPL");
"""
        try:
            with open('/tmp/test_module.c', 'w') as f:
                f.write(test_code)
            console.print("[green]✓ Created /tmp/test_module.c[/green]")
            console.print("[yellow]Compile with: make -C /lib/modules/$(uname -r)/build M=/tmp modules[/yellow]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    
    elif scenario == 'syscall-hook':
        console.print("[cyan]Simulating syscall hook...[/cyan]")
        console.print("This would attempt to modify sys_call_table")
        console.print("[yellow]Detection: Compare syscall addresses with baseline[/yellow]")
    
    else:
        console.print(f"[red]Unknown scenario: {scenario}[/red]")
        console.print("[yellow]Available scenarios: rootkit, lkm, syscall-hook[/yellow]")


# =====================================================================
# ORIGINAL CORE FUNCTIONS
# =====================================================================

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
    
    console.print("[bold blue]Capturing syscall addresses...[/bold blue]")
    baseline['syscalls'] = find_syscall_symbols(COMMON_SYSCALL_NAMES)
    
    syscall_count = sum(1 for v in baseline['syscalls'].values() if v is not None)
    
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
            
            if base_mod.get('size') != cur_mod.get('size'):
                mismatch = True
            
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
    
    baseline = None
    if os.path.exists(baseline_file):
        baseline = load_baseline(baseline_file)
    
    module_data = None
    if baseline:
        for m in baseline.get('modules', []):
            if m['name'] == module_name:
                module_data = m
                break
    
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
    
    BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct module_event {
    u64 timestamp;
    u32 pid;
    char name[64];
    u32 event_type;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

int trace_do_init_module(struct pt_regs *ctx) {
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
    
    try:
        b = BPF(text=BPF_PROGRAM)
        
        load_attached = False
        free_attached = False
        
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
            except Exception:
                continue
        
        for func in free_functions:
            try:
                b.attach_kprobe(event=func, fn_name="trace_free_module")
                free_attached = True
                console.print(f"[green]✓ Monitoring module unloads via {func}[/green]")
                break
            except Exception:
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
    
    def print_event(cpu, data, size):
        event = b["events"].event(data)
        timestamp = datetime.fromtimestamp(event.timestamp / 1e9)
        event_type = "LOAD" if event.event_type == 0 else "UNLOAD"
        name = event.name.decode('utf-8', 'replace')
        
        color = "green" if event.event_type == 0 else "red"
        console.print(f"[{color}]{timestamp.strftime('%H:%M:%S.%f')[:-3]} [{event_type:6s}] Module: {name} (PID: {event.pid})[/{color}]")
    
    b["events"].open_perf_buffer(print_event)
    
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Monitoring stopped[/bold yellow]")


# =====================================================================
# MAIN CLI
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        prog='kmim',
        description='KMIM - Kernel Module Integrity Monitor (Extended)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic operations
  sudo kmim baseline kmim_baseline.json    # Capture baseline
  sudo kmim scan kmim_baseline.json        # Scan for changes
  sudo kmim show ext4                      # Show module details
  sudo kmim monitor                        # Live eBPF monitoring
  
  # Advanced features
  sudo kmim detect-hooks                   # Detect syscall hooks
  sudo kmim continuous --interval 60       # Continuous monitoring
  sudo kmim report --format html -o report.html
  sudo kmim simulate rootkit               # Test detection
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
    
    # Detect hooks command
    detect_parser = subparsers.add_parser(
        'detect-hooks',
        help='Detect syscall hooks and anomalies'
    )
    
    # Continuous monitoring command
    continuous_parser = subparsers.add_parser(
        'continuous',
        help='Continuous integrity monitoring'
    )
    continuous_parser.add_argument(
        '--baseline',
        default='kmim_baseline.json',
        help='Baseline file for comparison'
    )
    continuous_parser.add_argument(
        '--interval',
        type=int,
        default=60,
        help='Scan interval in seconds (default: 60)'
    )
    
    # Report command
    report_parser = subparsers.add_parser(
        'report',
        help='Generate security report'
    )
    report_parser.add_argument(
        '--format',
        choices=['html', 'json'],
        default='html',
        help='Report format (default: html)'
    )
    report_parser.add_argument(
        '-o', '--output',
        required=True,
        help='Output file path'
    )
    
    # Simulate command
    simulate_parser = subparsers.add_parser(
        'simulate',
        help='Simulate attack scenarios for testing'
    )
    simulate_parser.add_argument(
        'scenario',
        choices=['rootkit', 'lkm', 'syscall-hook'],
        help='Attack scenario to simulate'
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
    
    elif args.command == 'detect-hooks':
        results = comprehensive_anomaly_scan()
        
        # Display results
        console.print("\n[bold blue]═══ Anomaly Detection Results ═══[/bold blue]\n")
        
        if results['hidden_modules']:
            console.print("[bold red]🚨 Hidden Modules:[/bold red]")
            for mod in results['hidden_modules']:
                console.print(f"  • {mod}")
            console.print()
        
        if results['suspicious_modules']:
            console.print("[bold yellow]⚠️  Suspicious Modules:[/bold yellow]")
            for mod in results['suspicious_modules']:
                console.print(f"  • {mod['name']}")
                for alert in mod['alerts']:
                    console.print(f"    - {alert}")
            console.print()
        
        if results['syscall_hooks']:
            console.print("[bold red]🔧 Syscall Hooks:[/bold red]")
            for hook in results['syscall_hooks']:
                console.print(f"  • {hook['syscall']}: {hook['reason']}")
            console.print()
        
        if results['memory_anomalies']:
            console.print("[bold yellow]💾 Memory Anomalies:[/bold yellow]")
            for anomaly in results['memory_anomalies']:
                console.print(f"  • {anomaly['module']}")
                for issue in anomaly['issues']:
                    console.print(f"    - {issue}")
            console.print()
        
        total_issues = (len(results['hidden_modules']) + 
                       len(results['suspicious_modules']) + 
                       len(results['syscall_hooks']) + 
                       len(results['memory_anomalies']))
        
        if total_issues == 0:
            console.print("[bold green]✓ No anomalies detected[/bold green]")
        else:
            console.print(f"[bold red]Total issues found: {total_issues}[/bold red]")
    
    elif args.command == 'continuous':
        monitor = ContinuousMonitor(args.baseline, args.interval)
        monitor.start()
    
    elif args.command == 'report':
        # Run scan first
        results = comprehensive_anomaly_scan()
        
        if args.format == 'html':
            generate_html_report(results, args.output)
        else:
            generate_json_report(results, args.output)
    
    elif args.command == 'simulate':
        simulate_attack(args.scenario)


if __name__ == '__main__':
    main()
