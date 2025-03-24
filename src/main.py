#!/usr/bin/env python3
import os
import re
import hashlib
import argparse
import time
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Rich library not found. Install with: pip install rich")
    print("Continuing with standard output...\n")


class ThreatDefinition:
    def __init__(self, pattern, description, category, severity):
        self.pattern = pattern
        self.description = description
        self.category = category
        self.severity = severity  # 1-Low, 2-Medium, 3-High, 4-Critical
        
    def __str__(self):
        return f"{self.category} - {self.description}"


class SimpleAntivirus:
    def __init__(self):
        # Initialize console if rich is available
        self.rich_console = Console() if RICH_AVAILABLE else None
        
        # Initialize signature databases
        self.virus_signatures = {
            "ec9c6f035a8c4a00c90be20ea8861266": "Trojan_VTHighConfidence_37.72",
            "44d88612fea8a8f36de82e1278abb02f": "eicar-test-file"
        }
        
        # Suspicious patterns to look for in files with structured threat categories
        self.suspicious_patterns = [
            # BSOD triggers
            ThreatDefinition(
                re.compile(r"NtRaiseHardError", re.IGNORECASE), 
                "Windows error triggering API call", 
                "Suspicious.Pattern.BSOD.API", 
                3
            ),
            ThreatDefinition(
                re.compile(r"KeBugCheck", re.IGNORECASE), 
                "Windows kernel crash function", 
                "Suspicious.Pattern.BSOD.API", 
                3
            ),
            ThreatDefinition(
                re.compile(r"taskkill.*\s/f\s.*\swininit", re.IGNORECASE), 
                "Critical process termination attempt", 
                "Suspicious.Pattern.BSOD.CMD", 
                4
            ),
            ThreatDefinition(
                re.compile(r"wininit", re.IGNORECASE), 
                "Windows initialization process reference", 
                "Suspicious.Pattern.BSOD.System", 
                3
            ),
            ThreatDefinition(
                re.compile(r"os\.system\(.*wininit", re.IGNORECASE), 
                "Python BSOD trigger attempt", 
                "Suspicious.Pattern.BSOD.Python", 
                4
            ),
            
            # Rickroll indicators
            ThreatDefinition(
                re.compile(r"dQw4w9WgXcQ"), 
                "YouTube Rickroll video ID", 
                "Suspicious.Pattern.Rickroll.YouTube", 
                1
            ),
            ThreatDefinition(
                re.compile(r"rick.?roll", re.IGNORECASE), 
                "Rickroll reference", 
                "Suspicious.Pattern.Rickroll", 
                1
            ),
            ThreatDefinition(
                re.compile(r"never.gonna.give.you.up", re.IGNORECASE), 
                "Rickroll lyrics", 
                "Suspicious.Pattern.Rickroll.Lyrics", 
                1
            ),
            ThreatDefinition(
                re.compile(r"ascii\.live/rick", re.IGNORECASE), 
                "ASCII art Rickroll attempt", 
                "Suspicious.Pattern.Rickroll.ASCII", 
                2
            ),
            ThreatDefinition(
                re.compile(r"curl.*rick", re.IGNORECASE), 
                "Rickroll download attempt", 
                "Suspicious.Pattern.Rickroll.Download", 
                2
            ),
            ThreatDefinition(
                re.compile(r"os\.system\(.*rick", re.IGNORECASE), 
                "Python Rickroll execution", 
                "Suspicious.Pattern.Rickroll.Python", 
                2
            ),
            
            # Potentially harmful code
            ThreatDefinition(
                re.compile(r"fork\s*\(\s*\).*while.*true", re.IGNORECASE), 
                "System resource exhaustion attack", 
                "Malicious.Pattern.ForkBomb", 
                4
            ),
            ThreatDefinition(
                re.compile(r"rm\s+-rf\s+[~/]*", re.IGNORECASE), 
                "Destructive file deletion", 
                "Malicious.Pattern.DataDestruction", 
                4
            ),
            ThreatDefinition(
                re.compile(r"format\s+[a-zA-Z]:.*\/[QYy]", re.IGNORECASE), 
                "Drive format command", 
                "Malicious.Pattern.DataDestruction", 
                4
            ),
            
            # Command execution
            ThreatDefinition(
                re.compile(r"os\.system\(", re.IGNORECASE), 
                "System command execution", 
                "Suspicious.Pattern.CommandExecution.Python", 
                2
            ),
            ThreatDefinition(
                re.compile(r"subprocess\.call", re.IGNORECASE), 
                "System command execution via subprocess", 
                "Suspicious.Pattern.CommandExecution.Python", 
                2
            ),
            ThreatDefinition(
                re.compile(r"subprocess\.Popen", re.IGNORECASE), 
                "System command execution via subprocess", 
                "Suspicious.Pattern.CommandExecution.Python", 
                2
            ),
            ThreatDefinition(
                re.compile(r"exec\s*\(", re.IGNORECASE), 
                "Dynamic code execution", 
                "Suspicious.Pattern.CodeExecution", 
                3
            ),
            ThreatDefinition(
                re.compile(r"eval\s*\(", re.IGNORECASE), 
                "Dynamic code evaluation", 
                "Suspicious.Pattern.CodeExecution", 
                3
            ),
            
            # Common malware behavior
            ThreatDefinition(
                re.compile(r"WScript\.Shell.*\.Run", re.IGNORECASE), 
                "Script execution via Windows Script Host", 
                "Suspicious.Pattern.CommandExecution.WSH", 
                3
            ),
            ThreatDefinition(
                re.compile(r"powershell.*\-enc|\-encoded", re.IGNORECASE), 
                "Obfuscated PowerShell command", 
                "Suspicious.Pattern.Obfuscation.PowerShell", 
                3
            ),
            ThreatDefinition(
                re.compile(r"eval\s*\(\s*base64_decode", re.IGNORECASE), 
                "Base64 encoded PHP execution", 
                "Suspicious.Pattern.Obfuscation.PHP", 
                3
            ),
            ThreatDefinition(
                re.compile(r"document\.cookie", re.IGNORECASE), 
                "Browser cookie access", 
                "Suspicious.Pattern.InfoStealing.Web", 
                2
            ),
            ThreatDefinition(
                re.compile(r"netsh\s+firewall\s+set\s+opmode\s+disable", re.IGNORECASE), 
                "Firewall disabling attempt", 
                "Malicious.Pattern.SecurityDisable", 
                4
            ),
            
            # Keyloggers or data theft
            ThreatDefinition(
                re.compile(r"GetAsyncKeyState", re.IGNORECASE), 
                "Keyboard input monitoring", 
                "Suspicious.Pattern.Keylogger.Windows", 
                3
            ),
            ThreatDefinition(
                re.compile(r"RegisterHotKey", re.IGNORECASE), 
                "Keyboard hotkey registration", 
                "Suspicious.Pattern.KeyboardMonitor", 
                2
            ),
            ThreatDefinition(
                re.compile(r"SetWindowsHookEx", re.IGNORECASE), 
                "Windows event hooking", 
                "Suspicious.Pattern.SystemHook", 
                3
            ),
        ]
        
        # File extensions to scan
        self.target_extensions = [
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", 
            ".py", ".php", ".html", ".htm", ".hta", ".scr", ".pif"
        ]

    def print_rich(self, message, style="", highlight=False):
        """Print with rich formatting if available, otherwise use standard print."""
        if RICH_AVAILABLE:
            if highlight:
                self.rich_console.print(Panel(message, style=style))
            else:
                self.rich_console.print(message, style=style)
        else:
            print(message)

    def print_threat(self, threat, file_path=""):
        """Print a detected threat with appropriate formatting."""
        if RICH_AVAILABLE:
            severity_color = {
                1: "blue",
                2: "yellow",
                3: "orange",
                4: "red bold"
            }.get(threat.severity, "white")
            
            threat_text = Text()
            if file_path:
                threat_text.append(f"{file_path}\n", style="cyan underline")
            
            threat_text.append(f"{threat.category}", style=severity_color + " bold")
            threat_text.append(f" - {threat.description}")
            
            self.rich_console.print(threat_text)
        else:
            if file_path:
                print(f"{file_path}")
            print(f"[{'CRITICAL' if threat.severity >= 4 else 'WARNING'}] {threat.category} - {threat.description}")

    def calculate_file_hash(self, file_path):
        """Calculate MD5 hash of a file."""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            self.print_rich(f"Error hashing {file_path}: {e}", style="red")
            return None

    def check_hash_signature(self, file_path):
        """Check if file's hash matches known virus signatures."""
        file_hash = self.calculate_file_hash(file_path)
        if file_hash and file_hash in self.virus_signatures:
            return self.virus_signatures[file_hash]
        return None

    def check_combined_threats(self, content):
        """Check for combinations of threats that appear together."""
        combined_threats = []
        
        # Check for BSOD + Rickroll combination
        if "rick" in content.lower() and "wininit" in content.lower():
            combined_threats.append(
                ThreatDefinition(
                    None,  # No regex pattern needed here
                    "Combined BSOD and Rickroll attack", 
                    "Malicious.Pattern.Combined.RickrollBSOD", 
                    4
                )
            )
            
        return combined_threats

    def scan_file_content(self, file_path):
        """Scan file contents for suspicious patterns."""
        threats = []
        
        try:
            # Check file size first to avoid reading very large files
            file_size = os.path.getsize(file_path)
            if file_size > 1000 * 1024 * 1024:  # 50 MB
                threats.append(
                    ThreatDefinition(
                        None,
                        f"File too large to scan content ({file_size / (1024 * 1024):.2f} MB)",
                        "Scan.Limitation.FileSize",
                        1
                    )
                )
                return threats
            
            # Check if it's a text file or binary
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    
                    # Check for suspicious patterns
                    for threat_def in self.suspicious_patterns:
                        if threat_def.pattern.search(content):
                            threats.append(threat_def)
                    
                    # Check for combined threats
                    combined = self.check_combined_threats(content)
                    threats.extend(combined)
                    
            except UnicodeDecodeError:
                # If it fails as text, try binary mode for some patterns
                try:
                    with open(file_path, 'rb') as f:
                        binary_content = f.read()
                        binary_text = binary_content.decode('latin-1')
                        
                        # Check only certain patterns in binary files
                        for threat_def in self.suspicious_patterns:
                            if threat_def.pattern.search(binary_text):
                                threats.append(threat_def)
                except Exception as e:
                    threats.append(
                        ThreatDefinition(
                            None,
                            f"Error scanning binary content: {e}",
                            "Scan.Error.BinaryParsing",
                            1
                        )
                    )
        
        except Exception as e:
            threats.append(
                ThreatDefinition(
                    None,
                    f"Error scanning file: {e}",
                    "Scan.Error.FileRead",
                    1
                )
            )
        
        return threats

    def should_scan_file(self, file_path):
        """Determine if a file should be scanned based on extension."""
        ext = os.path.splitext(file_path)[1].lower()
        # Always scan files with target extensions or files with no extension
        return ext in self.target_extensions or ext == ""

    def scan_file(self, file_path):
        """Scan a single file for threats."""
        try:
            # Check if file exists and is a regular file
            if not os.path.isfile(file_path):
                self.print_rich(f"Warning: {file_path} is not a file or doesn't exist.", style="yellow")
                return []
            
            results = []
            
            # Skip files that don't need scanning
            if not self.should_scan_file(file_path):
                return []
            
            # Check file hash against known signatures
            sig_match = self.check_hash_signature(file_path)
            if sig_match:
                results.append(
                    ThreatDefinition(
                        None,
                        "Known malware signature match",
                        sig_match,
                        4
                    )
                )
            
            # Scan file content for suspicious patterns
            content_threats = self.scan_file_content(file_path)
            results.extend(content_threats)
            
            return results
            
        except Exception as e:
            return [
                ThreatDefinition(
                    None,
                    f"Error scanning file: {e}",
                    "Scan.Error.Unknown",
                    1
                )
            ]

    def scan_directory(self, directory_path, recursive=False, verbose=False):
        """Scan a directory for threats."""
        start_time = time.time()
        scanned_files = 0
        infected_files = 0
        all_threats = []
        
        try:
            if RICH_AVAILABLE:
                # Use Rich progress display
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]{task.description}"),
                    BarColumn(),
                    TextColumn("[bold]{task.completed}/{task.total}"),
                    TimeElapsedColumn(),
                ) as progress:
                    if recursive:
                        # Get file count for progress bar
                        file_count = sum(1 for _ in Path(directory_path).rglob('*') if _.is_file())
                        scan_task = progress.add_task(f"Scanning directory: {directory_path}", total=file_count)
                        
                        for path in Path(directory_path).rglob('*'):
                            if path.is_file():
                                if verbose:
                                    progress.print(f"Scanning: {path}")
                                
                                results = self.scan_file(str(path))
                                scanned_files += 1
                                progress.update(scan_task, advance=1)
                                
                                if results:
                                    infected_files += 1
                                    progress.print(f"\n[bold red]Threats found in {path}:[/bold red]")
                                    for threat in results:
                                        self.print_threat(threat)
                                        all_threats.append((str(path), threat))
                    else:
                        # Non-recursive scan
                        file_count = sum(1 for item in os.listdir(directory_path) 
                                      if os.path.isfile(os.path.join(directory_path, item)))
                        scan_task = progress.add_task(f"Scanning directory: {directory_path}", total=file_count)
                        
                        for item in os.listdir(directory_path):
                            item_path = os.path.join(directory_path, item)
                            if os.path.isfile(item_path):
                                if verbose:
                                    progress.print(f"Scanning: {item_path}")
                                    
                                results = self.scan_file(item_path)
                                scanned_files += 1
                                progress.update(scan_task, advance=1)
                                
                                if results:
                                    infected_files += 1
                                    progress.print(f"\n[bold red]Threats found in {item_path}:[/bold red]")
                                    for threat in results:
                                        self.print_threat(threat)
                                        all_threats.append((item_path, threat))
            else:
                # Standard output if Rich not available
                if recursive:
                    for path in Path(directory_path).rglob('*'):
                        if path.is_file():
                            if verbose:
                                print(f"Scanning: {path}")
                            else:
                                print(f"Scanning: {path}", end='\r')
                                
                            results = self.scan_file(str(path))
                            scanned_files += 1
                            
                            if results:
                                infected_files += 1
                                print(f"\nThreats found in {path}:")
                                for threat in results:
                                    print(f"  {threat}")
                                    all_threats.append((str(path), threat))
                else:
                    # Non-recursive scan
                    for item in os.listdir(directory_path):
                        item_path = os.path.join(directory_path, item)
                        if os.path.isfile(item_path):
                            if verbose:
                                print(f"Scanning: {item_path}")
                            else:
                                print(f"Scanning: {item_path}", end='\r')
                                
                            results = self.scan_file(item_path)
                            scanned_files += 1
                            
                            if results:
                                infected_files += 1
                                print(f"\nThreats found in {item_path}:")
                                for threat in results:
                                    print(f"  {threat}")
                                    all_threats.append((item_path, threat))
        
        except Exception as e:
            self.print_rich(f"Error scanning directory {directory_path}: {e}", style="red bold")
        
        # Generate summary
        scan_time = time.time() - start_time
        self.print_scan_summary(scan_time, scanned_files, infected_files, all_threats)

    def print_scan_summary(self, scan_time, scanned_files, infected_files, threats):
        """Print a summary of the scan results."""
        if RICH_AVAILABLE:
            # Create a summary table
            summary_table = Table(title="Scan Summary")
            summary_table.add_column("Metric", style="cyan")
            summary_table.add_column("Value", style="green")
            
            summary_table.add_row("Scan Time", f"{scan_time:.2f} seconds")
            summary_table.add_row("Files Scanned", str(scanned_files))
            summary_table.add_row("Infected Files", f"[bold red]{infected_files}[/bold red]" if infected_files > 0 else "0")
            summary_table.add_row("Total Threats", f"[bold red]{len(threats)}[/bold red]" if threats else "0")
            
            self.rich_console.print("\n")
            self.rich_console.print(summary_table)
            
            if threats:
                threat_table = Table(title="Detected Threats")
                threat_table.add_column("File", style="cyan")
                threat_table.add_column("Threat Category", style="red")
                threat_table.add_column("Description", style="yellow")
                threat_table.add_column("Severity", style="magenta")
                
                for file_path, threat in threats:
                    severity_text = {
                        1: "Low",
                        2: "Medium",
                        3: "High",
                        4: "Critical"
                    }.get(threat.severity, "Unknown")
                    
                    threat_table.add_row(
                        os.path.basename(file_path),
                        threat.category,
                        threat.description,
                        severity_text
                    )
                
                self.rich_console.print(threat_table)
        else:
            # Standard output summary
            print("\n" + "=" * 50)
            print(f"Scan completed in {scan_time:.2f} seconds")
            print(f"Files scanned: {scanned_files}")
            print(f"Infected files: {infected_files}")
            print(f"Total threats: {len(threats)}")
            print("=" * 50)
            
            if threats:
                print("\nDetected Threats:")
                for file_path, threat in threats:
                    print(f"File: {file_path}")
                    print(f"  Threat: {threat.category}")
                    print(f"  Description: {threat.description}")
                    print(f"  Severity: {threat.severity}/4")
                    print("-" * 30)


def main():
    parser = argparse.ArgumentParser(description='Neartha Antivirus')
    parser.add_argument('path', nargs='?', default=None, help='File or directory to scan')
    parser.add_argument('-r', '--recursive', action='store_true', help='Scan directories recursively')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show all files being scanned')
    parser.add_argument('-f', '--full-scan', action='store_true', help='Perform a full system scan')
    
    args = parser.parse_args()
    
    scanner = SimpleAntivirus()
    
    scanner.print_rich("=" * 50, style="blue")
    scanner.print_rich("Neartha Antivirus Scanner", style="bold blue", highlight=True)
    scanner.print_rich("=" * 50, style="blue")
    
    if args.full_scan:
        # Determine root directory based on operating system
        if os.name == 'nt':  # Windows
            roots = []
            # Get all drive letters
            import string
            from ctypes import windll
            drives = []
            bitmask = windll.kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    drives.append(letter + ":\\")
                bitmask >>= 1
            
            scanner.print_rich(f"Starting full system scan on drives: {', '.join(drives)}", style="cyan")
            for drive in drives:
                scanner.print_rich(f"\nScanning drive: {drive}", style="cyan bold", highlight=True)
                scanner.scan_directory(drive, recursive=True, verbose=args.verbose)
        else:  # Unix-like systems
            scanner.print_rich("Starting full system scan from root directory", style="cyan")
            scanner.scan_directory("/", recursive=True, verbose=args.verbose)
    
    elif args.path:
        if os.path.isfile(args.path):
            scanner.print_rich(f"Scanning file: {args.path}", style="cyan")
            results = scanner.scan_file(args.path)
            if results:
                scanner.print_rich("Threats found:", style="red bold")
                for threat in results:
                    scanner.print_threat(threat, args.path)
                scanner.print_rich("Learn about these detections: https://neartha.w3spaces.com/detections.html", style="red bold")
            else:
                scanner.print_rich("No threats detected.", style="green")
        
        elif os.path.isdir(args.path):
            scanner.print_rich(
                f"Scanning directory: {args.path} {'(recursively)' if args.recursive else ''}",
                style="cyan"
            )
            scanner.scan_directory(args.path, args.recursive, args.verbose)
        
        else:
            scanner.print_rich(f"Error: {args.path} is not a valid file or directory.", style="red bold")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
