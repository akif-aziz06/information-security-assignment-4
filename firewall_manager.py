"""
Windows Firewall Manager Module
Manages firewall rules using netsh advfirewall commands.
"""

import subprocess
import re


def run_cmd(cmd, admin_hint=False):
    """Run a command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=15
        )
        output = result.stdout.strip() + '\n' + result.stderr.strip()
        output = output.strip()
        success = result.returncode == 0
        if not success and 'requires elevation' in output.lower():
            output += '\n⚠️ This command requires Administrator privileges. Run the app as Administrator.'
        return success, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out."
    except Exception as e:
        return False, str(e)


# ─── Rule Management ────────────────────────────────────────────────────────

def block_incoming_port(port, protocol='tcp', name=None):
    """Block incoming traffic on a specific port."""
    rule_name = name or f"ISA4_Block_Inbound_Port_{port}"
    cmd = (
        f'netsh advfirewall firewall add rule name="{rule_name}" '
        f'dir=in action=block protocol={protocol} localport={port} '
        f'enable=yes'
    )
    return rule_name, cmd


def allow_localhost_port(port, protocol='tcp', name=None):
    """Allow localhost (127.0.0.1) access to a specific port."""
    rule_name = name or f"ISA4_Allow_Localhost_Port_{port}"
    cmd = (
        f'netsh advfirewall firewall add rule name="{rule_name}" '
        f'dir=in action=allow protocol={protocol} localport={port} '
        f'remoteip=127.0.0.1 enable=yes'
    )
    return rule_name, cmd


def enable_logging():
    """Enable logging of dropped connections."""
    cmds = [
        'netsh advfirewall set allprofiles logging droppedconnections enable',
        'netsh advfirewall set allprofiles logging allowedconnections enable',
        'netsh advfirewall set allprofiles logging maxfilesize 4096',
    ]
    return cmds


def delete_rule(rule_name):
    """Delete a firewall rule by name."""
    cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    return cmd


def list_custom_rules():
    """List our custom firewall rules (ISA4_ prefix)."""
    cmd = 'netsh advfirewall firewall show rule name=all dir=in'
    return cmd


def test_port_connectivity(host, port):
    """Test if a port is reachable using PowerShell Test-NetConnection."""
    cmd = f'powershell -Command "Test-NetConnection -ComputerName {host} -Port {port} -WarningAction SilentlyContinue | Select-Object -Property ComputerName,RemotePort,TcpTestSucceeded | Format-List"'
    return cmd


def get_firewall_status():
    """Get current firewall profile status."""
    cmd = 'netsh advfirewall show allprofiles state'
    return cmd


def get_log_path():
    """Get the firewall log file path."""
    cmd = 'netsh advfirewall show allprofiles logging'
    return cmd


# ─── Pre-built Rule Sets for the Assignment ─────────────────────────────────

ASSIGNMENT_RULES = [
    {
        'id': 'rule1',
        'title': 'Rule 1: Block Incoming Telnet (Port 23)',
        'description': (
            'Blocks all incoming TCP traffic on port 23 (Telnet). '
            'Telnet transmits data in plaintext including passwords, making it a '
            'significant security risk. Blocking this port prevents unauthorized '
            'Telnet connections to your machine.'
        ),
        'purpose': (
            '• Telnet is an unencrypted protocol — passwords sent in cleartext\n'
            '• Commonly targeted by attackers for remote access\n'
            '• Modern alternative: SSH (port 22) provides encrypted connections\n'
            '• Blocking unused ports reduces the attack surface'
        ),
        'command': 'netsh advfirewall firewall add rule name="ISA4_Block_Telnet_Port_23" dir=in action=block protocol=tcp localport=23 enable=yes',
        'delete_command': 'netsh advfirewall firewall delete rule name="ISA4_Block_Telnet_Port_23"',
        'rule_name': 'ISA4_Block_Telnet_Port_23',
        'test_port': 23,
    },
    {
        'id': 'rule2',
        'title': 'Rule 2: Allow Localhost on Port 8080',
        'description': (
            'Allows incoming TCP traffic on port 8080 ONLY from localhost (127.0.0.1). '
            'This is useful for development servers and local web applications that '
            'should only be accessible from the local machine.'
        ),
        'purpose': (
            '• Restricts access to development/test servers to local machine only\n'
            '• Prevents external users from accessing internal web applications\n'
            '• Common pattern for local proxy servers and dev environments\n'
            '• Follows the principle of least privilege'
        ),
        'command': 'netsh advfirewall firewall add rule name="ISA4_Allow_Localhost_8080" dir=in action=allow protocol=tcp localport=8080 remoteip=127.0.0.1 enable=yes',
        'delete_command': 'netsh advfirewall firewall delete rule name="ISA4_Allow_Localhost_8080"',
        'rule_name': 'ISA4_Allow_Localhost_8080',
        'test_port': 8080,
    },
    {
        'id': 'rule3',
        'title': 'Rule 3: Enable Dropped Packet Logging',
        'description': (
            'Enables Windows Firewall logging for all dropped (blocked) connections. '
            'The log file records source/destination IPs, ports, and protocols of '
            'blocked traffic for security monitoring and forensics.'
        ),
        'purpose': (
            '• Provides visibility into blocked connection attempts\n'
            '• Essential for security monitoring and incident response\n'
            '• Helps identify potential attacks or misconfigured applications\n'
            '• Log file location: C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log'
        ),
        'command': 'netsh advfirewall set allprofiles logging droppedconnections enable',
        'delete_command': 'netsh advfirewall set allprofiles logging droppedconnections disable',
        'rule_name': 'Logging_Dropped_Connections',
        'test_port': None,
    },
]
