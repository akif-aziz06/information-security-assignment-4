"""
Information Security Assignment 4 — Main Streamlit Application
Task 1: Vulnerability Scanner  |  Task 2: Firewall Configuration
"""

import streamlit as st
import subprocess
import time
import sys
import os
import signal

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import VulnerabilityScanner
from firewall_manager import ASSIGNMENT_RULES, run_cmd, get_firewall_status, get_log_path, test_port_connectivity

# ─── Page Config ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IS Assignment 4 — Security Scanner & Firewall",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ──────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.main .block-container { padding-top: 2rem; max-width: 1200px; }

/* Severity badges */
.badge { padding: 4px 12px; border-radius: 20px; font-size: 13px; font-weight: 600; display: inline-block; }
.badge-critical { background: linear-gradient(135deg, #dc2626, #b91c1c); color: white; }
.badge-high { background: linear-gradient(135deg, #ea580c, #c2410c); color: white; }
.badge-medium { background: linear-gradient(135deg, #d97706, #b45309); color: white; }
.badge-low { background: linear-gradient(135deg, #2563eb, #1d4ed8); color: white; }
.badge-info { background: linear-gradient(135deg, #6b7280, #4b5563); color: white; }

/* Metric cards */
.metric-card { background: linear-gradient(135deg, #1e293b, #0f172a); border: 1px solid #334155;
    border-radius: 12px; padding: 20px; text-align: center; }
.metric-card h3 { margin: 0; font-size: 32px; }
.metric-card p { margin: 5px 0 0 0; font-size: 14px; color: #94a3b8; }

/* Rule card */
.rule-card { background: linear-gradient(135deg, #1e293b, #0f172a); border: 1px solid #334155;
    border-radius: 12px; padding: 20px; margin: 10px 0; }

/* Status indicators */
.status-active { color: #22c55e; font-weight: 600; }
.status-inactive { color: #ef4444; font-weight: 600; }
</style>
""", unsafe_allow_html=True)

# ─── Sidebar ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔐 IS Assignment 4")
    st.markdown("**Bahria University Lahore**")
    st.markdown("8th Semester — Information Security")
    st.divider()
    st.markdown("### 📋 Tasks")
    st.markdown("1. 🔍 Vulnerability Scanner")
    st.markdown("2. 🔥 Firewall Configuration")
    st.divider()
    st.markdown("### 🛠️ Tech Stack")
    st.markdown("- **Frontend:** Streamlit")
    st.markdown("- **Vuln App:** Flask")
    st.markdown("- **Scanner:** Python (requests + bs4)")
    st.markdown("- **Firewall:** netsh (Windows)")

# ─── Tabs ────────────────────────────────────────────────────────────────────
tab1, tab2 = st.tabs(["🔍 Task 1: Vulnerability Scanner", "🔥 Task 2: Firewall Configuration"])

# ═════════════════════════════════════════════════════════════════════════════
# TASK 1: VULNERABILITY SCANNER
# ═════════════════════════════════════════════════════════════════════════════
with tab1:
    st.markdown("# 🔍 Web Application Vulnerability Scanner")
    st.markdown("Scan a target web application for **OWASP Top 10** security vulnerabilities.")

    # ── Vulnerable App Management ────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 🖥️ Step 1: Start the Vulnerable Web App")
    st.info("💡 The vulnerable Flask app (DVWA-Lite) must be running before scanning. Open a **separate terminal** and run:\n\n```\npython vulnerable_app.py\n```\n\nThis starts the app on **http://127.0.0.1:5000**")

    col_url, col_btn = st.columns([3, 1])
    with col_url:
        target_url = st.text_input(
            "Target URL",
            value="http://127.0.0.1:5000",
            help="URL of the web application to scan",
            key="target_url"
        )
    with col_btn:
        st.markdown("<br>", unsafe_allow_html=True)
        # Check if app is reachable
        if st.button("🔗 Test Connection", key="test_conn"):
            try:
                import requests
                resp = requests.get(target_url, timeout=5)
                if resp.status_code == 200:
                    st.success(f"✅ Connected! Status: {resp.status_code}")
                else:
                    st.warning(f"⚠️ Status: {resp.status_code}")
            except Exception as e:
                st.error(f"❌ Cannot connect: {e}")

    # ── Run Scan ─────────────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 🔎 Step 2: Run the Scan")

    scan_modules = st.multiselect(
        "Select scan modules",
        ["Security Headers", "Information Disclosure", "SQL Injection",
         "Cross-Site Scripting (XSS)", "CSRF Protection", "Path Traversal",
         "Access Control", "Cookie Security"],
        default=["Security Headers", "Information Disclosure", "SQL Injection",
                 "Cross-Site Scripting (XSS)", "CSRF Protection", "Path Traversal",
                 "Access Control", "Cookie Security"],
        key="scan_modules"
    )

    if st.button("🚀 Start Full Scan", type="primary", key="start_scan"):
        scanner = VulnerabilityScanner(target_url)
        progress_bar = st.progress(0, text="Initializing scan...")
        status_text = st.empty()

        def update_progress(step, total, msg):
            progress_bar.progress(step / total if total > 0 else 0, text=msg)
            status_text.text(msg)

        try:
            findings = scanner.full_scan(progress_callback=update_progress)
            progress_bar.progress(1.0, text="✅ Scan complete!")
            time.sleep(0.5)

            # Store results in session
            st.session_state['findings'] = [f.to_dict() for f in findings]
            st.session_state['scan_log'] = scanner.scan_log
            st.session_state['summary'] = scanner.get_summary()
            st.session_state['target'] = target_url
        except Exception as e:
            st.error(f"❌ Scan failed: {e}")
            st.info("Make sure the vulnerable app is running on the target URL.")

    # ── Display Results ──────────────────────────────────────────────────────
    if 'findings' in st.session_state and st.session_state['findings']:
        st.markdown("---")
        st.markdown("### 📊 Scan Results")
        st.markdown(f"**Target:** `{st.session_state.get('target', 'N/A')}`")

        summary = st.session_state['summary']

        # Metric cards
        cols = st.columns(5)
        severity_colors = {
            'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🔵', 'Info': '⚪'
        }
        for i, (sev, count) in enumerate(summary.items()):
            with cols[i]:
                st.metric(f"{severity_colors[sev]} {sev}", count)

        st.markdown(f"**Total Vulnerabilities Found: {len(st.session_state['findings'])}**")

        # Findings detail
        st.markdown("---")
        st.markdown("### 🔎 Detailed Findings")

        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        sorted_findings = sorted(st.session_state['findings'], key=lambda x: severity_order.get(x['severity'], 5))

        for idx, f in enumerate(sorted_findings):
            sev = f['severity']
            badge_class = f"badge-{sev.lower()}"
            icon = severity_colors.get(sev, '⚪')

            with st.expander(f"{icon} [{sev}] {f['name']}", expanded=(sev in ['Critical', 'High'])):
                col1, col2 = st.columns([1, 4])
                with col1:
                    st.markdown(f"**Severity:**")
                    st.markdown(f'<span class="badge {badge_class}">{sev}</span>', unsafe_allow_html=True)
                    st.markdown(f"**Category:**")
                    st.markdown(f"`{f['category']}`")
                with col2:
                    st.markdown("**Description:**")
                    st.markdown(f"{f['description']}")
                    st.markdown("**Evidence:**")
                    st.code(f['evidence'], language="text")
                    st.markdown("**🛡️ Mitigation:**")
                    st.success(f['mitigation'])

        # Scan log
        with st.expander("📋 Scan Log"):
            st.code('\n'.join(st.session_state.get('scan_log', [])), language="text")

    elif 'findings' in st.session_state and not st.session_state['findings']:
        st.success("✅ No vulnerabilities found!")


# ═════════════════════════════════════════════════════════════════════════════
# TASK 2: FIREWALL CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("# 🔥 Windows Firewall Configuration")
    st.markdown("Configure and test basic firewall rules using **Windows Defender Firewall**.")

    st.warning("⚠️ **Administrator privileges required!** Run this app as Administrator to apply firewall rules.\n\nRight-click on your terminal → **Run as Administrator** → then run `streamlit run app.py`")

    # ── Firewall Status ──────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 📡 Current Firewall Status")

    if st.button("🔄 Check Firewall Status", key="fw_status"):
        cmd = get_firewall_status()
        success, output = run_cmd(cmd)
        if success:
            st.code(output, language="text")
        else:
            st.error(f"Failed: {output}")

    # ── Assignment Rules ─────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 📜 Firewall Rules Configuration")
    st.markdown("The following three rules demonstrate key firewall concepts:")

    for rule in ASSIGNMENT_RULES:
        st.markdown(f"#### {rule['title']}")

        col_desc, col_action = st.columns([3, 1])

        with col_desc:
            st.markdown(f"**Description:** {rule['description']}")
            with st.expander(f"💡 Why is this rule useful?"):
                st.markdown(rule['purpose'])
            st.markdown("**Command:**")
            st.code(rule['command'], language="bash")

        with col_action:
            st.markdown("<br>", unsafe_allow_html=True)

            # Apply rule
            if st.button(f"✅ Apply", key=f"apply_{rule['id']}"):
                success, output = run_cmd(rule['command'])
                if success:
                    st.success(f"Rule applied!")
                    st.session_state[f"rule_{rule['id']}_status"] = "active"
                else:
                    st.error(f"Failed: {output}")

            # Remove rule
            if st.button(f"❌ Remove", key=f"remove_{rule['id']}"):
                success, output = run_cmd(rule['delete_command'])
                if success:
                    st.success(f"Rule removed!")
                    st.session_state[f"rule_{rule['id']}_status"] = "inactive"
                else:
                    st.error(f"Failed: {output}")

            # Test rule (for port rules)
            if rule['test_port']:
                if st.button(f"🧪 Test", key=f"test_{rule['id']}"):
                    cmd = test_port_connectivity('127.0.0.1', rule['test_port'])
                    success, output = run_cmd(cmd)
                    st.code(output, language="text")

        st.divider()

    # ── View Current Rules ───────────────────────────────────────────────────
    st.markdown("### 📋 View Applied Rules")

    if st.button("🔍 Show All Custom Rules (ISA4_*)", key="show_rules"):
        cmd = 'netsh advfirewall firewall show rule name=all dir=in'
        success, output = run_cmd(cmd)
        if success:
            # Filter for our rules
            lines = output.split('\n')
            our_rules = []
            current_block = []
            for line in lines:
                if line.strip().startswith('Rule Name:'):
                    if current_block and any('ISA4_' in l for l in current_block):
                        our_rules.extend(current_block)
                        our_rules.append('---')
                    current_block = [line]
                else:
                    current_block.append(line)
            if current_block and any('ISA4_' in l for l in current_block):
                our_rules.extend(current_block)

            if our_rules:
                st.code('\n'.join(our_rules), language="text")
            else:
                st.info("No custom ISA4_ rules found. Apply rules above first.")
        else:
            st.error(f"Failed: {output}")

    # ── Logging ──────────────────────────────────────────────────────────────
    st.markdown("### 📝 Firewall Logging")

    if st.button("📂 Show Log Settings", key="show_log"):
        cmd = get_log_path()
        success, output = run_cmd(cmd)
        if success:
            st.code(output, language="text")
        else:
            st.error(f"Failed: {output}")

    if st.button("📄 View Recent Log Entries", key="view_log"):
        log_path = r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
        try:
            cmd = f'powershell -Command "Get-Content \'{log_path}\' -Tail 20"'
            success, output = run_cmd(cmd)
            if success and output.strip():
                st.code(output, language="text")
            else:
                st.info("Log file is empty or not accessible. Enable logging and generate some traffic first.")
        except Exception as e:
            st.error(f"Cannot read log: {e}")

    # ── Cleanup ──────────────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 🧹 Cleanup")
    st.markdown("Remove all custom rules created by this assignment:")

    if st.button("🗑️ Remove All Custom Rules", type="secondary", key="cleanup"):
        for rule in ASSIGNMENT_RULES:
            if rule['test_port']:  # Only delete named rules (not logging config)
                success, output = run_cmd(rule['delete_command'])
                if success:
                    st.success(f"Removed: {rule['rule_name']}")
                else:
                    st.warning(f"Could not remove {rule['rule_name']}: {output}")
        # Disable logging
        success, output = run_cmd('netsh advfirewall set allprofiles logging droppedconnections disable')
        if success:
            st.success("Disabled dropped connection logging.")

    # ── Summary Table ────────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 📊 Rules Summary Table")

    summary_data = []
    for rule in ASSIGNMENT_RULES:
        summary_data.append({
            'Rule': rule['title'],
            'Command': rule['command'],
            'Action': 'Block' if 'block' in rule['command'] else ('Allow' if 'allow' in rule['command'] else 'Log'),
            'Direction': 'Inbound',
        })

    st.table(summary_data)
