import requests  
import json
import time
import random
import os
import re
import asyncio
import faiss
import httpx
import logging
from bs4 import BeautifulSoup
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaEmbeddings

# 設定日誌
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 儲存路徑
DATA_PATH = "/home/st335/CTIAgent/autoagent_final/data/vulnerability_data_U2.json"


# 建立資料夾
os.makedirs("data", exist_ok=True)

# Define URLs
urls={
    # ---------------------------------------------------------------------------------------------
    # Ubuntu 22.04 
    # ---------------------------------------------------------------------------------------------
    "Dirty Pipe Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0847",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-0847",
        "Ubuntu": "https://askubuntu.com/questions/1396518/what-ubuntu-versions-are-affected-by-cve-2022-0847"
    },
    "OverlayFS Local Privilege Escalation Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3493",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-3493"
    },
    "Netfilter Use-After-Free Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-0179",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-0179"
    },
    "Linux Kernel Remote Code Execution Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-36971",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-36971",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2024-36971",
        "SUSE": "https://www.suse.com/security/cve/CVE-2024-36971.html"
    },
    "OpenSSH Server Remote Code Execution Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6387",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
        "Qualys": "https://www.qualys.com/regresshion-cve-2024-6387/"
    },
    "Linux Kernel NULL Pointer Dereference Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26595",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-26595",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2024-26595"
    },
    "Linux Kernel Denial of Service Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26929",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2024-26929"
    },
    "Linux Kernel Deadlock Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38597",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38597"
    },
    "Linux Kernel File Locking Race Condition Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41012",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-41012",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-41012"
    },
    "Linux Kernel File Locking Compatibility Path Race Condition Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41020",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-41020",
        "SUSE": "https://www.suse.com/security/cve/CVE-2024-41020.html",
        "Amazon Linux": "https://alas.aws.amazon.com/cve/html/CVE-2024-41020.html"
    },
    "Linux Kernel ssb_device_uevent NULL Pointer Dereference Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43914",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43914"
    },
    "Linux Kernel ibmvnic skb Memory Leak Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41066",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-41066"
    },
    "Linux Kernel closures BUG_ON() Misuse Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-42252",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-42252"
    },
    "Linux Kernel hv_sock Dangling Pointer Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53103",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53103",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-53103",
        "Amazon Linux": "https://alas.aws.amazon.com/cve/html/CVE-2024-53103.html"
    },
    "Linux Kernel netfilter ipset Range Check Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53141",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53141",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2024-53141"
    },
    "Linux Kernel qlen Adjustment Ordering Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53164",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53164",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-53164"
    },
    "Ruby SAML Signature Verification Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-45409",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-45409",
        "Ubuntu": "https://ubuntu.com/security/notices/USN-7309-1",
        "WorkOS": "https://workos.com/blog/ruby-saml-cve-2024-45409"
    },
    "Ruby SAML Improper Validation Vulnerability (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5697",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-5697",
        "Ubuntu": "https://ubuntu.com/security/notices/USN-7309-1"
    },
    "Ruby SAML XML External Entity (XXE) Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11428",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-11428",
        "GitHub": "https://github.com/onelogin/ruby-saml/pull/322"
    },
    "PostgreSQL psql SQL Injection Vulnerability (2025)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-1094",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2025-1094",
        "PostgreSQL": "https://www.postgresql.org/support/security/CVE-2025-1094/",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2025-1094"
    },
    "ST21NFCA NFC Driver Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-26490",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-26490",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2022-26490"
    },
    "Netfilter Subsystem Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1016",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-1016"
    },
    "TCINDEX Use-After-Free Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1281",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-1281",
        "Amazon Linux": "https://alas.aws.amazon.com/AL2/ALASKERNEL-5.15-2023-015.html"
    },
    "Network Queueing Rules Null Pointer Dereference (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47929",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-47929",
        "Amazon Linux": "https://alas.aws.amazon.com/AL2/ALASKERNEL-5.15-2023-013.html"
    },
    "MPLS Implementation Double-Free Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-26545",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-26545"
    },
    "needrestart Privilege Escalation Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-48990",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-48990",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-48990",
        "Qualys": "https://www.qualys.com/2024/11/19/needrestart/needrestart.txt"
    },
    "needrestart Ruby Interpreter Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-48992",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-48992",
        "Tenable": "https://www.tenable.com/cve/CVE-2024-48992",
        "Recorded Future": "https://www.recordedfuture.com/vulnerability-database/CVE-2024-48992"
    },
    "needrestart Race Condition Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-48991",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-48991"
    },
    "Module::ScanDeps Perl Module Vulnerability (2024)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-11003",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-11003"
    },
    "Linux Kernel Vulnerabilities (2023)": {
        "CVE-2023-1079": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1079",
        "CVE-2023-3006": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-3006",
        "CVE-2023-3773": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-3773",
        "CVE-2023-4244": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4244"
    },
    "KVM x2APIC MSR Access Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5090",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-5090",
        "Ubuntu": "https://ubuntu.com/security/notices/USN-6537-1",
        "Tenable": "https://www.tenable.com/plugins/nessus/186622"
    },
    "Virtio Ring Buffer Handling Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5158",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-5158",
        "Ubuntu": "https://ubuntu.com/security/notices/USN-6537-1",
        "Tenable": "https://www.tenable.com/plugins/nessus/186622"
    },
    "NVMe-oF/TCP Use-After-Free Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5178",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-5178",
        "Ubuntu": "https://ubuntu.com/security/notices/USN-6537-1",
        "Tenable": "https://www.tenable.com/plugins/nessus/186622"
    },
    "SMB Client Use-After-Free Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5345",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-5345",
        "Ubuntu": "https://ubuntu.com/security/notices/USN-6537-1",
        "Tenable": "https://www.tenable.com/plugins/nessus/186622"
    },
    "VMware Virtual GPU DRM Driver Use-After-Free Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5633",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-5633",
        "Ubuntu": "https://ubuntu.com/security/notices/USN-6537-1",
        "Tenable": "https://www.tenable.com/plugins/nessus/186622"
    },
    "Linux Kernel Performance Events (perf) Heap Out-of-Bounds Write Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5717",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-5717",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2023-5717",
        "Amazon Linux": "https://alas.aws.amazon.com/cve/html/CVE-2023-5717.html"
    },
    "Linux Kernel Netfilter Table Creation Out-of-Bounds Access Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6040",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-6040",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2023-6040"
    },
    "Linux Kernel Cryptographic Algorithm Scatterwalk Null Pointer Dereference Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6176",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-6176",
        "Ubuntu": "https://ubuntu.com/security/CVE-2023-6176"
    },
    "Linux Kernel SMB Client smbCalcSize Out-of-Bounds Read Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6606",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-6606"
    },
    "Linux Kernel Netfilter nf_tables Use-After-Free Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6817",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-6817",
        "Amazon Linux": "https://alas.aws.amazon.com/AL2/ALASKERNEL-5.10-2024-047.html"
    },
    "Linux Kernel IPv4 IGMP Use-After-Free Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6932",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-6932",
        "Amazon Linux": "https://alas.aws.amazon.com/AL2/ALASKERNEL-5.10-2024-047.html"
    },
    "Linux Kernel AMD Zen2 SMT Side-Channel Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20588",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-20588",
        "SUSE": "https://www.suse.com/security/cve/CVE-2023-20588.html"
    },
    "nf_tables Use-After-Free Vulnerability (CVE-2024-1086)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1086",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-1086",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2024-1086",
        "Amazon Linux": "https://alas.aws.amazon.com/cve/html/CVE-2024-1086.html"
    },
    "OpenSSH Remote Code Execution Vulnerability (CVE-2024-6387)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6387",
        "Qualys": "https://www.qualys.com/regresshion-cve-2024-6387/",
        "Palo Alto Networks": "https://security.paloaltonetworks.com/CVE-2024-6387"
    },
    "Linux Kernel Multiple Vulnerabilities (CVE-2024-26595)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26595"
    },
    "Linux Kernel Multiple Vulnerabilities (CVE-2024-26663)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26663"
    },
    "Linux Kernel Multiple Vulnerabilities (CVE-2024-26929)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26929",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-26929"
    },
    "Linux Kernel Deadlock Vulnerability in FEC Driver (CVE-2024-38553)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38553",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38553"
    },
    "Linux Kernel Potential NULL Pointer Dereference in ssb_device_uevent() (CVE-2024-40982)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-40982",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-40982"
    },
    "Linux Kernel File Locking Race Condition Vulnerability (CVE-2024-41012)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41012",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-41012",
        "Feedly": "https://feedly.com/cve/CVE-2024-41012"
    },
    "Linux Kernel File Locking Compatibility Path Race Condition Vulnerability (CVE-2024-41020)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41020",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-41020"
    },
    "Linux Kernel Closure Handling Warning Vulnerability (CVE-2024-42252)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-42252",
        "Amazon Linux": "https://alas.aws.amazon.com/cve/html/CVE-2024-42252.html"
    },
    "Linux Kernel hv_sock Dangling Pointer Vulnerability (CVE-2024-53103)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53103",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53103",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2024-53103",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-53103",
        "Amazon Linux": "https://alas.aws.amazon.com/cve/html/CVE-2024-53103.html",
        "SUSE": "https://www.suse.com/security/cve/CVE-2024-53103.html"
    },
    "Linux Kernel netfilter ipset Missing Range Check Vulnerability (CVE-2024-53141)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53141",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53141"
    },
    "Linux Kernel net sched qlen Adjustment Ordering Vulnerability (CVE-2024-53164)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53164",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53164",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-53164"
    },
    "CVE-2024-45409": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-45409",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-45409",
        "Ubuntu": "https://ubuntu.com/security/notices/USN-7309-1"
    },
    "CVE-2016-5697": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5697",
        "Ubuntu": "https://ubuntu.com/security/notices/USN-7309-1"
    },
    "CVE-2017-11428": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11428",
        "Ubuntu": "https://ubuntu.com/security/notices/USN-7309-1"
    },
    "CVE-2024-47738": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-47738",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-47738",
        "Ubuntu": "https://ubuntu.com/security/notices/USN-7301-1"
    },
    "CVE-2024-50006": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50006",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-50006",
        "Ubuntu": "https://ubuntu.com/security/notices/USN-7301-1"
    },
    "CVE-2024-26595": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26595",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-26595",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-26595"
    },
    "CVE-2024-26663": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26663",
        "Tenable": "https://www.tenable.com/plugins/pipeline/issues/184206-3"
    },
    "CVE-2024-26929": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26929",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-26929",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-26929"
    },
    "CVE-2024-38553": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38553",
        "Tenable": "https://www.tenable.com/plugins/pipeline/issues/184206-3"
    },
    "CVE-2024-38597": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38597",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38597"
    },
    "CVE-2024-38661": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38661",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38661"
    },
    "CVE-2024-40967": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-40967",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-40967",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-40967"
    },
    "CVE-2024-40982": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-40982",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-40982"
    },
    "CVE-2024-47715": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-47715",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-47715"
    },
    "CVE-2024-53103": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53103",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53103",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-53103",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-53103",
        "SUSE": "https://www.suse.com/security/cve/CVE-2024-53103.html"
    },
    "CVE-2024-53141": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53141",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53141",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2024-53141",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-53141",
        "SUSE": "https://www.suse.com/security/cve/CVE-2024-53141.html"
    },
    "CVE-2024-53164": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53164",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53164",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2024-53164"
    },
    "CVE-2024-49963": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49963",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49963",
        "Ubuntu": "https://ubuntu.com/security/notices/USN-7301-1"
    },
    "CVE-2024-57823": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-57823",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-57823",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2024-57823",
        "Ubuntu": "https://ubuntu.com/security/notices/USN-7316-1"
    },
    "CVE-2020-25713": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25713",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-25713",
        "Ubuntu": "https://ubuntu.com/security/notices/USN-7316-1",
        "SUSE": "https://www.suse.com/security/cve/CVE-2020-25713.html"
    },
    "CVE-2024-57822": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-57822",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-57822",
        "Debian Bug Tracker": "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1067896",
        "GitHub Issue": "https://github.com/dajobe/raptor/issues/70"
    },
    "CVE-2025-1094": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-1094",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2025-1094",
        "Rapid7 Blog": "https://www.rapid7.com/blog/post/2025/02/13/cve-2025-1094-postgresql-psql-sql-injection-fixed/"
    },
    "CVE-2024-1086": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1086",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-1086"
    },
    "CVE-2024-6387": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6387",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
        "Qualys Advisory": "https://www.qualys.com/regresshion-cve-2024-6387/",
        "Vicarius Blog": "https://www.vicarius.io/vsociety/posts/regresshion-an-openssh-regression-error-cve-2024-6387",
        "Palo Alto Networks Bulletin": "https://security.paloaltonetworks.com/CVE-2024-6387"
    },
    "CVE-2022-26490": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-26490",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-26490"
    },
    "CVE-2022-1015": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1015",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-1015",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2022-1015",
        "Ubuntu": "https://ubuntu.com/security/CVE-2022-1015",
        "GitHub PoC": "https://github.com/pqlx/CVE-2022-1015",
        "Vicarius Blog": "https://www.vicarius.io/vsociety/posts/cve-2022-1015-nftables-out-of-bounds-access-lpe"
    },
    "CVE-2022-1016": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1016",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-1016",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2022-1016",
        "Ubuntu": "https://ubuntu.com/security/CVE-2022-1016"
    },
    "CVE-2023-1281": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1281",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-1281",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2023-1281",
        "Ubuntu": "https://ubuntu.com/security/CVE-2023-1281"
    },
    "CVE-2022-47929": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47929",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-47929",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2022-47929",
        "Ubuntu": "https://ubuntu.com/security/CVE-2022-47929"
    },
    "CVE-2023-26545": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-26545",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-26545",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2023-26545",
        "Ubuntu": "https://ubuntu.com/security/CVE-2023-26545"
    },
    # ---------------------------------------------------------------------------------------------
    # Ubuntu 24.04 
    # ---------------------------------------------------------------------------------------------
     "CVE-2024-3094": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3094",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-3094",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-3094",
        "Wikipedia": "https://en.wikipedia.org/wiki/XZ_Utils_backdoor"
    },
    "CVE-2024-53104": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53104",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53104",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-53104"
    },
    "CVE-2024-48990": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-48990",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-48990"
    },
    "CVE-2024-26595": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26595",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-26595"
    },
    "CVE-2024-26663": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26663",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-26663"
    },
    "CVE-2024-26929": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26929",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-26929",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-26929",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-26929"
    },
    "CVE-2024-38553": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38553",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38553"
    },
    "CVE-2024-38597": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38597",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38597"
    },
    "CVE-2024-38661": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38661",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38661"
    },
    "CVE-2024-40967": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-40967",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-40967"
    },
    "CVE-2024-40982": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-40982",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-40982",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-40982",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-40982"
    },
    "CVE-2024-41012": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41012",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-41012",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-41012",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-41012"
    },
    "CVE-2024-41020": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41020",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-41020",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-41020",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-41020"
    },
    "CVE-2024-41066": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41066",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-41066",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-41066",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-41066"
    },
    "CVE-2024-42252": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-42252",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-42252",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-42252",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-42252"
    },
    "CVE-2024-42311": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-42311",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-42311",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-42311",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-42311"
    },
    "CVE-2024-43914": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43914",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43914",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-43914",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-43914"
    },
    "CVE-2024-47715": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-47715",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-47715",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-47715",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-47715"
    },
    "CVE-2024-53103": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53103",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53103",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-53103",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-53103"
    },
    "CVE-2024-53141": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53141",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53141",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-53141",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-53141"
    },
    "CVE-2024-53164": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53164",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53164",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-53164"
    },
    "CVE-2024-45409": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-45409",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-45409",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-45409"
    },
    "CVE-2016-5697": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5697",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-5697",
        "Ubuntu": "https://ubuntu.com/security/CVE-2016-5697"
    },
    "CVE-2017-11428": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11428",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-11428",
        "Ubuntu": "https://ubuntu.com/security/CVE-2017-11428"
    },
    "CVE-2024-47738": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-47738",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-47738",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-47738"
    },
    "CVE-2024-50006": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50006",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-50006",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-50006"
    },
    "CVE-2024-49963": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49963",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49963",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-49963"
    },
    "CVE-2024-57823": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-57823",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-57823"
    },
    "CVE-2020-25713": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25713",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-25713"
    },
    "CVE-2024-57822": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-57822",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-57822"
    },
    "CVE-2024-3094": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3094",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-3094",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-3094",
        "Wikipedia": "https://en.wikipedia.org/wiki/XZ_Utils_backdoor"
    },
    "CVE-2024-53104": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53104",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53104"
    },
    "CVE-2024-48990": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-48990",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-48990",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-48990",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-48990"
    },
    "CVE-2024-26595": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26595",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-26595"
    },
    "CVE-2024-26663": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26663",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-26663"
    },
    "CVE-2024-26929": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26929",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-26929",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-26929",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-26929"
    },
    "CVE-2024-38553": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38553",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38553"
    },
    "CVE-2024-38597": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38597",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38597"
    },
    "CVE-2024-38661": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38661",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38661"
    },
    "CVE-2024-40967": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-40967",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-40967"
    },
    "CVE-2024-40982": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-40982",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-40982",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-40982",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-40982"
    },
    "CVE-2024-41012": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41012",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-41012",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-41012",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-41012"
    },
    "CVE-2024-41020": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41020",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-41020",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-41020",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-41020"
    },
    "CVE-2024-41066": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41066",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-41066",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-41066",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-41066"
    },
    "CVE-2024-42252": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-42252",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-42252",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-42252",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-42252"
    },
    "CVE-2024-42311": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-42311",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-42311",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-42311",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-42311"
    },
    "CVE-2024-43914": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43914",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43914",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-43914",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-43914"
    },
    "CVE-2024-47715": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-47715",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-47715",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-47715",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-47715"
    },
    "CVE-2024-53103": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53103",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53103",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-53103",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-53103"
    },
    "CVE-2024-53141": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53141",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53141",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-53141",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-53141"
    },
    "CVE-2024-53164": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53164",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53164",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-53164"
    },
    "CVE-2024-45409": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-45409",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-45409",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-45409"
    },
    "CVE-2016-5697": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5697",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-5697",
        "Ubuntu": "https://ubuntu.com/security/CVE-2016-5697"
    },
    "CVE-2017-11428": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11428",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-11428",
        "Ubuntu": "https://ubuntu.com/security/CVE-2017-11428"
    },
    "CVE-2024-47738": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-47738",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-47738",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-47738"
    },
    "CVE-2024-50006": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50006",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-50006",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-50006",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-50006",
        "SUSE": "https://www.suse.com/security/cve/CVE-2024-50006.html"
    },
    "CVE-2024-49963": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49963",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49963",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-49963"
    },
    "CVE-2024-57823": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-57823",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-57823",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-57823",
        "SUSE": "https://www.suse.com/security/cve/CVE-2024-57823.html"
    },
    "CVE-2020-25713": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25713",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-25713",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2020-25713"
    },
    "CVE-2024-57822": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-57822",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-57822"
    },
     "CVE-2024-3094": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3094",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-3094",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-3094",
        "Wikipedia": "https://en.wikipedia.org/wiki/XZ_Utils_backdoor"
    },
    "CVE-2024-53104": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53104",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53104"
    },
    "CVE-2024-48990": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-48990",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-48990",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-48990",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-48990"
    },
    "CVE-2024-26595": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26595",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-26595"
    },
    "CVE-2024-26663": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26663",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-26663"
    },
    "CVE-2024-26929": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26929",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-26929",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-26929"
    },
    "CVE-2024-38553": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38553",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38553"
    },
    "CVE-2024-38597": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38597",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38597"
    },
    "CVE-2024-38661": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38661",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38661"
    },
    "CVE-2024-40967": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-40967",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-40967"
    },
    "CVE-2024-40982": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-40982",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-40982",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-40982",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-40982"
    },
    "CVE-2024-41012": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41012",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-41012",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-41012",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-41012"
    },
    "CVE-2024-41020": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41020",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-41020",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-41020",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-41020"
    },
    "CVE-2024-41066": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41066",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-41066",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-41066",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-41066"
    },
    "CVE-2024-42252": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-42252",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-42252",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-42252",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-42252"
    },
    "CVE-2024-42311": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-42311",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-42311"
    },
    "CVE-2024-43914": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43914",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43914"
    },
    "CVE-2024-47715": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-47715",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-47715"
    },
    "CVE-2024-53103": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53103",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53103",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-53103",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-53103",
        "Amazon Linux": "https://alas.aws.amazon.com/cve/html/CVE-2024-53103.html"
    },
    "CVE-2024-53141": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53141",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53141",
        "Debian": "https://security-tracker.debian.org/tracker/CVE-2024-53141"
    },
    "CVE-2024-53164": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53164",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-53164",
    },
    "CVE-2024-45409": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-45409",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-45409",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-45409",
        "RubySec": "https://rubysec.com/advisories/CVE-2024-45409"
    },
    "CVE-2016-5697": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5697",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-5697",
        "Ubuntu": "https://ubuntu.com/security/CVE-2016-5697"
    },
    "CVE-2017-11428": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11428",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-11428",
        "Ubuntu": "https://ubuntu.com/security/CVE-2017-11428"
    },
    "CVE-2024-47738": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-47738",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-47738",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-47738"
    },
    "CVE-2024-50006": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50006",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-50006",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-50006",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-50006",
        "SUSE": "https://www.suse.com/security/cve/CVE-2024-50006.html"
    },
    "CVE-2024-49963": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49963",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49963",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-49963",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-49963",
        "SUSE": "https://www.suse.com/security/cve/CVE-2024-49963.html"
    },
    "CVE-2024-57823": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-57823",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-57823",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-57823",
        "Debian": "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1067896"
    },
    "CVE-2020-25713": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25713",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-25713",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2020-25713",
        "Debian": "https://security-tracker.debian.org/tracker/CVE-2020-25713"
    },
    "CVE-2024-57822": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-57822",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-57822",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-57822",
        "Debian": "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1067896"
    },
    "CVE-2024-50078": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50078",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-50078",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-50078",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-50078"
    },
    "CVE-2024-50079": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50079",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-50079",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-50079",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-50079"
    },
    "CVE-2024-50080": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50080",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-50080",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-50080",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-50080"
    },
    "CVE-2024-50081": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50081",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-50081",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-50081",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-50081"
    },
    "CVE-2024-50082": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50082",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-50082",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-50082",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-50082"
    },
    "CVE-2024-50083": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50083",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-50083",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-50083",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-50083",
        "Amazon Linux": "https://alas.aws.amazon.com/cve/html/CVE-2024-50083.html"
    },
    "CVE-2024-50084": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50084",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-50084",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-50084",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-50084"
    },
    "CVE-2024-50085": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50085",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-50085",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-50085",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-50085"
    },
    "CVE-2024-50086": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50086",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-50086",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-50086",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-50086",
        "SUSE": "https://www.suse.com/security/cve/CVE-2024-50086.html"
    },
    "CVE-2024-50087": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50087",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-50087",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-50087",
        "Ubuntu": "https://ubuntu.com/security/CVE-2024-50087"
    }
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:110.0) Gecko/20100101 Firefox/110.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:110.0) Gecko/20100101 Firefox/110.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:110.0) Gecko/20100101 Firefox/110.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
]

# 設定 Proxy（可選）
PROXIES = [
    "http://103.48.68.34:83",
    "http://193.149.225.129:80",
    "http://103.48.68.37:83",
    "http://144.217.197.151:3129",
    "http://195.225.232.3:8085",
]

def get_random_proxy():
    return {"http://": random.choice(PROXIES), "https://": random.choice(PROXIES)}


async def fetch_text(url, session, retries=5, timeout=15):
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Referer": "https://www.google.com/",
        "Accept-Language": "en-US,en;q=0.5",
    }
    
    for attempt in range(retries):
        try:
            response = await session.get(url, headers=headers)
            if response.status_code == 403:
                logging.warning(f"403 Forbidden for {url} (Attempt {attempt+1}/{retries}), retrying...")
                await asyncio.sleep(5 + random.random() * 10)
                continue  # 重新嘗試請求
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            return "\n".join(p.get_text(strip=True) for p in soup.find_all(['p', 'li', 'div']) if p.get_text(strip=True))
        except httpx.RequestError as e:
            logging.warning(f"Failed to fetch {url} (Attempt {attempt+1}/{retries}): {e}")
            await asyncio.sleep(5 + random.random() * 10)
    return ""

async def fetch_all():
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as session:
        tasks = []
        for vuln, sources in urls.items():
            for source, url in sources.items():
                tasks.append((vuln, source, fetch_text(url, session)))
        
        results = []
        for t in tasks:
            result = await t[2]
            results.append(result)
            await asyncio.sleep(random.uniform(1, 5))  # 1~5秒隨機延遲
            
        data = {}
        for i, (vuln, source, _) in enumerate(tasks):
            data.setdefault(vuln, {})[source] = results[i]

        with open(DATA_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        logging.info("Successfully crawled vulnerability information!")

asyncio.run(fetch_all())