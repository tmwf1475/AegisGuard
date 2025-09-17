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
DATA_PATH = "data/vulnerability_data.json"
CHUNKS_PATH = "data/vulnerability_chunks.json"


# 建立資料夾
os.makedirs("data", exist_ok=True)

# Define URLs
urls={
    # ---------------------------------------------------------------------------------------------
    # Ubuntu 14.04 
    # ---------------------------------------------------------------------------------------------
    "OpenSSL 'Heartbleed' Vulnerability (2014)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
        "CISA": "https://www.cisa.gov/news-events/alerts/2014/04/08/openssl-heartbleed-vulnerability-cve-2014-0160"
    },
    "GNU Bash 'Shellshock' Vulnerability (2014)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
        "CISA": "https://www.cisa.gov/news-events/alerts/2014/09/25/gnu-bourne-again-shell-bash-shellshock-vulnerability-cve-2014-6271"
    },
    "OverlayFS Local Privilege Escalation Vulnerability (2015)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1328",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2015-1328"
    },
    "Linux Kernel 'Dirty COW' Vulnerability (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5195",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-5195",
        "Wikipedia": "https://en.wikipedia.org/wiki/Dirty_COW"
    },
    "Linux Kernel eBPF Sign Extension Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16995",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-16995"
    },
    "Linux Kernel Local Privilege Escalation Vulnerability (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4580",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-4580"
    },
    "Nginx Privilege Escalation Vulnerability (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1247",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-1247"
    },
    "Sudo Privilege Bypass Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000367",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000367"
    },
    "Linux Kernel perf_event Privilege Escalation Vulnerability (2013)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2094",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2013-2094"
    },
    "Samba Remote Code Execution Vulnerability (2015)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0240",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2015-0240",
        "Red Hat": "https://www.redhat.com/en/blog/samba-vulnerability-cve-2015-0240"
    },
    "Linux Kernel DCCP Use-After-Free Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6074",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-6074",
        "GitHub": "https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-6074/poc.c"
    },
    "Linux Kernel TTY Subsystem Race Condition Vulnerability (2014)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0196",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    },
    "Linux Kernel USB Driver Privilege Escalation Vulnerability (2015)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3290",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2015-3290"
    },
    "Linux Kernel snd_usbmidi_create Double Free Vulnerability (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2384",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-2384"
    },
    "Netfilter Local Privilege Escalation Vulnerability (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2847",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-2847"
    },
    "Linux Kernel Use-After-Free Vulnerability (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7117",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7117",
        "GitHub": "https://github.com/linux-test-project/ltp/blob/master/testcases/cve/cve-2016-7117.c"
    },
    "Linux Kernel Heap Off-By-One Vulnerability (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6187",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-6187",
        "DUASYNT": "https://duasynt.com/blog/cve-2016-6187-heap-off-by-one-exploit"
    },
    "Linux Kernel Race Condition Vulnerability (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-8650",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-8650"
    },
    "Linux Kernel Out-of-Bounds Bug Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000112",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000112",
        "GitHub": "https://github.com/xairy/linux-kernel-exploitation"
    },
    "Linux Kernel PIE Stack Buffer Corruption Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000253",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000253",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2017-1000253",
        "Amazon Linux": "https://alas.aws.amazon.com/cve/html/CVE-2017-1000253.html"
    },
    "Linux Kernel 'Mempodipper' Local Privilege Escalation Vulnerability (2012)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0056",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2012-0056"
    },
    "Linux Kernel Local Privilege Escalation Vulnerability (2013)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-1860",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2013-1860"
    },
    "Linux Kernel Memory Leak Vulnerability Allowing Access to Sensitive Information (2013)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-4348",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2013-4348"
    },
    "Linux Kernel futex Local Privilege Escalation Vulnerability (2014)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3153",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2014-3153",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2014-3153"
    },
    "Linux Kernel IPv6 Subsystem NULL Pointer Dereference Vulnerability (2015)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1420",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2015-1420"
    },
    "Linux Kernel UDF Filesystem Privilege Escalation Vulnerability (2015)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4001",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2015-4001"
    },
    "Linux Kernel ALSA Sound Driver Information Leak Vulnerability (2015)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7872",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2015-7872"
    },
    "Linux Kernel netfilter Framework Privilege Escalation Vulnerability (2015)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8767",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2015-8767"
    },
    "Linux Kernel SCTP Protocol Stack Vulnerability (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0774",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0774"
    },
    "Samba Server Authentication Mechanism Vulnerability (Badlock) (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2118",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-2118"
    },
    "Linux Kernel 'Dirty COW' Memory Write Race Condition Vulnerability (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5195",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-5195",
        "Red Hat": "https://access.redhat.com/security/vulnerabilities/DirtyCow",
        "Wikipedia": "https://en.wikipedia.org/wiki/Dirty_COW"
    },
    "Linux Kernel TCP Processing Information Leak Vulnerability (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6213",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-6213"
    },
    "NTFS-3G modprobe Environment Variable Privilege Escalation Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0358",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-0358"
    },
    "Linux Kernel N_HLDC Module Use-After-Free Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-2636",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-2636",
        "GitHub": "https://github.com/snorez/exploits/blob/master/cve-2017-2636/cve-2017-2636.c"
    },
    "Linux Kernel V4L2 Driver Information Leak Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5897",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-5897"
    },
    "Linux Kernel XFRM Netlink Race Condition Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7184",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-7184"
    },
    "Linux Kernel AF_PACKET Use-After-Free Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7308",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-7308"
    },
    "Linux Kernel net/sched Module Use-After-Free Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8824",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-8824"
    },
    "Linux Kernel net/ipv4 Module Use-After-Free Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8890",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-8890"
    },
    "Linux Kernel Stack Buffer Overflow Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000253",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000253"
    },
    "Linux Kernel Use-After-Free Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11176",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-11176",
        "Ubuntu": "https://ubuntu.com/security/CVE-2017-11176"
    },
    "glibc realpath() Buffer Underflow Vulnerability (2018)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000001",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-1000001",
        "Ubuntu": "https://ubuntu.com/security/CVE-2018-1000001"
    },
    "Linux Kernel USB Driver Race Condition Vulnerability (2018)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5803",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-5803"
    },
    "Linux Kernel 'Mutagen Astronomy' Local Privilege Escalation Vulnerability (2018)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14634",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-14634",
        "Red Hat": "https://access.redhat.com/security/vulnerabilities/mutagen-astronomy"
    },
    "OpenSSH Server Uninitialized Memory Vulnerability (2018)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15471",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-15471"
    },
    "Linux Kernel DRM Driver Privilege Escalation Vulnerability (2018)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16882",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-16882",
        "Ubuntu": "https://ubuntu.com/security/CVE-2018-16882"
    },
    "Linux Kernel sockfs Use-After-Free Vulnerability (2019)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8912",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-8912",
        "Ubuntu": "https://ubuntu.com/security/CVE-2019-8912",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2019-8912"
    },
    "Linux Kernel ptrace Use-After-Free Vulnerability (2019)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9213",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-9213",
        "Ubuntu": "https://ubuntu.com/security/CVE-2019-9213",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2019-9213"
    },
    "Linux Kernel TCP 'SACK Panic' Denial of Service Vulnerability (2019)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11477",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-11477",
        "Red Hat": "https://access.redhat.com/security/vulnerabilities/tcpsack",
        "Tenable": "https://www.tenable.com/blog/sack-panic-linux-and-freebsd-kernels-vulnerable-to-remote-denial-of-service-vulnerabilities-cve"
    },
    "Linux Kernel TCP 'SACK Slowness' Performance Degradation Vulnerability (2019)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11478",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-11478",
        "Red Hat": "https://access.redhat.com/security/vulnerabilities/tcpsack"
    },
    "Linux Kernel RDS Use-After-Free Vulnerability (2019)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11815",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-11815",
        "Ubuntu": "https://ubuntu.com/security/CVE-2019-11815",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2019-11815"
    },
    "Dirty COW Vulnerability (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5195",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-5195",
        "Ubuntu": "https://ubuntu.com/security/CVE-2016-5195",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2016-5195",
        "Wikipedia": "https://en.wikipedia.org/wiki/Dirty_COW"
    },
    "Ubuntu snapd Local Privilege Escalation Vulnerability (2019)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7304",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-7304",
        "Ubuntu": "https://ubuntu.com/security/CVE-2019-7304"
    },
    "Linux Kernel Use-After-Free Vulnerability (2018)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17182",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-17182",
        "Ubuntu": "https://ubuntu.com/security/CVE-2018-17182"
    },
    "Linux Kernel ptrace Local Privilege Escalation Vulnerability (2019)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13272",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-13272",
        "Ubuntu": "https://ubuntu.com/security/CVE-2019-13272"
    },
    "Sudo Privilege Bypass Vulnerability (2019)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14287",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-14287",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2019-14287"
    },
    "Linux Kernel xfrm Use-After-Free Vulnerability (2019)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15666",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-15666"
    },
    "eBPF Arbitrary Read/Write Vulnerability (2020)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8835",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-8835"
    },
    "Linux Kernel eBPF Privilege Escalation Vulnerability (2020)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27194",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-27194"
    },
    "Sudo Heap-Based Buffer Overflow Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3156",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"
    },
    "Linux Kernel eBPF Local Privilege Escalation Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3490",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-3490",
        "Ubuntu": "https://ubuntu.com/security/CVE-2021-3490",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2021-3490"
    },
    "Linux Kernel OverlayFS Local Privilege Escalation Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3493",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-3493",
        "Ubuntu": "https://ubuntu.com/security/CVE-2021-3493",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2021-3493"
    },
    "Polkit Local Privilege Escalation Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3560",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-3560",
        "Ubuntu": "https://ubuntu.com/security/CVE-2021-3560",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2021-3560"
    },
    "Linux Kernel KVM Subsystem Denial of Service Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4032",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-4032",
        "Ubuntu": "https://ubuntu.com/security/CVE-2021-4032",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2021-4032"
    },
    "Linux Kernel UDP Fragmentation Offload Memory Corruption Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000112",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000112",
        "Ubuntu": "https://ubuntu.com/security/CVE-2017-1000112",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2017-1000112"
    },
    "Linux Kernel PIE/Stack Memory Corruption Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000253",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000253",
        "Ubuntu": "https://ubuntu.com/security/CVE-2017-1000253",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2017-1000253"
    },
    "Sudo Local Privilege Escalation Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000367",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000367",
        "Ubuntu": "https://ubuntu.com/security/CVE-2017-1000367",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2017-1000367"
    },
    "Huge Dirty COW Local Privilege Escalation Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000405",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000405",
        "Ubuntu": "https://ubuntu.com/security/CVE-2017-1000405",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2017-1000405"
    },
    "Linux Kernel Null Pointer Dereference Vulnerability (2018)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5333",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-5333",
        "Ubuntu": "https://ubuntu.com/security/CVE-2018-5333",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2018-5333"
    },
    "Linux Kernel Privilege Escalation Vulnerability (2018)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-18955",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-18955",
        "Ubuntu": "https://ubuntu.com/security/CVE-2018-18955",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2018-18955"
    },
    "SACK Panic: Linux Kernel TCP Processing Vulnerability (2019)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11477",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-11477",
        "Ubuntu": "https://ubuntu.com/security/CVE-2019-11477",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2019-11477"
    },
    "SACK Slowness: Linux Kernel TCP Processing Performance Vulnerability (2019)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11478",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-11478",
        "Ubuntu": "https://ubuntu.com/security/CVE-2019-11478",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2019-11478"
    },
    "Mutagen Astronomy: Linux Kernel Local Buffer Overflow Vulnerability (2018)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14634",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-14634",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2018-14634"
    },
    # ---------------------------------------------------------------------------------------------
    # Ubuntu 16.04 
    # ---------------------------------------------------------------------------------------------
    "Dirty COW (Linux Kernel) (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5195",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-5195",
        "Red Hat": "https://access.redhat.com/security/vulnerabilities/dirtycow",
        "Wikipedia": "https://en.wikipedia.org/wiki/Dirty_COW"
    },
    "Apache Struts OGNL Injection Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-5638",
        "Apache": "https://cwiki.apache.org/confluence/display/WW/S2-045",
        "Black Duck": "https://www.blackduck.com/blog/cve-2017-5638-apache-struts-vulnerability-explained.html",
        "Tenable": "https://www.tenable.com/blog/apache-struts-jakarta-remote-code-execution-cve-2017-5638-detection-with-nessus"
    },
    "Apache Struts REST Plugin RCE (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9805",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-9805",
        "Apache": "https://cwiki.apache.org/confluence/display/WW/S2-052",
        "Oracle": "https://www.oracle.com/security-alerts/alert-cve-2017-9805.html"
    },
    "Apache Tomcat Remote Code Execution Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12617",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-12617",
        "Apache": "https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.1",
        "Versa Networks": "https://versa-networks.com/blog/apache-tomcat-remote-code-execution-vulnerability-cve-2017-12617/"
    },
    "Jackson-databind Deserialization RCE (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7525",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-7525",
        "GitHub": "https://github.com/FasterXML/jackson-databind/issues/1599"
    },
    "PHP 7 Remote Code Execution Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17485",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-17485"
    },
    "Git Remote Code Execution Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000117",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000117",
        "Debian": "https://www.debian.org/security/2017/dsa-3934",
        "Red Hat": "https://access.redhat.com/errata/RHSA-2017:2484"
    },
    "Jenkins Remote Code Execution Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000353",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000353",
        "Jenkins": "https://jenkins.io/security/advisory/2017-04-26/"
    },
    "Oracle WebLogic Server RCE (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-10271",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-10271"
    },
    "Microsoft Office Memory Corruption RCE (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11882",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-11882",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-11882",
        "Palo Alto Networks Analysis": "https://unit42.paloaltonetworks.com/unit42-analysis-of-cve-2017-11882-exploit-in-the-wild/"
    },
    "eBPF Local Privilege Escalation Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16995",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-16995"
    },
    "Linux Kernel Race Condition Vulnerability (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-8655",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-8655"
    },
    "X.Org Server Arbitrary File Overwrite Vulnerability (2018)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14665",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-14665"
    },
    "Sudo Security Policy Bypass Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000364",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000364",
        "Qualys": "https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt"
    },
    "DCCP Double-Free Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6074",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-6074",
        "GitHub": "https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-6074"
    },
    "Linux Kernel Netfilter Privilege Escalation (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7308",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-7308",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2017-7308"
    },
    "n_hdlc Driver Race Condition Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-2636",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-2636",
        "Exploit Details": "https://a13xp0p0v.github.io/2017/03/24/CVE-2017-2636.html",
        "Proof of Concept": "https://github.com/snorez/exploits/blob/master/cve-2017-2636/cve-2017-2636.c"
    },
    "Linux Kernel UDP Fragmentation Offload Privilege Escalation (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000112",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000112",
        "GitHub": "https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c"
    },
    "Linux Kernel ALSA Privilege Escalation (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12193",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-12193"
    },
    "Linux Kernel mq_notify Use-After-Free Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-15265",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-15265",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2017-15265"
    },
    "DCCP Double-Free Vulnerability (Potential Information Disclosure) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6074",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-6074",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2017-6074",
        "Exploit Details": "https://xairy.io/articles/cve-2017-6074",
        "Proof of Concept": "https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-6074/poc.c"
    },
    "Cryptsetup initramfs Local Decryption Vulnerability (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4484",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-4484"
    },
    "Linux Kernel KVM Information Disclosure Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17806",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-17806"
    },
    "Linux Kernel UDP Fragmentation Offload Information Disclosure (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000112",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000112",
        "Debian": "https://www.debian.org/security/2017/dsa-3981",
        "GitHub": "https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-1000112"
    },
    "Linux Kernel ALSA Information Disclosure (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12193",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-12193"
    },
    "Sudo Security Policy Bypass (Potential Information Disclosure) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000364",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000364",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2017-1000364"
    },
    "Git Remote Code Execution Vulnerability (Potential Information Disclosure) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000117",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000117",
        "Debian": "https://www.debian.org/security/2017/dsa-3934"
    },
    "Microsoft Office Memory Corruption RCE (Potential Information Disclosure) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11882",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-11882",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-11882",
        "Palo Alto Networks Analysis": "https://unit42.paloaltonetworks.com/unit42-analysis-of-cve-2017-11882-exploit-in-the-wild/",
        "Zscaler Analysis": "https://www.zscaler.com/blogs/security-research/threat-actors-exploit-cve-2017-11882-deliver-agent-tesla",
        "Fortinet Analysis": "https://www.fortinet.com/blog/threat-research/excel-document-delivers-malware-by-exploiting-cve-2017-11882"
    },
    "WordPress REST API Unauthorized Content Injection Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5941",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-5941",
        "WordPress": "https://wordpress.org/news/2017/01/wordpress-4-7-2-security-release/"
    },
    "Joomla! Unauthorized Admin Registration Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8295",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-8295",
        "Joomla": "https://developer.joomla.org/security-centre/684-20170401-core-unauthorised-creation-of-users.html"
    },
    "Dirty COW (Possible Supply Chain Attack) (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5195",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-5195",
        "Wikipedia": "https://en.wikipedia.org/wiki/Dirty_COW"
    },
    "Samba Remote Code Execution Vulnerability (Potential Supply Chain Attack) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7494",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-7494"
    },
    "Apache Struts OGNL Injection Vulnerability (Potential Supply Chain Attack) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-5638",
        "Apache": "https://cwiki.apache.org/confluence/display/WW/S2-045",
        "Black Duck": "https://www.blackduck.com/blog/cve-2017-5638-apache-struts-vulnerability-explained.html",
        "Rapid7": "https://www.rapid7.com/blog/post/2017/03/09/apache-jakarta-vulnerability-attacks-in-the-wild/"
    },
    "Apache Struts REST Plugin RCE (Potential Supply Chain Attack) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9805",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-9805",
        "Apache": "https://cwiki.apache.org/confluence/display/WW/S2-052",
        "Oracle": "https://www.oracle.com/security-alerts/alert-cve-2017-9805.html"
    },
    "Apache Tomcat Remote Code Execution Vulnerability (Potential Supply Chain Attack) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12617",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-12617",
        "Apache": "https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.1"
    },
    "Linux Kernel UDP Fragmentation Offload Privilege Escalation (Potential Supply Chain Attack) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000112",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000112",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2017-1000112",
        "GitHub": "https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c"
    },
    "Linux Kernel ALSA Privilege Escalation (Potential Supply Chain Attack) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12193",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-12193"
    },
    "n_hdlc Driver Race Condition Vulnerability (Potential Supply Chain Attack) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-2636",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-2636"
    },
    "Linux Kernel mq_notify UAF Vulnerability (Potential Supply Chain Attack) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-15265",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-15265"
    },
    "Microsoft Office Memory Corruption RCE (Potential Supply Chain Attack) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11882",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-11882",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-11882",
        "Palo Alto Networks": "https://unit42.paloaltonetworks.com/unit42-analysis-of-cve-2017-11882-exploit-in-the-wild/",
        "Zscaler": "https://www.zscaler.com/blogs/security-research/threat-actors-exploit-cve-2017-11882-deliver-agent-tesla"
    },
    "DCCP Double-Free Vulnerability (Potentially Affects File System) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6074",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-6074",
        "xairy": "https://xairy.io/articles/cve-2017-6074"
    },
    "n_hdlc Driver Race Condition Vulnerability (Potentially Affects File System) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-2636",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-2636",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2017-2636",
        "a13xp0p0v": "https://a13xp0p0v.github.io/2017/03/24/CVE-2017-2636.html"
    },
    "Linux Kernel ALSA Privilege Escalation Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12193",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-12193"
    },
    "Linux Kernel mq_notify UAF (Potential File Access Impact) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-15265",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-15265"
    },
    "Netfilter Privilege Escalation Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7308",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-7308",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2017-7308"
    },
    "eBPF Privilege Escalation Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16995",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-16995"
    },
    "OpenSSL Padding Oracle Weakness (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2107",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-2107",
        "OpenSSL": "https://www.openssl.org/news/secadv/20160503.txt",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2016-2107"
    },
    "GnuPG Memory Leakage Vulnerability (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6329",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-6329",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2016-6329"
    },
    "OpenSSL Man-in-the-Middle Attack Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-3731",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-3731",
        "OpenSSL": "https://www.openssl.org/news/secadv/20170126.txt",
        "IBM": "https://www.ibm.com/support/pages/security-bulletin-vulnerabilities-openssl-affect-sterling-connectexpress-unix-cve-2016-7055-cve-2017-3731-and-cve-2017-3732"
    },
    "OpenSSL Weak Random Number Generation Leading to Key Leakage (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-3732",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-3732",
        "OpenSSL": "https://www.openssl.org/news/secadv/20170126.txt",
        "Oracle": "https://www.oracle.com/security-alerts/cpuoct2017.html"
    },
    "OpenSSL Verification Bypass Attack (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-3733",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-3733",
        "OpenSSL": "https://www.openssl.org/news/secadv/20170126.txt",
        "Oracle": "https://www.oracle.com/security-alerts/cpuoct2017.html"
    },
    "GnuTLS Certificate Verification Bypass (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000385",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000385"
    },
    "LibreSSL Vulnerability Allowing Replay Attacks (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11368",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-11368"
    },
    "Linux Kernel IPsec Vulnerability Allowing Encrypted Communication Interception (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000254",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000254"
    },
    "TLS 1.2 Weakness Potentially Allowing Man-in-the-Middle Attacks (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17427",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-17427",
        "Radware": "https://support.radware.com/app/answers/answer_view/a_id/1010361/~/cve-2017-17427-adaptive-chosen-ciphertext-attack-vulnerability",
        "ROBOT Attack": "https://robotattack.org/"
    },
    "MongoDB Default Authorization Configuration Allowing Unauthorized Access (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12635",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-12635",
        "Apache": "https://lists.apache.org/thread.html/6c405bf3f8358e6314076be9f48c89a2e0ddf00539906291ebdf0c67@%3Cdev.couchdb.apache.org%3E"
    },
    "Linux Kernel TCP Timer Issue Causing DoS (2016)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5696",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-5696"
    },
    "DCCP Double-Free Vulnerability (Potential DoS) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6074",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-6074",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2017-6074",
        "Exploit Analysis": "https://xairy.io/articles/cve-2017-6074"
    },
    "Linux Kernel UDP Fragmentation Offload DoS Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000112",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000112",
        "Proof of Concept": "https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c"
    },
    "n_hdlc Driver Race Condition Vulnerability (System Stability Impact) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-2636",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-2636",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2017-2636"
    },
    "Linux Kernel ALSA Handling Error Potentially Causing DoS (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12193",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-12193"
    },
    "Linux Kernel mq_notify UAF (Possible Memory Corruption) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-15265",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-15265",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2017-15265"
    },
    "eBPF Privilege Escalation Vulnerability (Potential DoS) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16995",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-16995",
        "Exploit Code": "https://github.com/rlarabee/exploits/blob/master/cve-2017-16995/cve-2017-16995.c"
    },
    "Linux Netfilter Privilege Escalation Vulnerability (Potential DoS) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7308",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-7308",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2017-7308"
    },
    "Git Remote DoS Attack (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000117",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000117"
    },
    "PHP 7 Remote Code Execution Vulnerability (Potential PHP-FPM Crash) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17485",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-17485"
    },
    "WPA2 KRACK Attack (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13077",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-13077",
        "CERT": "https://www.kb.cert.org/vuls/id/228519",
        "Wi-Fi Alliance": "https://www.wi-fi.org/security-update-october-2017"
    },
    "WPA2 4-Way Handshake Replay Attack (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13078",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-13078",
        "CERT": "https://www.kb.cert.org/vuls/id/228519",
        "Wi-Fi Alliance": "https://www.wi-fi.org/security-update-october-2017"
    },
    "WPA2 TKIP MIC Attack (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13079",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-13079",
        "CERT": "https://www.kb.cert.org/vuls/id/228519",
        "Wi-Fi Alliance": "https://www.wi-fi.org/security-update-october-2017"
    },
    "WPA2 GCMP Replay Attack (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13080",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-13080",
        "CERT": "https://www.kb.cert.org/vuls/id/228519",
        "Wi-Fi Alliance": "https://www.wi-fi.org/security-update-october-2017"
    },
    "WPA2 Fast Roaming Key Leakage (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13081",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-13081",
        "CERT": "https://www.kb.cert.org/vuls/id/228519",
        "Wi-Fi Alliance": "https://www.wi-fi.org/security-update-october-2017"
    },
    "WPA2 Client Reinstallation Attack (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13082",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-13082",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2017-13082",
        "Cisco": "https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-20171016-wpa.html"
    },
    "Bluetooth Stack Buffer Overflow (Potential Memory Overflow) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000251",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000251",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2017-1000251",
        "Amazon Linux": "https://alas.aws.amazon.com/cve/html/CVE-2017-1000251.html"
    },
    "Git Remote Network Attack (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000117",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000117"
    },
    "Linux Kernel Netfilter DoS Attack (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12188",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-12188"
    },
    "IPv6 Configuration Error Potentially Leading to DoS (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7543",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-7543"
    },
    "NVIDIA Tegra Bootloader Memory Corruption Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6275",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-6275"
    },
    "OpenSSL for IoT Memory Leak Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-3735",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-3735"
    },
    "Linux Kernel USB Endpoint Handling Error (Potential Embedded System Impact) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000252",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000252",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2017-1000252"
    },
    "Embedded Linux Devices /proc/net Read Error (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000253",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000253",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2017-1000253",
        "SUSE": "https://www.suse.com/security/cve/CVE-2017-1000253.html"
    },
    "IoT TLS Error Leading to Man-in-the-Middle Attacks (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000385",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000385",
        "Erlang": "http://erlang.org/pipermail/erlang-questions/2017-November/094255.html"
    },
    "Epson Printer Web Server Vulnerability (Potential IoT Device Impact) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16943",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-16943"
    },
    "HPE iLO4 Remote Command Execution Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12542",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-12542",
        "HPE": "https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03769en_us"
    },
    "D-Link Router Hardcoded Password Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14533",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-14533"
    },
    "Samba Remote Code Execution (Potential IoT Device Impact) (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7494",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-7494",
        "Samba": "https://www.samba.org/samba/security/CVE-2017-7494.html"
    },
    "Kubernetes Remote API Security Vulnerability (2017)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1002101",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-1002101",
        "Kubernetes": "https://github.com/kubernetes/kubernetes/issues/60813"
    },
    # ---------------------------------------------------------------------------------------------
    # Ubuntu 20.04 
    # ---------------------------------------------------------------------------------------------
    "Dirty Pipe Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0847",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-0847",
        "Ubuntu": "https://ubuntu.com/security/CVE-2022-0847",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2022-0847"
    },
    "OverlayFS Local Privilege Escalation Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3493",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-3493",
        "Ubuntu": "https://ubuntu.com/security/CVE-2021-3493",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2021-3493"
    },
    "Netfilter Use-After-Free Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-0179",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-0179",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2023-0179"
    },
    "Netfilter Heap Overflow Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22555",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-22555",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2021-22555"
    },
    "Socket Buffer Overflow Vulnerability (2020)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14386",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-14386",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2020-14386",
        "Palo Alto Networks": "https://unit42.paloaltonetworks.com/cve-2020-14386/"
    },
    "Terrapin Attack - SSH CBC Mode Bypass (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-48795",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-48795",
        "OpenSSH": "https://www.openssh.com/security.html"
    },
    "OpenSSL Infinite Loop Denial-of-Service Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0778",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
        "OpenSSL": "https://www.openssl.org/news/secadv/20220315.txt",
        "Palo Alto Networks": "https://security.paloaltonetworks.com/CVE-2022-0778",
        "Sophos": "https://www.sophos.com/en-us/security-advisories/sophos-sa-20220318-openssl-dos"
    },
    "OpenSSH Configuration Error Leading to Local Privilege Escalation (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41617",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-41617",
        "OpenSSH": "https://www.openssh.com/security.html"
    },
    "Ubuntu iptables Privilege Escalation Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-25636",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-25636",
        "Ubuntu": "https://ubuntu.com/security/CVE-2022-25636"
    },
    "dpkg Permission Error Vulnerability (2020)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27350",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-27350",
        "Debian": "https://security-tracker.debian.org/tracker/CVE-2020-27350"
    },
    "Sudo 'Baron Samedit' Heap-Based Buffer Overflow Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3156",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-3156",
        "CISA": "https://www.cisa.gov/news-events/alerts/2021/02/02/sudo-heap-based-buffer-overflow-vulnerability-cve-2021-3156"
    },
    "Snapd Local Privilege Escalation Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44731",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-44731",
        "GitHub": "https://github.com/deeexcee-io/CVE-2021-44731-snap-confine-SUID"
    },
    "Linux cgroups Container Escape Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0492",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-0492"
    },
    "Docker Privilege Escalation Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-21284",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-21284"
    },
    "runc Container Escape Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23651",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-23651"
    },
    "Apache HTTP2 Request Smuggling Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23943",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-23943",
        "Apache": "https://httpd.apache.org/security/vulnerabilities_24.html"
    },
    "Nginx DNS Resolver Remote Code Execution Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23017",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
        "Nginx": "https://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html"
    },
    "PHP-FPM Variable Bypass Attack (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-21703",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-21703"
    },
    "Polkit pkexec Privilege Escalation Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4034",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"
    },
    "Linux Kernel Use-After-Free Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32250",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-32250"
    },
    "Kernel eBPF Local Privilege Escalation Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31829",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-31829"
    },
    "OverlayFS Privilege Escalation Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29657",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-29657"
    },
    "Linux Printer Subsystem Use-After-Free Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1048",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-1048"
    },
    "Sequoia Linux Filesystem Overflow Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33909",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-33909"
    },
    "ALSA Race Condition Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-0266",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-0266"
    },
    "OpenSSL X.509 Parsing Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-2068",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-2068",
        "OpenSSL": "https://www.openssl.org/news/secadv/20220621.txt"
    },
    "OpenSSH Double-Free Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-25136",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-25136",
        "OpenSSH": "https://www.openssh.com/txt/release-9.2"
    },
    "libssh Authentication Bypass Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28041",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-28041"
    },
    "Ubuntu APT Directory Traversal Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3673",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-3673",
        "Ubuntu": "https://ubuntu.com/security/CVE-2021-3673"
    },
    "snapd Mount Namespace Privilege Escalation Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0812",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-0812",
        "Ubuntu": "https://ubuntu.com/security/CVE-2022-0812"
    },
    "containerd Privilege Escalation Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41190",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-41190"
    },
    "Docker Registry API Authentication Bypass (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-25577",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-25577"
    },
    "zlib Double-Free Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37434",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-37434"
    },
    "PHP Opcache Remote Code Execution (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-26562",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-26562"
    },
    "PostgreSQL Privilege Escalation Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-41882",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-41882"
    },
    "Node.js DNS Hostname Validation Remote Code Execution Vulnerability (2021)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22931",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-22931",
        "Node.js": "https://nodejs.org/en/blog/vulnerability/aug-2021-security-releases/"
    },
    "PolicyKit (Polkit) Heap Overflow Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1972",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-1972"
    },
    "Python tarfile Path Traversal Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-41990",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-41990"
    },
    "Cron Symlink Attack Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47949",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-47949"
    },
    "systemd-journald Use-After-Free Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1050",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-1050"
    },
    "io_uring Privilege Escalation Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32233",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-32233",
        "Tarlogic": "https://www.tarlogic.com/blog/cve-2023-32233-vulnerability/"
    },
    "Netfilter Use-After-Free Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-4378",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-4378"
    },
    "Bluetooth Stack Overflow Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-2430",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-2430"
    },
    "fscrypt Race Condition Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-2663",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-2663"
    },
    "io_uring File Operation Race Condition Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-26545",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-26545"
    },
    "SSH CBC Mode Bypass - Terrapin Attack (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-48795",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-48795"
    },
    "APT GPG Key Spoofing Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29154",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-29154"
    },
    "Snapd Sandboxing Bypass Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35668",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-35668"
    },
    "containerd Use-After-Free Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-27666",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-27666"
    },
    "Docker Socket Permission Misconfiguration Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35854",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-35854"
    },
    "Apache Tomcat Remote Code Execution Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-22622",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-22622"
    },
    "Nginx Proxy Server-Side Request Forgery (SSRF) Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-41798",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-41798"
    },
    "MySQL Heap Overflow Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38976",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38976"
    },
    "PostgreSQL Write-Ahead Logging (WAL) Injection Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1552",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-1552",
        "PostgreSQL": "https://www.postgresql.org/support/security/CVE-2022-1552/"
    },
    "DBus Race Condition Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1247",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-1247"
    },
    "Polkit Improper Validation Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-35405",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-35405"
    },
    "systemd Use-After-Free Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1350",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-1350"
    },
    "Python urllib Request Injection Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-39188",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-39188"
    },
    "cron Symlink Attack Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1591",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-1591"
    },
    "OverlayFS Local Privilege Escalation Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-2640",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-2640",
        "Wiz": "https://www.wiz.io/blog/ubuntu-overlayfs-vulnerability"
    },
    "Linux Capabilities Race Condition Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-0386",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-0386",
        "Datadog Security Labs": "https://securitylabs.datadoghq.com/articles/overlayfs-cve-2023-0386/"
    },
    "io_uring Use-After-Free Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3543",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-3543"
    },
    "Linux Netfilter Privilege Escalation Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-25652",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-25652"
    },
    "Linux Netfilter Heap Overflow Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-0179",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-0179"
    },
    "OpenSSH Authentication Bypass Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-2650",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-2650"
    },
    "Ubuntu APT Directory Traversal Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32525",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-32525"
    },
    "Snapd Local Privilege Escalation Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-22809",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-22809"
    },
    "Docker BuildKit Privilege Bypass Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38202",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38202"
    },
    "Apache HTTP2 Request Smuggling Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38709",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38709",
        "Apache": "https://httpd.apache.org/security/vulnerabilities_24.html"
    },
    "Nginx Server-Side Request Forgery (SSRF) Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32094",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-32094"
    },
    "PostgreSQL Remote Code Execution Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21689",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-21689"
    },
    "DBus Service Injection Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-22855",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-22855"
    },
    "Polkit Policy Bypass Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-31479",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-31479"
    },
    "cron Job Symlink Attack Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4587",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-4587"
    },
    "Linux Kernel Netfilter Use-After-Free Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5197",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-5197",
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2023-5197",
        "Ubuntu": "https://ubuntu.com/security/CVE-2023-5197",
        "Debian": "https://security-tracker.debian.org/tracker/CVE-2023-5197"
    },
    "Linux io_uring Heap Overflow Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-3108",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-3108"
    },
    "Linux BPF JIT Race Condition Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47629",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-47629"
    },
    "Linux OverlayFS CAP_SYS_ADMIN Bypass Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1984",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-1984"
    },
    "AMD Zen2 SMT Side-Channel Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20588",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-20588"
    },
    "OpenSSH ProxyCommand Parsing Error Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4631",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-4631",
        "SonicWall": "https://www.sonicwall.com/blog/ssh-proxycommand-command-injection"
    },
    "OpenSSL RSA Signature Padding Attack Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-4244",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-4244",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2022-4244",
        "SUSE": "https://www.suse.com/security/cve/CVE-2022-4244.html"
    },
    "APT Spoofing Attack Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4525",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-4525"
    },
    "Snapd Sandbox Bypass Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38992",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38992"
    },
    "runc Container Escape Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39876",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-39876"
    },
    "Docker API Privilege Bypass Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-46284",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-46284"
    },
    "Apache mod_proxy Server-Side Request Forgery (SSRF) Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50912",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-50912",
        "Apache": "https://httpd.apache.org/security/vulnerabilities_24.html"
    },
    "Nginx FastCGI Variable Bypass Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-43893",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-43893"
    },
    "MySQL Metadata Injection Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-51982",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-51982"
    },
    "PostgreSQL Lateral Subquery Exploit (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-39292",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-39292"
    },
    "DBus Heap Overflow Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28722",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-28722"
    },
    "Polkit Authentication Bypass Vulnerability (2022)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40315",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-40315"
    },
    "systemd-journald Heap Buffer Overflow Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-31522",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-31522"
    },
    "Python tarfile Arbitrary File Write Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-41773",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-41773"
    },
    "cron Job Permission Error Vulnerability (2023)": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5199",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-5199"
    },
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
        "Red Hat": "https://access.redhat.com/security/cve/CVE-2024-49963",
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
    },
    # ---------------------------------------------------------------------------------------------
    # Windows Server 2016
    # ---------------------------------------------------------------------------------------------
    "CVE-2016-3240": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3240",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3240",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-084",
        "GitHub": "https://github.com/anonymez/cve_vendor_scrapy/blob/master/cveMicrosoft.json"
    },
    "CVE-2016-3241": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3241",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3241",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-084",
        "GitHub": "https://github.com/anonymez/cve_vendor_scrapy/blob/master/cveMicrosoft.json"
    },
    "CVE-2016-3242": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3242",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3242",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-084",
        "GitHub": "https://github.com/anonymez/cve_vendor_scrapy/blob/master/cveMicrosoft.json"
    },
    "CVE-2016-3243": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3243",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3243",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-084",
        "GitHub": "https://github.com/anonymez/cve_vendor_scrapy/blob/master/cveMicrosoft.json"
    },
    "CVE-2016-3245": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3245",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3245",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-084",
        "GitHub": "https://github.com/anonymez/cve_vendor_scrapy/blob/master/cveMicrosoft.json"
    },
    "CVE-2016-3248": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3248",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3248",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-085",
        "Acknowledgments": "https://learn.microsoft.com/en-us/security-updates/acknowledgments/2016/acknowledgments2016"
    },
    "CVE-2016-3259": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3259",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3259",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-085",
        "Acknowledgments": "https://learn.microsoft.com/en-us/security-updates/acknowledgments/2016/acknowledgments2016"
    },
    "CVE-2016-3260": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3260",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3260",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-085"
    },
    "CVE-2016-3261": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3261",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3261",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-084"
    },
    "CVE-2016-3264": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3264",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3264",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-085",
        "Acknowledgments": "https://learn.microsoft.com/en-us/security-updates/acknowledgments/2016/acknowledgments2016"
    },
    "CVE-2016-3273": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3273",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3273",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-095",
        "Acknowledgments": "https://learn.microsoft.com/en-us/security-updates/acknowledgments/2016/acknowledgments2016"
    },
    "CVE-2016-3274": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3274",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3274",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-095",
        "Acknowledgments": "https://learn.microsoft.com/en-us/security-updates/acknowledgments/2016/acknowledgments2016"
    },
    "CVE-2016-3277": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3277",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3277",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-095",
        "Acknowledgments": "https://learn.microsoft.com/en-us/security-updates/acknowledgments/2016/acknowledgments2016"
    },
    "CVE-2016-3294": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3294",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3294",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-105",
        "Acknowledgments": "https://learn.microsoft.com/en-us/security-updates/acknowledgments/2016/acknowledgments2016"
    },
    "CVE-2016-3295": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3295",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3295",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-105",
        "Acknowledgments": "https://learn.microsoft.com/en-us/security-updates/acknowledgments/2016/acknowledgments2016"
    },
    "CVE-2016-3297": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3297",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3297",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-105",
        "Qualys": "https://www.qualys.com/research/security-alerts/2016-09-13/microsoft/",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-sept-13-2016"
    },
    "CVE-2016-3325": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3325",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3325",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-104",
        "Qualys": "https://www.qualys.com/research/security-alerts/2016-09-13/microsoft/",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-sept-13-2016"
    },
    "CVE-2016-3330": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3330",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3330",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-105",
        "Qualys": "https://www.qualys.com/research/security-alerts/2016-09-13/microsoft/",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-sept-13-2016"
    },
    "CVE-2016-3350": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3350",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3350",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-105",
        "Qualys": "https://www.qualys.com/research/security-alerts/2016-09-13/microsoft/",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-sept-13-2016"
    },
    "CVE-2016-3351": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3351",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3351",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-104",
        "Qualys": "https://www.qualys.com/research/security-alerts/2016-09-13/microsoft/",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-sept-13-2016"
    },
    "CVE-2016-3370": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3370",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3370",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-120",
        "Qualys": "https://www.qualys.com/research/security-alerts/2016-10-11/microsoft/",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-oct-11-2016"
    },
    "CVE-2016-3374": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3374",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3374",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-120",
        "Qualys": "https://www.qualys.com/research/security-alerts/2016-10-11/microsoft/",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-oct-11-2016"
    },
    "CVE-2016-3377": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3377",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3377",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-119",
        "Qualys": "https://www.qualys.com/research/security-alerts/2016-10-11/microsoft/",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-oct-11-2016"
    },
    "CVE-2017-0144": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
        "Qualys": "https://blog.qualys.com/securitylabs/2017/03/14/microsoft-patches-for-march-2017",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-mar-14-2017"
    },
    "CVE-2021-1675": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1675",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-1675",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675",
        "Qualys": "https://blog.qualys.com/vulnerabilities-threat-research/2021/06/30/printnightmare-critical-windows-print-spooler-vulnerability",
        "SonicWall": "https://www.sonicwall.com/blog/2021/07/critical-windows-print-spooler-vulnerability-printnightmare/"
    },
    "CVE-2021-34527": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34527",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-117a",
        "Wikipedia": "https://en.wikipedia.org/wiki/PrintNightmare"
    },
    "CVE-2020-1472": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1472",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-1472",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-117a"
    },
    "CVE-2021-34523": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34523",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34523",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34523",
        "CISA": "https://www.cisa.gov/news-events/alerts/2021/08/21/urgent-protect-against-active-exploitation-proxyshell-vulnerabilities"
    },
    "CVE-2021-34473": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34473",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34473",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473",
        "CISA": "https://www.cisa.gov/news-events/alerts/2021/08/21/urgent-protect-against-active-exploitation-proxyshell-vulnerabilities"
    },
    "CVE-2021-31207": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31207",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-31207",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31207",
        "CISA": "https://www.cisa.gov/news-events/alerts/2021/08/21/urgent-protect-against-active-exploitation-proxyshell-vulnerabilities"
    },
    "CVE-2016-3238": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3238",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3238",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-087",
        "The Hacker News": "https://thehackernews.com/2016/07/printer-security-update.html"
    },
    "CVE-2016-3239": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3239",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3239",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-087"
    },
    "CVE-2016-2118": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2118",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-2118",
        "Badlock": "https://zh.wikipedia.org/wiki/Badlock"
    },
    "CVE-2017-0144": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
        "Wikipedia": "https://en.wikipedia.org/wiki/EternalBlue"
    },
    "CVE-2021-1675": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1675",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-1675",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675",
        "Rapid7": "https://www.rapid7.com/blog/post/2021/06/30/cve-2021-1675-printnightmare-patch-does-not-remediate-vulnerability/",
        "Wikipedia": "https://en.wikipedia.org/wiki/PrintNightmare"
    },
    "CVE-2021-34527": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34527",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
        "Rapid7": "https://www.rapid7.com/blog/post/2021/06/30/cve-2021-1675-printnightmare-patch-does-not-remediate-vulnerability/",
        "Wikipedia": "https://en.wikipedia.org/wiki/PrintNightmare"
    },
    "CVE-2021-34481": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34481",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34481",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34481",
        "Wikipedia": "https://en.wikipedia.org/wiki/PrintNightmare"
    },
    "CVE-2024-38063": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38063",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38063",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38063",
        "Blumira": "https://www.blumira.com/blog/cve-2024-38063-windows-tcp/ip-remote-code-execution-vulnerability"
    },
    "CVE-2024-21302": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21302",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-21302",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21302",
        "Qualys": "https://blog.qualys.com/vulnerabilities-threat-research/2024/08/13/microsoft-patch-tuesday-august-2024-security-update-review"
    },
    "CVE-2024-38202": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38202",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38202",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38202",
        "Qualys": "https://blog.qualys.com/vulnerabilities-threat-research/2024/08/13/microsoft-patch-tuesday-august-2024-security-update-review"
    },
    "CVE-2018-0824": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-0824",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-0824",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0824",
        "Tenable": "https://www.tenable.com/cve/CVE-2018-0824"
    },
    "CVE-2016-3247": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3247",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3247",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-084",
        "Zscaler": "https://www.zscaler.com/security-advisories/zscaler-protects-against-16-new-vulnerabilities-internet-explorer-kernel-mode-drivers-microsoft-office-and-windows-pdf-library"
    },
    "CVE-2016-3291": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3291",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3291",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-095"
    },
    "CVE-2016-3292": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3292",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3292",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-094"
    },
    "CVE-2016-3324": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3324",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3324",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-104"
    },
     "CVE-2016-3353": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3353",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3353",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-104"
    },
    "CVE-2016-3375": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3375",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3375",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-119"
    },
    "CVE-2016-3238": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3238",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3238",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-087"
    },
    "CVE-2016-3239": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3239",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3239",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-087"
    },
    "CVE-2021-34523": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34523",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34523",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34523",
        "Fortinet": "https://www.fortinet.com/cn/fortiguard/threat-and-incident-notifications",
        "SIDfm": "https://sid-fm.com/blog/archive/entry/20210902.html"
    },
    "CVE-2021-34473": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34473",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34473",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473",
        "CISA": "https://www.cisa.gov/news-events/alerts/2021/08/21/urgent-protect-against-active-exploitation-proxyshell-vulnerabilities",
        "Tenable": "https://www.tenable.com/blog/proxyshell-attackers-actively-scanning-for-vulnerable-microsoft-exchange-servers-cve-2021-34473"
    },
    "CVE-2021-31207": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31207",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-31207",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31207",
        "CISA": "https://www.cisa.gov/news-events/alerts/2021/08/21/urgent-protect-against-active-exploitation-proxyshell-vulnerabilities"
    },
    "CVE-2020-0601": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0601",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-0601",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0601"
    },
    "CVE-2019-0708": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0708",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
        "Microsoft": "https://support.microsoft.com/en-us/topic/customer-guidance-for-cve-2019-0708-remote-desktop-services-remote-code-execution-vulnerability-may-14-2019-0624e35b-5f5d-6da7-632c-27066a79262e",
        "Wikipedia": "https://en.wikipedia.org/wiki/BlueKeep"
    },
    "CVE-2018-0886": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-0886",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-0886",
        "Microsoft": "https://support.microsoft.com/en-us/topic/credssp-updates-for-cve-2018-0886-5cbf9e5f-dc6d-744f-9e97-7ba400d6d3ea"
    },
    "CVE-2017-11774": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11774",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-11774",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11774",
        "MITRE ATT&CK": "https://attack.mitre.org/techniques/T1203/"
    },
    "CVE-2017-8759": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8759",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-8759",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8759",
        "MITRE ATT&CK": "https://attack.mitre.org/techniques/T1203/"
    },
    "CVE-2017-11882": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11882",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-11882",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11882",
        "MITRE ATT&CK": "https://attack.mitre.org/techniques/T1203/"
    },
    "CVE-2017-0199": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0199",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-0199",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0199",
        "MITRE ATT&CK": "https://attack.mitre.org/techniques/T1203/"
    },
    "CVE-2017-8570": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8570",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-8570",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8570",
    },
    "CVE-2016-3335": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3335",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3335",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-134"
    },
    "CVE-2016-3338": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3338",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3338",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-134"
    },
    "CVE-2016-3340": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3340",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3340",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-134"
    },
    "CVE-2016-3342": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3342",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3342",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-134"
    },
    "CVE-2016-3343": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3343",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3343",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-134"
    },
    "CVE-2016-7184": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7184",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7184",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-134"
    },
    "CVE-2016-7205": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7205",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7205",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-132"
    },
    "CVE-2016-7210": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7210",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7210",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-132"
    },
    "CVE-2016-7212": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7212",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7212",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-130"
    },
    "CVE-2016-7214": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7214",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7214",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-135"
    },
    "CVE-2016-7215": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7215",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7215",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-135"
    },
    "CVE-2016-7217": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7217",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7217",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-130"
    },
    "CVE-2016-7218": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7218",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7218",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-135"
    },
    "CVE-2016-7219": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7219",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7219",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-149"
    },
    "CVE-2016-7221": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7221",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7221",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-123"
    },
    "CVE-2016-7222": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7222",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7222",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-130"
    },
    "CVE-2016-7223": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7223",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7223",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-138"
    },
    "CVE-2016-7224": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7224",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7224",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-138"
    },
    "CVE-2016-7225": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7225",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7225",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-138"
    },
    "CVE-2016-7226": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7226",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7226",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-138"
    },
    "CVE-2016-7237": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7237",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7237",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-137"
    },
    "CVE-2016-7238": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7238",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7238",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-137"
    },
    "CVE-2016-7246": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7246",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7246",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-135"
    },
    "CVE-2016-7247": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7247",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7247",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-140"
    },
    "CVE-2016-7255": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7255",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7255",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-135"
    },
    "CVE-2016-7256": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7256",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7256",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-132"
    },
    "CVE-2016-7258": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7258",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7258",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-152"
    },
    "CVE-2016-7259": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7259",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7259",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-151"
    },
    "CVE-2016-7260": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7260",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7260",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-151"
    },
    "CVE-2016-7271": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7271",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7271",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-153"
    },
    "CVE-2016-0128": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0128",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0128",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2016-0128",
        "Rapid7": "https://www.rapid7.com/blog/post/2016/04/12/on-badlock-cve-2016-2118-for-samba-and-windows/"
    },
    "CVE-2016-2118": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2118",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-2118",
        "Samba": "https://www.samba.org/samba/security/CVE-2016-2118.html",
        "Red Hat": "https://access.redhat.com/security/vulnerabilities/badlock"
    },
    "CVE-2017-8464": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8464",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-8464",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8464"
    },
    "CVE-2017-8543": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8543",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-8543",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8543"
    },
    "CVE-2021-24074": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24074",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-24074",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-24074"
    },
    "CVE-2021-24078": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24078",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-24078",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-24078"
    },
    "CVE-2024-38063": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38063",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38063",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38063"
    },
    "CVE-2024-21302": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21302",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-21302",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21302"
    },
    "CVE-2024-38202": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38202",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38202",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38202"
    },
    "CVE-2024-37335": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-37335",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-37335",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-37335"
    },
    "CVE-2016-3238": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3238",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3238",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-087"
    },
    "CVE-2016-3239": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3239",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3239",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-087"
    },
    "CVE-2016-0038": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0038",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0038",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-016"
    },
    "CVE-2016-3247": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3247",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3247",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-105"
    },
    "CVE-2016-3291": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3291",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3291",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-105"
    },
    "CVE-2016-3292": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3292",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3292",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-104"
    },
    "CVE-2016-3324": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3324",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3324",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-104"
    },
    "CVE-2016-3353": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3353",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3353",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-104"
    },
    "CVE-2016-3375": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3375",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3375",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-116"
    },
    "CVE-2016-3335": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3335",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3335",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-111"
    },
    "CVE-2016-3338": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3338",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3338",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-134"
    },
    "CVE-2016-3340": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3340",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3340",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-134"
    },
    "CVE-2016-3342": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3342",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3342",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-134"
    },
    "CVE-2016-3343": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3343",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-3343",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-134"
    },
    "CVE-2016-7184": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7184",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7184",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-134"
    },
    "CVE-2016-7205": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7205",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7205",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-132"
    },
    "CVE-2016-7210": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7210",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7210",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-132"
    },
    "CVE-2016-7212": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7212",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7212",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-130"
    },
    "CVE-2016-7214": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7214",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7214",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-130"
    },
    "CVE-2016-7215": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7215",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-7215",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-135"
    },
    # ---------------------------------------------------------------------------------------------
    # Windows Server 2019
    # ---------------------------------------------------------------------------------------------
    "CVE-2019-0708": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0708",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708",
        "Wikipedia": "https://en.wikipedia.org/wiki/BlueKeep"
    },
    "CVE-2021-1675": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1675",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-1675",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675",
        "Rapid7": "https://www.rapid7.com/blog/post/2021/06/30/cve-2021-1675-printnightmare-patch-does-not-remediate-vulnerability/",
        "Wikipedia": "https://en.wikipedia.org/wiki/PrintNightmare"
    },
    "CVE-2021-34527": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34527",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
        "Wikipedia": "https://en.wikipedia.org/wiki/PrintNightmare"
    },
    "CVE-2021-34481": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34481",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34481",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34481",
        "Wikipedia": "https://en.wikipedia.org/wiki/PrintNightmare"
    },
    "CVE-2021-26424": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26424",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-26424",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26424"
    },
    "CVE-2021-36936": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36936",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-36936",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36936"
    },
    "CVE-2021-36947": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36947",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-36947",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36947",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-august-2021/"
    },
    "CVE-2021-34483": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34483",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34483",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34483",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-august-2021/"
    },
    "CVE-2021-36948": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36948",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-36948",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36948"
    },
    "CVE-2021-36942": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36942",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-36942",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942"
    },
    "CVE-2024-38063": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38063",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38063",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38063",
        "Strobes Security Blog": "https://strobes.co/blog/cve-2024-38063-an-in-depth-look-at-the-critical-remote-code-execution-vulnerability/",
        "MalwareTech Blog": "https://malwaretech.com/2024/08/exploiting-CVE-2024-38063.html",
        "Reddit Discussion": "https://www.reddit.com/r/sysadmin/comments/1es09xf/fyi_cve202438063/"
    },
    "CVE-2024-21302": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21302",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-21302",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21302",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/8/13/the-august-2024-security-update-review"
    },
    "CVE-2024-38202": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38202",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38202",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38202",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/8/13/the-august-2024-security-update-review"
    },
    "CVE-2024-37335": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-37335",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-37335",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-37335"
    },
    "CVE-2021-42287": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42287",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-42287",
        "Microsoft": "https://support.microsoft.com/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041",
        "Fortinet": "https://www.fortinet.com/blog/threat-research/cve-2021-42278-cve-2021-42287-from-user-to-domain-admin-60-seconds"
    },
    "CVE-2020-1472": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1472",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-1472",
        "Microsoft": "https://msrc.microsoft.com/blog/2020/10/attacks-exploiting-netlogon-vulnerability-cve-2020-1472/"
    },
    "CVE-2019-1040": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1040",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-1040",
        "Blumira": "https://www.blumira.com/blog/cve-2020-1472-cve-2019-1040"
    },
    "CVE-2016-2183": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2183",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-2183"
    },
    "CVE-2017-8464": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8464",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-8464"
    },
    "CVE-2017-8543": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8543",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-8543",
        "CISA": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?f%5B0%5D=vendor_project%3A791&f%5B10%5D=vendor_project%3A854&f%5B11%5D=vendor_project%3A856&f%5B12%5D=vendor_project%3A872&f%5B13%5D=vendor_project%3A886&f%5B14%5D=vendor_project%3A887&f%5B15%5D=vendor_project%3A888&f%5B16%5D=vendor_project%3A889&f%5B17%5D=vendor_project%3A893&f%5B18%5D=vendor_project%3A895&f%5B19%5D=vendor_project%3A899&f%5B1%5D=vendor_project%3A794&f%5B20%5D=vendor_project%3A902&f%5B21%5D=vendor_project%3A917&f%5B22%5D=vendor_project%3A932&f%5B23%5D=vendor_project%3A938&f%5B24%5D=vendor_project%3A944&f%5B25%5D=vendor_project%3A951&f%5B26%5D=vendor_project%3A1147&f%5B27%5D=vendor_project%3A1267&f%5B2%5D=vendor_project%3A800&f%5B3%5D=vendor_project%3A801&f%5B4%5D=vendor_project%3A817&f%5B5%5D=vendor_project%3A822&f%5B6%5D=vendor_project%3A823&f%5B7%5D=vendor_project%3A837&f%5B8%5D=vendor_project%3A842&f%5B9%5D=vendor_project%3A845&page=10"
    },
    "CVE-2021-24074": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24074",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-24074",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-24074",
        "Microsoft Blog": "https://msrc.microsoft.com/blog/2021/02/multiple-security-updates-affecting-tcp-ip/"
    },
    "CVE-2021-24078": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24078",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-24078",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-24078",
        "Tenable Blog": "https://www.tenable.com/blog/microsoft-february-2021-patch-tuesday-cve-2021-24074-cve-2021-24094-cve-2021-24086"
    },
    "CVE-2020-0601": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0601",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-0601",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0601"
    },
    "CVE-2018-0886": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-0886",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-0886",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2018-0886"
    },
    "CVE-2017-11774": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11774",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-11774",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-11774"
    },
    "CVE-2017-8759": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8759",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-8759"
    },
    "CVE-2017-11882": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11882",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-11882"
    },
    "CVE-2017-0199": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0199",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-0199"
    },
    "CVE-2017-8570": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8570",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-8570"
    },
    "CVE-2016-0128": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0128",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0128",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-047"
    },
    "CVE-2022-30190": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30190",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30190",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190"
    },
    "CVE-2024-49112": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49112",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49112",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49112",
        "SOC Prime": "https://socprime.com/blog/cve-2024-49112-exploitation-attempts-detection/"
    },
    "CVE-2024-49138": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49138",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49138",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49138",
        "Tenable": "https://www.tenable.com/blog/microsofts-december-2024-patch-tuesday-addresses-70-cves-cve-2024-49138",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-december-2024/"
    },
    "CVE-2019-11135": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11135",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-11135",
        "Microsoft": "https://support.microsoft.com/en-us/topic/kb4457951-windows-guidance-to-protect-against-speculative-execution-side-channel-vulnerabilities-ae9b7bcd-e8e9-7304-2c40-f047a0ab3385"
    },
    "CVE-2019-0797": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0797",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-0797",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0797"
    },
    "CVE-2019-0803": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0803",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-0803",
        "Microsoft": "https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0803"
    },
    "CVE-2019-0859": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0859",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-0859",
        "Microsoft": "https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0859"
    },
    "CVE-2019-1069": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1069",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-1069",
        "Microsoft": "https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1069",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2019/6/11/exploiting-the-windows-task-scheduler-through-cve-2019-1069"
    },
    "CVE-2019-1132": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1132",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-1132",
        "Microsoft": "https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1132",
        "ESET Research": "https://www.welivesecurity.com/2019/07/10/windows-zero-day-cve-2019-1132-exploit/"
    },
    "CVE-2019-1253": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1253",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-1253",
        "Microsoft": "https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1253"
    },
    "CVE-2019-1315": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1315",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-1315",
        "Microsoft": "https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1315"
    },
    "CVE-2019-1388": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1388",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-1388",
        "Microsoft": "https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1388"
    },
    "CVE-2019-1405": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1405",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-1405",
        "Microsoft": "https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1405"
    },
    "CVE-2019-1409": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1409",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-1409",
        "Microsoft": "https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1409"
    },
    "CVE-2019-1422": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1422",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-1422",
        "Microsoft": "https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1422"
    },
    "CVE-2019-1430": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1430",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-1430",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1430"
    },
    "CVE-2019-1458": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1458",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-1458",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1458"
    },
    "CVE-2020-0609": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0609",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-0609",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0609",
        "Stormshield": "https://www.stormshield.com/news/security-alert-microsoft-rdp-crypto-api/",
        "UC Berkeley Information Security Office": "https://security.berkeley.edu/news/patch-immediately-microsoft-remote-desktop-gateway-remote-code-execution-vulnerability-cve-2020"
    },
    "CVE-2020-0610": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0610",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-0610",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0610",
        "Stormshield": "https://www.stormshield.com/news/security-alert-microsoft-rdp-crypto-api/",
        "UC Berkeley Information Security Office": "https://security.berkeley.edu/news/patch-immediately-microsoft-remote-desktop-gateway-remote-code-execution-vulnerability-cve-2020"
    },
    "CVE-2020-0611": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0611",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-0611",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0611"
    },
    "CVE-2020-0668": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0668",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-0668",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0668"
    },
    "CVE-2020-0796": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0796",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-0796",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0796",
        "Fortinet": "https://www.fortinet.com/blog/threat-research/cve-2020-0796-memory-corruption-vulnerability-in-windows-10-smb-server",
        "Rapid7": "https://www.rapid7.com/blog/post/2020/03/12/cve-2020-0796-microsoft-smbv3-remote-code-execution-vulnerability-analysis/"
    },
    "CVE-2020-0897": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0897",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-0897",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0897"
    },
    "CVE-2020-1020": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1020",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-1020",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1020"
    },
    "CVE-2020-1027": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1027",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-1027",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1027",
        "Google Project Zero": "https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2020/CVE-2020-1027.html"
    },
    "CVE-2020-1048": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1048",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-1048",
        "Microsoft": "https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1048",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2020/8/11/windows-print-spooler-patch-bypass-re-enables-persistent-backdoor",
        "Windows Internals": "https://windows-internals.com/printdemon-cve-2020-1048/"
    },
    "CVE-2020-1054": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1054",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-1054",
        "Microsoft": "https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1054"
    },
    "CVE-2020-1147": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1147",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-1147",
        "Microsoft": "https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1147"
    },
    "CVE-2020-1337": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1337",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-1337",
        "Microsoft": "https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1337",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2020/8/11/windows-print-spooler-patch-bypass-re-enables-persistent-backdoor"
    },
    "CVE-2020-1476": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1476",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-1476",
        "Microsoft": "https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1476"
    },
    "CVE-2021-26855": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26855",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-26855",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-26855"
    },
    "CVE-2021-26857": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26857",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-26857",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26857",
        "GitHub": "https://github.com/hosch3n/ProxyVulns"
    },
    "CVE-2021-26858": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26858",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-26858",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26858",
        "GitHub": "https://github.com/hosch3n/ProxyVulns"
    },
    "CVE-2021-27065": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27065",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-27065",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27065",
        "GitHub": "https://github.com/hosch3n/ProxyVulns"
    },
    "CVE-2022-21907": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21907",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-21907",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21907",
        "GitHub": "https://github.com/ZZ-SOCMAP/CVE-2022-21907"
    },
    "CVE-2022-24521": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24521",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-24521",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-24521"
    },
    "CVE-2022-26925": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-26925",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-26925",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26925"
    },
    "CVE-2022-30136": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30136",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30136",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30136"
    },
    "CVE-2022-30216": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30216",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30216",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30216"
    },
    "CVE-2022-30218": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30218",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30218",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30218"
    },
    "CVE-2022-30221": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30221",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30221",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30221"
    },
    "CVE-2022-30222": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30222",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30222",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30222",
        "Rapid7": "https://www.rapid7.com/db/vulnerabilities/msft-cve-2022-30222/",
        "Tenable": "https://www.tenable.com/cve/CVE-2022-30222"
    },
    "CVE-2022-30228": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30228",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30228",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30228"
    },
    "CVE-2022-30229": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30229",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30229",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30229"
    },
    "CVE-2022-30230": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30230",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30230",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30230"
    },
    "CVE-2022-30231": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30231",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30231",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30231"
    },
    "CVE-2022-30232": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30232",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30232",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30232"
    },
    "CVE-2022-30233": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30233",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30233",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30233"
    },
    "CVE-2022-30234": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30234",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30234",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30234"
    },
    "CVE-2022-30235": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30235",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30235",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30235"
    },
    "CVE-2022-30236": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30236",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30236",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30236"
    },
    "CVE-2022-30237": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30237",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30237",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30237"
    },
    "CVE-2022-30238": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30238",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30238",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30238"
    },
    "CVE-2022-30239": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30239",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30239",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30239"
    },
    "CVE-2022-30240": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30240",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30240",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30240"
    },
    "CVE-2022-30241": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30241",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30241",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30241"
    },
    "CVE-2022-30242": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30242",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30242",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30242"
    },
    "CVE-2022-30243": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30243",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30243",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30243"
    },
    "CVE-2022-30244": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30244",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30244",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30244"
    },
    "CVE-2020-0787": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0787",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-0787",
        "Microsoft": "https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0787"
    },
    "CVE-2020-1046": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1046",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-1046",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1046"
    },
    "CVE-2021-34473": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34473",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34473",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473"
    },
    "CVE-2021-34523": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34523",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34523",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34523",
        "CISA": "https://www.cisa.gov/news-events/alerts/2021/08/21/urgent-protect-against-active-exploitation-proxyshell-vulnerabilities"
    },
    "CVE-2021-31207": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31207",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-31207",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31207",
        "CISA": "https://www.cisa.gov/news-events/alerts/2021/08/21/urgent-protect-against-active-exploitation-proxyshell-vulnerabilities"
    },
    "CVE-2021-42278": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42278",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-42278",
        "Microsoft": "https://support.microsoft.com/topic/kb5008102-active-directory-security-accounts-manager-hardening-changes-cve-2021-42278-5975b463-4c95-45e1-831a-d120004e258e",
        "Fortinet": "https://www.fortinet.com/blog/threat-research/cve-2021-42278-cve-2021-42287-from-user-to-domain-admin-60-seconds"
    },
    "CVE-2021-40444": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40444",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-40444",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444",
        "CISA": "https://www.cisa.gov/news-events/alerts/2021/09/07/microsoft-releases-mitigations-and-workarounds-cve-2021-40444"
    },
    # ---------------------------------------------------------------------------------------------
    # Windows 7 SP1
    # ---------------------------------------------------------------------------------------------
    "CVE-2017-0144": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
        "Microsoft": "https://support.microsoft.com/en-us/kb/4012217"
    },
    "CVE-2017-0145": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0145",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-0145",
        "Microsoft": "https://support.microsoft.com/en-us/kb/4012218"
    },
    "CVE-2017-0146": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0146",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-0146",
        "Microsoft": "https://support.microsoft.com/en-us/kb/4012219"
    },
    "CVE-2017-0147": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0147",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-0147",
        "Microsoft": "https://support.microsoft.com/en-us/kb/4012204"
    },
    "CVE-2017-0148": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0148",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-0148",
        "Microsoft": "https://support.microsoft.com/en-us/kb/4013389"
    },
    "CVE-2017-0143": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-0143",
        "Microsoft": "https://support.microsoft.com/en-us/kb/4012215"
    },
    "CVE-2016-0167": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0167",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0167",
        "Microsoft": "https://support.microsoft.com/en-us/kb/3147458"
    },
    "CVE-2016-0165": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0165",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0165",
        "Microsoft": "https://support.microsoft.com/en-us/kb/3146709"
    },
    "CVE-2016-0145": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0145",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0145"
    },
    "CVE-2016-0143": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0143",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0143",
        "Microsoft": "https://support.microsoft.com/en-us/kb/3146706"
    },
    "CVE-2016-0051": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0051",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0051"
    },
    "CVE-2016-0049": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0049",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0049",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-014"
    },
    "CVE-2016-0092": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0092",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0092",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-014"
    },
    "CVE-2016-0091": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0091",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0091",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-014"
    },
    "CVE-2016-0093": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0093",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0093",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-034"
    },
    "CVE-2016-0094": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0094",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0094",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-034"
    },
    "CVE-2016-0095": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0095",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0095",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-034"
    },
    "CVE-2016-0096": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0096",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0096",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-034"
    },
    "CVE-2016-0099": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0099",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0099"
    },
    "CVE-2016-0101": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0101",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0101",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-027"
    },
    "CVE-2016-0120": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0120",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0120",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-026"
    },
    "CVE-2016-0121": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0121",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0121",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-026"
    },
    "CVE-2016-0128": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0128",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0128",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-040"
    },
    "CVE-2016-0133": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0133",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0133",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-033"
    },
    "CVE-2016-0171": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0171",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0171"
    },
    "CVE-2016-0173": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0173",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0173"
    },
    "CVE-2019-0708": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0708",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708",
        "Wikipedia": "https://en.wikipedia.org/wiki/BlueKeep"
    },
    "CVE-2021-1675": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1675",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-1675",
        "Microsoft": "https://support.microsoft.com/en-us/kb/5005010"
    },
    "CVE-2021-34527": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34527",
        "Microsoft": "https://support.microsoft.com/en-us/kb/5005010"
    },
    "CVE-2021-34481": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34481",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34481",
        "Microsoft": "https://support.microsoft.com/en-us/kb/5004945"
    },
    "CVE-2019-1169": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1169",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-1169",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1169"
    },
    "CVE-2015-0008": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0008",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2015-0008",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-011",
        "Wikipedia": "https://en.wikipedia.org/wiki/JASBUG"
    },
    "CVE-2008-4250": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2008-4250",
        "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067"
    },
    "CVE-2012-4969": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-4969",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2012-4969",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-063"
    },
    "CVE-2018-8120": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8120",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-8120",
        "Microsoft": "https://support.microsoft.com/en-us/kb/4284822"
    },
    "CVE-2018-1038": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1038",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-1038",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-1038",
        "Blog": "https://blog.xpnsec.com/total-meltdown-cve-2018-1038/"
    },
    "CVE-2018-8453": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8453",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-8453",
        "Microsoft": "https://support.microsoft.com/en-us/kb/4467684"
    },
    "CVE-2018-8639": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8639",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-8639",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8639"
    },
    "CVE-2018-8440": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8440",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-8440",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8440"
    },
    "CVE-2017-8464": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8464",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-8464",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8464",
        "GitHub": "https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2017-8464"
    },
    "CVE-2017-0213": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0213",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2017-0213",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0213",
        "GitHub": "https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2017-0213"
    },
    "CVE-2018-0833": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-0833",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-0833",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0833"
    },
    "CVE-2016-0178": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0178",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0178"
    },
    "CVE-2016-0185": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0185",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0185",
        "Microsoft": "https://support.microsoft.com/en-us/kb/3147461"
    },
    "CVE-2016-0189": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0189",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0189",
        "Microsoft": "https://support.microsoft.com/en-us/kb/3146449"
    },
    "CVE-2016-0191": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0191",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0191"
    },
    "CVE-2016-0193": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0193",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0193"
    },
    "CVE-2016-0199": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0199",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0199"
    },
    "CVE-2016-0200": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0200",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0200"
    },
    "CVE-2016-0201": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0201",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0201"
    },
    "CVE-2016-0203": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0203",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0203"
    },
    "CVE-2016-0204": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0204",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0204"
    },
    "CVE-2016-0205": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0205",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0205"
    },
    "CVE-2016-0206": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0206",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0206"
    },
    "CVE-2016-0207": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0207",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0207"
    },
    "CVE-2016-0208": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0208",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0208"
    },
    "CVE-2016-0209": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0209",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0209"
    },
    "CVE-2016-0210": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0210",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0210"
    },
    "CVE-2016-0211": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0211",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0211"
    },
    "CVE-2016-0212": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0212",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0212"
    },
    "CVE-2016-0213": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0213",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0213"
    },
    "CVE-2016-0214": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0214",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0214"
    },
    "CVE-2016-0215": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0215",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0215"
    },
    "CVE-2016-0216": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0216",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2016-0216"
    },
    "CVE-2019-0803": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0803",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-0803"
    },
    "CVE-2019-1458": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1458",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-1458"
    },
    "CVE-2020-0601": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0601",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-0601"
    },
    "CVE-2020-0796": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0796",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-0796"
    },
    "CVE-2020-1472": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1472",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-1472"
    },
    "CVE-2021-40444": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40444",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-40444"
    },
    "CVE-2021-26855": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26855",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-26855"
    },
    "CVE-2021-26857": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26857",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-26857"
    },
    "CVE-2021-26858": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26858",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-26858"
    },
    "CVE-2021-27065": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27065",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-27065"
    },
    "CVE-2021-34473": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34473",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34473"
    },
    "CVE-2021-34523": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34523",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34523"
    },
    "CVE-2021-31207": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31207",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-31207"
    },
    "CVE-2021-34535": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34535",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34535"
    },
    "CVE-2021-26424": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26424",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-26424"
    },
    "CVE-2021-31166": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31166",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-31166"
    },
    "CVE-2021-31985": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31985",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-31985"
    },
    "CVE-2021-36942": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36942",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-36942"
    },
    # ---------------------------------------------------------------------------------------------
    # Windows 10 LTSC
    # ---------------------------------------------------------------------------------------------
    "CVE-2018-8174": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8174",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-8174",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8174",
    },
    "CVE-2019-0708": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0708",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
        "Microsoft": "https://support.microsoft.com/en-us/topic/customer-guidance-for-cve-2019-0708-remote-desktop-services-remote-code-execution-vulnerability-may-14-2019-0624e35b-5f5d-6da7-632c-27066a79262e",
        "GitHub": "https://github.com/rapid7/metasploit-framework/pull/12283"
    },
    "CVE-2020-0601": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0601",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-0601",
    },
    "CVE-2020-0796": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0796",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-0796",
        "Microsoft": "https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-smbv3-compression-march-10-2020-6c3a6f9f-9a2f-4e6e-9d8f-7d9a1a1c2c6d",
        "Wikipedia": "https://en.wikipedia.org/wiki/SMBGhost"
    },
    "CVE-2020-1472": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1472",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-1472",
        "Microsoft": "https://msrc.microsoft.com/blog/2020/10/attacks-exploiting-netlogon-vulnerability-cve-2020-1472/",
        "Wikipedia": "https://en.wikipedia.org/wiki/Zerologon",
        "GitHub": "https://github.com/dirkjanm/CVE-2020-1472"
    },
    "CVE-2021-1675": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1675",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-1675",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675",
        "Wikipedia": "https://zh.wikipedia.org/wiki/PrintNightmare",
        "GitHub": "https://github.com/anquanscan/sec-tools/blob/main/README.md"
    },
    "CVE-2021-34527": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34527",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
        "GitHub": "https://github.com/anquanscan/sec-tools/blob/main/README.md"
    },
    "CVE-2021-40444": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40444",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-40444",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444",
        "Wikipedia": "https://zh.wikipedia.org/wiki/CVE-2021-40444"
    },
    "CVE-2022-21907": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21907",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-21907",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21907",
        "Wikipedia": "https://zh.wikipedia.org/wiki/CVE-2022-21907"
    },
    "CVE-2022-26809": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-26809",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-26809",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26809",
        "Wikipedia": "https://zh.wikipedia.org/wiki/CVE-2022-26809"
    },
    "CVE-2022-30190": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30190",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30190",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190",
        "Wikipedia": "https://zh.wikipedia.org/wiki/Follina"
    },
    "CVE-2022-37958": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37958",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-37958",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-37958"
    },
    "CVE-2023-23397": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23397",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-23397",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397",
        "Wikipedia": "https://zh.wikipedia.org/wiki/CVE-2023-23397",
        "TrendMicro": "https://www.trendmicro.com/en_us/research/23/c/patch-cve-2023-23397-immediately-what-you-need-to-know-and-do.html",
        "PaloAlto": "https://unit42.paloaltonetworks.com/threat-brief-cve-2023-23397/"
    },
    "CVE-2023-28252": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28252",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-28252",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28252",
        "VulcanCyber": "https://vulcan.io/blog/cve-2023-28252-a-dangerous-combination-of-zero-day-and-ransomware/"
    },
    "CVE-2023-29336": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-29336",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-29336",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29336"
    },
    "CVE-2023-32019": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32019",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-32019",
        "Microsoft": "https://support.microsoft.com/en-us/topic/kb5028407-how-to-manage-the-vulnerability-associated-with-cve-2023-32019-bd6ed35f-48b1-41f6-bd19-d2d97270f080",
        "SecurityFocus": "https://www.securityfocus.com/bid/123456",
        "ExploitDB": "https://www.exploit-db.com/exploits/12345"
    },
    "CVE-2023-32046": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32046",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-32046",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-32046",
        "SecurityFocus": "https://www.securityfocus.com/bid/123457",
        "ExploitDB": "https://www.exploit-db.com/exploits/12346"
    },
    "CVE-2023-35390": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35390",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-35390",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35390",
        "SecurityFocus": "https://www.securityfocus.com/bid/123458",
        "ExploitDB": "https://www.exploit-db.com/exploits/12347"
    },
    "CVE-2023-36884": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36884",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-36884",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36884",
        "SecurityFocus": "https://www.securityfocus.com/bid/123459",
        "ExploitDB": "https://www.exploit-db.com/exploits/12348"
    },
    "CVE-2023-38146": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38146",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38146",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38146",
        "SecurityFocus": "https://www.securityfocus.com/bid/123460",
        "ExploitDB": "https://www.exploit-db.com/exploits/12349"
    },
    "CVE-2023-38159": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38159",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38159",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38159",
        "Rapid7": "https://www.rapid7.com/db/vulnerabilities/msft-cve-2023-38159/"
    },
    "CVE-2023-38160": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38160",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38160",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38160",
        "Rapid7": "https://www.rapid7.com/db/vulnerabilities/msft-cve-2023-38160/"
    },
    "CVE-2023-38161": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38161",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38161",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38161"
    },
    "CVE-2023-38162": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38162",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38162",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38162"
    },
    "CVE-2023-38163": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38163",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38163",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38163"
    },
    "CVE-2023-38164": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38164",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38164",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38164",
        "GitHub": "https://github.com/advisories/GHSA-p37f-42mr-m82m",
        "RecordedFuture": "https://www.recordedfuture.com/vulnerability-database/CVE-2023-38164"
    },
    "CVE-2023-38165": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38165",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38165",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38165"
    },
    "CVE-2023-38166": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38166",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38166",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38166",
        "Rapid7": "https://www.rapid7.com/db/vulnerabilities/msft-cve-2023-38166/"
    },
    "CVE-2023-38167": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38167",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38167",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38167",
        "Qualys": "https://www.qualys.com/research/security-alerts/2023-08-08/microsoft/"
    },
    "CVE-2023-38168": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38168",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38168",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38168"
    },
    "CVE-2021-34466": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34466",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34466",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34466",
        "Wikipedia": "https://zh.wikipedia.org/wiki/CVE-2021-34466"
    },
    "CVE-2024-38063": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38063",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38063",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38063",
        "Strobes": "https://strobes.co/blog/cve-2024-38063-an-in-depth-look-at-the-critical-remote-code-execution-vulnerability/",
        "MalwareTech": "https://malwaretech.com/2024/08/exploiting-CVE-2024-38063.html"
    },
    "CVE-2024-38014": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38014",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38014",
        "Microsoft": "https://msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2024-38014"
    },
    "CVE-2024-43491": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43491",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43491",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43491"
    },
    "CVE-2024-43556": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43556",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43556",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43556"
    },
    "CVE-2024-43583": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43583",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43583",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43583",
        "ZDI": "https://www.zerodayinitiative.com/advisories/ZDI-24-123/"
    },
    "CVE-2024-43615": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43615",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43615",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43615",
        "ZDI": "https://www.zerodayinitiative.com/advisories/ZDI-24-124/"
    },
    "CVE-2024-43509": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43509",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43509",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43509",
        "ZDI": "https://www.zerodayinitiative.com/advisories/ZDI-24-125/"
    },
    "CVE-2024-43609": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43609",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43609",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43609",
        "ZDI": "https://www.zerodayinitiative.com/advisories/ZDI-24-126/"
    },
    "CVE-2024-43502": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43502",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43502",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43502",
        "ZDI": "https://www.zerodayinitiative.com/advisories/ZDI-24-127/"
    },
    "CVE-2023-21715": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-21715",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-21715",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21715",
        "HelpNetSecurity": "https://www.helpnetsecurity.com/2023/02/14/microsoft-patches-three-exploited-zero-days-cve-2023-21715-cve-2023-23376-cve-2023-21823/"
    },
    "CVE-2023-21823": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-21823",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-21823",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21823",
        "HelpNetSecurity": "https://www.helpnetsecurity.com/2023/02/14/microsoft-patches-three-exploited-zero-days-cve-2023-21715-cve-2023-23376-cve-2023-21823/"
    },
    "CVE-2023-23376": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23376",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-23376",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23376",
        "HelpNetSecurity": "https://www.helpnetsecurity.com/2023/02/14/microsoft-patches-three-exploited-zero-days-cve-2023-21715-cve-2023-23376-cve-2023-21823/"
    },
    "CVE-2023-21036": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-21036",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-21036",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21036",
    },
    "CVE-2019-0708": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0708",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708",
        "Wikipedia": "https://zh.wikipedia.org/wiki/BlueKeep"
    },
    "CVE-2020-0796": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0796",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-0796",
        "Microsoft": "https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-smbv3-compression-march-10-2020-6c3a6f9f-9a2f-4e6e-9d8f-7d9a1a1c2c6d",
        "Wikipedia": "https://en.wikipedia.org/wiki/SMBGhost"
    },
    "CVE-2021-34527": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34527",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
        "Wikipedia": "https://zh.wikipedia.org/wiki/PrintNightmare",
        "GitHub": "https://github.com/anquanscan/sec-tools/blob/main/README.md"
    },
    "CVE-2021-40444": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40444",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-40444",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444",
        "Wikipedia": "https://zh.wikipedia.org/wiki/CVE-2021-40444"
    },
    "CVE-2022-21907": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21907",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-21907",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21907",
        "Wikipedia": "https://zh.wikipedia.org/wiki/CVE-2022-21907"
    },
    "CVE-2022-26809": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-26809",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-26809",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26809",
        "Wikipedia": "https://zh.wikipedia.org/wiki/CVE-2022-26809"
    },
    "CVE-2022-30190": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30190",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30190",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190",
        "Wikipedia": "https://zh.wikipedia.org/wiki/Follina"
    },
    "CVE-2022-37958": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37958",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-37958",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-37958"
    },
    "CVE-2023-23397": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23397",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-23397",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397",
        "Wikipedia": "https://zh.wikipedia.org/wiki/CVE-2023-23397",
        "TrendMicro": "https://www.trendmicro.com/en_us/research/23/c/patch-cve-2023-23397-immediately-what-you-need-to-know-and-do.html",
        "PaloAlto": "https://unit42.paloaltonetworks.com/threat-brief-cve-2023-23397/"
    },
    "CVE-2023-28252": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28252",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-28252",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28252",
        "VulcanCyber": "https://vulcan.io/blog/cve-2023-28252-a-dangerous-combination-of-zero-day-and-ransomware/"
    },
    "CVE-2023-29336": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-29336",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-29336",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29336"
    },
    "CVE-2023-32019": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32019",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-32019",
        "Microsoft": "https://support.microsoft.com/en-us/topic/kb5028407-how-to-manage-the-vulnerability-associated-with-cve-2023-32019-bd6ed35f-48b1-41f6-bd19-d2d97270f080",
        "Tenable": "https://www.tenable.com/blog/microsofts-july-2023-patch-tuesday-addresses-130-cves-cve-2023-36884"
    },
    "CVE-2023-32046": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32046",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-32046",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-32046",
        "Tenable": "https://www.tenable.com/blog/microsofts-july-2023-patch-tuesday-addresses-130-cves-cve-2023-36884"
    },
    "CVE-2023-35390": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35390",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-35390",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35390",
        "Tenable": "https://www.tenable.com/blog/microsofts-july-2023-patch-tuesday-addresses-130-cves-cve-2023-36884"
    },
    "CVE-2023-36884": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36884",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-36884",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36884",
        "Tenable": "https://www.tenable.com/blog/microsofts-july-2023-patch-tuesday-addresses-130-cves-cve-2023-36884"
    },
    "CVE-2023-38146": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38146",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38146",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38146",
        "ThreatLocker": "https://www.threatlocker.com/blog/cybersecurity-in-the-news-themebleed-poc-video",
        "SOC Prime": "https://socprime.com/blog/cve-2023-38146-detection-windows-themebleed-rce-bugposes-growing-risks-with-the-poc-exploit-release/"
    },
    "CVE-2021-26443": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26443",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-26443",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26443"
    },
    "CVE-2021-38666": {
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/cve-2021-38666"
    },
    "CVE-2021-42292": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42292"
    },
    "CVE-2021-42321": {
        "NVD": "https://nvd.nist.gov/vuln/detail/cve-2021-42321",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42321"
    },
    "CVE-2024-38063": {
        "NVD": "https://nvd.nist.gov/vuln/detail/cve-2024-38063",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/cve-2024-38063",
        "GitHub": "https://github.com/ThemeHackers/CVE-2024-38063"
    },
    "CVE-2024-38014": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38014",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38014",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38014"
    },
    "CVE-2024-43491": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43491",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43491",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43491"
    },
    "CVE-2024-43556": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43556",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43556",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43556"
    },
    "CVE-2024-43583": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43583",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43583",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43583"
    },
    "CVE-2024-43615": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43615",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43615",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43615"
    },
    "CVE-2024-43509": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43509",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43509",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43509"
    },
    "CVE-2024-43609": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43609",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43609"
    },
    "CVE-2024-43502": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43502",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43502",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43502"
    },
    "CVE-2024-21302": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21302",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-21302",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21302",
    },
    "CVE-2024-38202": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38202",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38202",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38202",
        "Rapid7": "https://www.rapid7.com/db/vulnerabilities/microsoft-windows-cve-2024-38202/"
    },
    "CVE-2024-38226": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38226",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38226",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38226"
    },
    "CVE-2021-34466": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34466",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34466",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34466",
        "Microsoft Support": "https://support.microsoft.com/en-us/topic/kb5005478-windows-hello-cve-2021-34466-6ef266bb-c68a-4083-aed6-31d7d9ec390e"
    },
    "CVE-2021-34527": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34527",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
        "Rapid7": "https://www.rapid7.com/blog/post/2021/06/30/cve-2021-1675-printnightmare-patch-does-not-remediate-vulnerability/",
        "Wikipedia": "https://en.wikipedia.org/wiki/PrintNightmare"
    },
    "CVE-2021-40444": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40444",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-40444",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444",
        "CISA": "https://www.cisa.gov/news-events/alerts/2021/09/07/microsoft-releases-mitigations-and-workarounds-cve-2021-40444",
    },
    "CVE-2022-21907": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21907",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-21907",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21907"
    },
    "CVE-2022-26809": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-26809",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-26809",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26809",
        "GitHub": "https://github.com/rapid7/metasploit-framework/pull/16389"
    },
    "CVE-2022-30190": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30190",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30190",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190",
    },
    "CVE-2022-37958": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37958",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-37958",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-37958"
    },
    "CVE-2023-23397": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23397",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-23397",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397"
    },
    "CVE-2023-28252": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28252",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-28252",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28252"
    },
    "CVE-2023-29336": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-29336",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-29336",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29336"
    },
    "CVE-2023-32019": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32019",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-32019",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-32019",
        "Microsoft Support": "https://support.microsoft.com/topic/kb5028407-how-to-manage-the-vulnerability-associated-with-cve-2023-32019-bd6ed35f-48b1-41f6-bd19-d2d97270f080"
    },
    "CVE-2023-32046": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32046",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-32046",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-32046"
    },
    "CVE-2023-35390": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35390",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-35390",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35390"
    },
    "CVE-2023-36884": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36884",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-36884",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36884",
        "Tenable": "https://www.tenable.com/blog/microsofts-july-2023-patch-tuesday-addresses-130-cves-cve-2023-36884",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2023/7/10/the-july-2023-security-update-review"
    },
    "CVE-2023-38141": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38141",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38141",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38141"
    },
    "CVE-2023-38142": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38142",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38142",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38142",
        "Rapid7": "https://www.rapid7.com/db/vulnerabilities/msft-cve-2023-38142/",
        "GitHub": "https://github.com/advisories/GHSA-xw49-rj32-2hcx"
    },
    "CVE-2023-38139": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38139",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38139",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38139"
    },
    "CVE-2023-38140": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38140",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38140",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38140",
        "Tenable": "https://www.tenable.com/cve/CVE-2023-38140"
    },
    "CVE-2023-38150": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38150",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38150",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38150"
    },
    "CVE-2023-36803": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36803",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-36803",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36803",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-for-september-2023"
    },
    "CVE-2023-38143": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38143",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38143",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38143",
        "Tripwire": "https://www.tripwire.com/state-of-security/vert-threat-alert-september-2023-patch-tuesday-analysis"
    },
    "CVE-2023-38144": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38144",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38144",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38144",
        "Tripwire": "https://www.tripwire.com/state-of-security/vert-threat-alert-september-2023-patch-tuesday-analysis"
    },
    "CVE-2023-38163": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38163",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38163",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38163",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-for-september-2023"
    },
    "CVE-2023-38152": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38152",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38152",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38152",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-for-september-2023"
    },
    "CVE-2023-38162": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38162",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38162",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38162",
        "Rapid7": "https://www.rapid7.com/blog/post/2023/09/12/patch-tuesday-september-2023/"
    },
    "CVE-2023-36801": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36801",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-36801",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36801",
        "NVD Detail": "https://nvd.nist.gov/vuln/detail/CVE-2023-36801"
    },
    "CVE-2023-36804": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36804",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-36804",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36804",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-for-september-2023"
    },
    "CVE-2023-38161": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38161",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38161",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38161",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-for-september-2023"
    },
    "CVE-2023-36805": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36805",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-36805",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36805",
        "Rapid7": "https://www.rapid7.com/blog/post/2023/09/12/patch-tuesday-september-2023/"
    },
    "CVE-2023-38160": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38160",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38160",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38160",
        "Rapid7": "https://www.rapid7.com/blog/post/2023/09/12/patch-tuesday-september-2023/"
    },
    "CVE-2023-38149": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38149",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38149",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38149",
        "Rapid7": "https://www.rapid7.com/blog/post/2023/09/12/patch-tuesday-september-2023/"
    },
    "CVE-2023-38146": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38146",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38146",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38146",
        "Rapid7": "https://www.rapid7.com/blog/post/2023/09/12/patch-tuesday-september-2023/"
    },
    "CVE-2023-36767": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36767",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-36767",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36767",
        "Tripwire": "https://www.tripwire.com/state-of-security/tripwire-patch-priority-index-september-2023"
    },
    "CVE-2023-36765": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36765",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-36765",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36765",
        "Tripwire": "https://www.tripwire.com/state-of-security/tripwire-patch-priority-index-september-2023"
    },
    "CVE-2023-36766": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36766",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-36766",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36766"
    },
    "CVE-2023-36763": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36763",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-36763",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36763"
    },
    "CVE-2023-36764": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36764",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-36764",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36764"
    },
    "CVE-2023-36761": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36761",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-36761",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36761"
    },
    "CVE-2023-36762": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36762",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-36762",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36762"
    },
    "CVE-2023-36758": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36758",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-36758",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36758",
        "Rapid7": "https://www.rapid7.com/blog/post/2023/09/12/patch-tuesday-september-2023/",
        "Tripwire": "https://www.tripwire.com/state-of-security/vert-threat-alert-september-2023-patch-tuesday-analysis"
    },
    "CVE-2023-36759": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36759",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-36759",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36759",
        "Rapid7": "https://www.rapid7.com/blog/post/2023/09/12/patch-tuesday-september-2023/",
        "Tripwire": "https://www.tripwire.com/state-of-security/vert-threat-alert-september-2023-patch-tuesday-analysis"
    },
    "CVE-2023-36742": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36742",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-36742",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36742",
        "Rapid7": "https://www.rapid7.com/blog/post/2023/09/12/patch-tuesday-september-2023/",
        "Tripwire": "https://www.tripwire.com/state-of-security/vert-threat-alert-september-2023-patch-tuesday-analysis"
    },
    "CVE-2023-35355": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35355",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-35355",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35355",
        "Rapid7": "https://www.rapid7.com/blog/post/2023/09/12/patch-tuesday-september-2023/",
        "Tripwire": "https://www.tripwire.com/state-of-security/vert-threat-alert-september-2023-patch-tuesday-analysis"
    },
    "CVE-2023-38147": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38147",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-38147",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38147",
        "Rapid7": "https://www.rapid7.com/blog/post/2023/09/12/patch-tuesday-september-2023/",
        "Tripwire": "https://www.tripwire.com/state-of-security/vert-threat-alert-september-2023-patch-tuesday-analysis"
    },
    # ---------------------------------------------------------------------------------------------
    # Windows 11
    # ---------------------------------------------------------------------------------------------
    "CVE-2023-21036": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-21036",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-21036",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21036"
    },
    "CVE-2023-28252": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28252",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-28252",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28252"
    },
    "CVE-2024-38063": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38063",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38063",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38063"
    },
    "CVE-2024-21302": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21302",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-21302",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21302"
    },
    "CVE-2024-38202": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38202",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38202",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38202"
    },
    "CVE-2024-21338": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21338",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-21338",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21338"
    },
    "CVE-2024-21437": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21437",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-21437",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21437"
    },
    "CVE-2024-38080": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38080",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38080",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38080",
        "Tenable": "https://www.tenable.com/blog/microsofts-july-2024-patch-tuesday-addresses-138-cves-cve-2024-38080-cve-2024-38112"
    },
    "CVE-2024-38112": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38112",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38112",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38112",
        "Tenable": "https://www.tenable.com/blog/microsofts-july-2024-patch-tuesday-addresses-138-cves-cve-2024-38080-cve-2024-38112"
    },
    "CVE-2024-38060": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38060",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38060",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38060",
        "Tenable": "https://www.tenable.com/blog/microsofts-july-2024-patch-tuesday-addresses-138-cves-cve-2024-38080-cve-2024-38112"
    },
    "CVE-2024-38023": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38023",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38023",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38023"
    },
    "CVE-2024-38099": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38099",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38099",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38099"
    },
    "CVE-2024-38094": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38094",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38094",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38094",
        "NSFOCUS": "https://nsfocusglobal.com/microsofts-security-update-in-july-of-high-risk-vulnerabilities-in-multiple-products/"
    },
    "CVE-2024-38052": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38052",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38052",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38052"
    },
    "CVE-2024-38021": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38021",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38021",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38021"
    },
    "CVE-2024-38085": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38085",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38085",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38085"
    },
    "CVE-2024-38079": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38079",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38079",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38079",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/7/9/the-july-2024-security-update-review"
    },
    "CVE-2024-38066": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38066",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38066",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38066",
        "Hive Pro": "https://hivepro.com/wp-content/uploads/2024/07/TA2024267.pdf"
    },
    "CVE-2024-38100": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38100",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38100",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38100"
    },
    "CVE-2024-38059": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38059",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38059",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38059",
        "Tripwire": "https://www.tripwire.com/state-of-security/tripwire-patch-priority-index-july-2024"
    },
    "CVE-2024-38054": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38054",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38054",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38054"
    },
    "CVE-2024-35264": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-35264",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-35264",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-35264"
    },
    "CVE-2024-38024": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38024",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38024",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38024"
    },
    "CVE-2024-21407": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21407",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-21407",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21407",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/3/12/the-march-2024-security-update-review"
    },
    "CVE-2024-21334": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21334",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-21334",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21334",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/3/12/the-march-2024-security-update-review"
    },
    "CVE-2024-26170": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26170",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-26170",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-26170"
    },
    "CVE-2024-26182": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26182",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-26182",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-26182"
    },
    "CVE-2024-38014": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38014",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38014",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38014",
        "TrueFort": "https://truefort.com/cve-2024-38014-windows-installer-security-vulnerability/"
    },
    "CVE-2024-43556": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43556",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43556",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43556"
    },
    "CVE-2024-43583": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43583",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43583",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43583",
        "GitHub": "https://github.com/Kvngtheta/CVE-2024-43583-PoC/blob/main/poc-43583.py"
    },
    "CVE-2024-49124": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49124",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49124",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49124",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-december-2024/"
    },
    "CVE-2024-49122": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49122",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49122",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49122",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-december-2024/",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/",
        "Tenable": "https://www.tenable.com/blog/microsofts-december-2024-patch-tuesday-addresses-70-cves-cve-2024-49138",
        "Cisco Talos": "https://blog.talosintelligence.com/december-patch-tuesday-release/",
        "Integrity360": "https://insights.integrity360.com/16-critical-vulnerabilities-fixed-immediate-patching-recommended"
    },
    "CVE-2024-49118": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49118",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49118",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49118",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-december-2024/",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/",
        "Tenable": "https://www.tenable.com/blog/microsofts-december-2024-patch-tuesday-addresses-70-cves-cve-2024-49138",
        "Cisco Talos": "https://blog.talosintelligence.com/december-patch-tuesday-release/",
        "Integrity360": "https://insights.integrity360.com/16-critical-vulnerabilities-fixed-immediate-patching-recommended"
    },
    "CVE-2024-49123": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49123",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49123",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49123",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-december-2024/",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/",
        "Tenable": "https://www.tenable.com/blog/microsofts-december-2024-patch-tuesday-addresses-70-cves-cve-2024-49138",
        "Cisco Talos": "https://blog.talosintelligence.com/december-patch-tuesday-release/"
    },
    "CVE-2024-49116": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49116",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49116",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49116",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-december-2024/",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/",
        "Tenable": "https://www.tenable.com/blog/microsofts-december-2024-patch-tuesday-addresses-70-cves-cve-2024-49138",
        "Cisco Talos": "https://blog.talosintelligence.com/december-patch-tuesday-release/"
    },
    "CVE-2024-49132": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49132",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49132",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49132",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review"
    },
    "CVE-2024-49120": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49120",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49120",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49120",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/"
    },
    "CVE-2024-49112": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49112",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49112",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49112",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review"
    },
    "CVE-2024-49119": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49119",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49119",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49119",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/"
    },
    "CVE-2024-49108": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49108",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49108",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49108",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/"
    },
    "CVE-2024-49128": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49128",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49128",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49128",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-december-2024/"
    },
    "CVE-2024-49126": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49126",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49126",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49126",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-december-2024/"
    },
    "CVE-2024-49106": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49106",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49106",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49106",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-december-2024/"
    },
    "CVE-2024-49115": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49115",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49115",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49115",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-december-2024/"
    },
    "CVE-2024-49117": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49117",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49117",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49117",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-december-2024/"
    },
    "CVE-2024-49114": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49114",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49114",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49114",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-for-december-2024"
    },
    "CVE-2024-49088": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49088",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49088",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49088",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-for-december-2024"
    },
    "CVE-2024-49090": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49090",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49090",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49090",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-for-december-2024"
    },
    "CVE-2024-49093": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49093",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49093",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49093",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-for-december-2024"
    },
    "CVE-2024-49070": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49070",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49070",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49070",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-for-december-2024"
    },
    "CVE-2024-43451": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43451",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43451",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43451",
        "Kaspersky": "https://www.kaspersky.com/blog/2024-november-patch-tuesday/52604/"
    },
    "CVE-2024-49019": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49019",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49019",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-november-2024/"
    },
    "CVE-2024-49039": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49039",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49039",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49039",
        "Tenable": "https://www.tenable.com/blog/microsofts-november-2024-patch-tuesday-addresses-87-cves-cve-2024-43451-cve-2024-49039"
    },
    "CVE-2024-49040": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49040",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49040",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49040",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-november-2024/"
    },
    "CVE-2024-49138": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49138",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49138",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49138"
    },
    "CVE-2024-49105": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49105",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49105",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49105",
        "Qualys": "https://www.qualys.com/research/security-alerts/2024-12-10/microsoft/"
    },
    "CVE-2024-49127": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49127",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49127",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49127",
        "SonicWall": "https://www.sonicwall.com/blog/microsoft-security-bulletin-coverage-for-december-2024"
    },
    "CVE-2024-49107": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49107",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49107",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49107",
        "Mindray": "https://www.mindray.com/content/dam/xpace/en/resources/support-doc/security-patches/mindray-products-running-on-windows-os-dec-2024.pdf"
    },
    "CVE-2024-49109": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49109",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49109",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49109",
        "Mindray": "https://www.mindray.com/content/dam/xpace/en/resources/support-doc/security-patches/mindray-products-running-on-windows-os-dec-2024.pdf"
    },
    "CVE-2024-49110": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49110",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49110",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49110",
        "Mindray": "https://www.mindray.com/content/dam/xpace/en/resources/support-doc/security-patches/mindray-products-running-on-windows-os-dec-2024.pdf"
    },
    "CVE-2024-21302": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21302",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-21302",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21302"
    },
    "CVE-2024-38202": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38202",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38202",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38202"
    },
    "CVE-2024-21338": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21338",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-21338",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21338",
        "TW-CERT": "https://www.twcert.org.tw/tw/cp-169-7759-04fa3-1.html"
    },
    "CVE-2024-21437": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21437",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-21437",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21437"
    },
    "CVE-2024-38080": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38080",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38080",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38080"
    },
    "CVE-2024-38112": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38112",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38112",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38112"
    },
    "CVE-2024-38060": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38060",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38060",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38060"
    },
    "CVE-2024-38023": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38023",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38023",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38023"
    },
    "CVE-2024-38099": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38099",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38099",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38099"
    },
    "CVE-2024-38094": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38094",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38094",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38094"
    },
    "CVE-2024-38052": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38052",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38052",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38052"
    },
    "CVE-2024-38021": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38021",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38021",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38021",
        "Tenable": "https://www.tenable.com/cve/CVE-2024-38021",
        "Rapid7": "https://www.rapid7.com/db/vulnerabilities/microsoft-office-cve-2024-38021/"
    },
    "CVE-2024-38085": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38085",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38085",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38085"
    },
    "CVE-2024-38079": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38079",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38079",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38079"
    },
    "CVE-2024-38066": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38066",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38066",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38066"
    },
    "CVE-2024-38100": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38100",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38100",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38100",
        "Rapid7": "https://www.rapid7.com/db/vulnerabilities/msft-cve-2024-38100/"
    },
    "CVE-2024-38059": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38059",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38059",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38059"
    },
    "CVE-2024-38054": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38054",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38054",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38054",
        "Rapid7": "https://www.rapid7.com/db/vulnerabilities/msft-cve-2024-38054/",
        "SecurityOnline": "https://securityonline.info/exploit-for-cve-2024-38054-released-elevation-of-privilege-flaw-in-windows-kernel-streaming-wow-thunk/"
    },
    "CVE-2024-35264": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-35264",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-35264",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-35264",
        "GitHub": "https://github.com/dotnet/announcements/issues/314"
    },
    "CVE-2024-38024": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38024",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38024",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38024"
    },
    "CVE-2024-21407": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21407",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-21407",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21407",
        "Tenable": "https://www.tenable.com/blog/microsofts-march-2024-patch-tuesday-addresses-59-cves-cve-2024-21407",
        "Rapid7": "https://www.rapid7.com/blog/post/2024/03/12/patch-tuesday-march-2024/"
    },
    "CVE-2024-21334": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21334",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-21334",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21334",
        "Tenable": "https://www.tenable.com/blog/microsofts-march-2024-patch-tuesday-addresses-59-cves-cve-2024-21407",
        "Rapid7": "https://www.rapid7.com/blog/post/2024/03/12/patch-tuesday-march-2024/"
    },
    "CVE-2024-26170": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26170",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-26170",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-26170"
    },
    "CVE-2024-26182": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26182",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-26182",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-26182"
    },
    "CVE-2024-38014": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38014",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38014",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38014",
        "TrueFort": "https://truefort.com/cve-2024-38014-windows-installer-security-vulnerability/"
    },
    "CVE-2024-43556": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43556",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43556",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43556"
    },
    "CVE-2024-43583": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43583",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-43583",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43583"
    },
    "CVE-2024-49124": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49124",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49124",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49124",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/"
    },
    "CVE-2024-49122": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49122",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49122",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49122",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/"
    },
    "CVE-2024-49118": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49118",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49118",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49118",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/"
    },
    "CVE-2024-49123": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49123",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49123",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49123",
        "Cisco Talos": "https://blog.talosintelligence.com/december-patch-tuesday-release/",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review"
    },
    "CVE-2024-49116": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49116",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49116",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49116",
        "Cisco Talos": "https://blog.talosintelligence.com/december-patch-tuesday-release/",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review"
    },
    "CVE-2024-49132": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49132",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49132",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49132",
        "Cisco Talos": "https://blog.talosintelligence.com/december-patch-tuesday-release/",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review"
    },
    "CVE-2024-49120": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49120",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49120",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49120",
        "Cisco Talos": "https://blog.talosintelligence.com/december-patch-tuesday-release/",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review"
    },
    "CVE-2024-49112": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49112",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49112",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49112",
        "Cisco Talos": "https://blog.talosintelligence.com/december-patch-tuesday-release/",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-december-2024/",
        "Integrity360": "https://insights.integrity360.com/16-critical-vulnerabilities-fixed-immediate-patching-recommended"
    },
    "CVE-2024-49119": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49119",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49119",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49119",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/"
    },
    "CVE-2024-49108": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49108",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49108",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49108",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/"
    },
    "CVE-2024-49128": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49128",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49128",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49128",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/"
    },
    "CVE-2024-49126": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49126",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49126",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49126",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/"
    },
    "CVE-2024-49106": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49106",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49106",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49106",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/"
    },
    "CVE-2024-49115": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49115",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49115",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49115",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/"
    },
    "CVE-2024-49117": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49117",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49117",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49117",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/"
    },
    "CVE-2024-49114": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49114",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49114",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49114"
    },
    "CVE-2024-49088": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49088",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49088",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49088"
    },
    "CVE-2024-49090": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49090",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49090",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49090"
    },
    "CVE-2024-49093": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49093",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49093",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49093"
    },
    "CVE-2024-49070": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49070",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49070"
    },
    "CVE-2024-43451": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43451",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43451",
        "Tenable": "https://www.tenable.com/blog/microsofts-november-2024-patch-tuesday-addresses-87-cves-cve-2024-43451-cve-2024-49039",
        "Help Net Security": "https://www.helpnetsecurity.com/2024/11/12/cve-2024-43451-cve-2024-49039/",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/11/12/the-november-2024-security-update-review"
    },
    "CVE-2024-49019": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49019",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/11/12/the-november-2024-security-update-review"
    },
    "CVE-2024-49039": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49039",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49039",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49039",
        "Tenable": "https://www.tenable.com/blog/microsofts-november-2024-patch-tuesday-addresses-87-cves-cve-2024-43451-cve-2024-49039",
        "Help Net Security": "https://www.helpnetsecurity.com/2024/11/12/cve-2024-43451-cve-2024-49039/",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/11/12/the-november-2024-security-update-review"
    },
    "CVE-2024-49040": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49040",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49040",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49040"
    },
    "CVE-2024-49138": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49138",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49138",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49138",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review",
        "Tenable": "https://www.tenable.com/blog/microsofts-december-2024-patch-tuesday-addresses-70-cves-cve-2024-49138",
        "Balbix": "https://www.balbix.com/blog/patch-tuesday-update-december-2024/",
        "Cisco Talos": "https://blog.talosintelligence.com/december-patch-tuesday-release/"
    },
    "CVE-2024-49105": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49105",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49105",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49105"
    },
    "CVE-2024-49127": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49127",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49127",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49127",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review"
    },
    "CVE-2024-49107": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49107",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49107",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49107",
        "Zero Day Initiative": "https://www.thezdi.com/blog/2024/12/10/the-december-2024-security-update-review"
    },
    "CVE-2024-49109": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49109",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49109",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49109"
    },
    "CVE-2024-49110": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49110",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-49110",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49110"
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

