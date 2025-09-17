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

