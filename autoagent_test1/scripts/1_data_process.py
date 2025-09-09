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

