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
DATA_PATH = "/home/st335/CTIAgent/autoagent_final/data/vulnerability_data_W1.json"


# 建立資料夾
os.makedirs("data", exist_ok=True)

# Define URLs
urls={
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
    # Windows Server 2022
    # ---------------------------------------------------------------------------------------------
    "CVE-2017-5715": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5715",
        "Microsoft": "https://support.microsoft.com/zh-hk/topic/kb4072698-windows-server-%E5%92%8C-azure-stack-hci-%E4%BF%9D%E8%AD%B7%E6%99%B6%E7%89%87%E5%9E%8B%E5%BE%AE%E7%B5%90%E6%A7%8B%E5%92%8C%E6%8E%A8%E6%B8%AC%E6%80%A7%E5%9F%B7%E8%A1%8C%E5%81%B4%E9%82%8A%E9%80%9A%E9%81%93%E5%BC%B1%E9%BB%9E%E7%9A%84%E6%8C%87%E5%BC%95-2f965763-00e2-8f98-b632-0d96f30c8c8e",
        "Wikipedia": "https://zh.wikipedia.org/wiki/%E5%B9%BD%E7%81%B5%E6%BC%8F%E6%B4%9E"
    },
    "CVE-2017-5753": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5753",
        "Microsoft": "https://support.microsoft.com/zh-hk/topic/kb4072698-windows-server-%E5%92%8C-azure-stack-hci-%E4%BF%9D%E8%AD%B7%E6%99%B6%E7%89%87%E5%9E%8B%E5%BE%AE%E7%B5%90%E6%A7%8B%E5%92%8C%E6%8E%A8%E6%B8%AC%E6%80%A7%E5%9F%B7%E8%A1%8C%E5%81%B4%E9%82%8A%E9%80%9A%E9%81%93%E5%BC%B1%E9%BB%9E%E7%9A%84%E6%8C%87%E5%BC%95-2f965763-00e2-8f98-b632-0d96f30c8c8e",
        "Wikipedia": "https://zh.wikipedia.org/wiki/%E5%B9%BD%E7%81%B5%E6%BC%8F%E6%B4%9E"
    },
    "CVE-2017-5754": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5754",
        "Microsoft": "https://support.microsoft.com/zh-hk/topic/kb4072698-windows-server-%E5%92%8C-azure-stack-hci-%E4%BF%9D%E8%AD%B7%E6%99%B6%E7%89%87%E5%9E%8B%E5%BE%AE%E7%B5%90%E6%A7%8B%E5%92%8C%E6%8E%A8%E6%B8%AC%E6%80%A7%E5%9F%B7%E8%A1%8C%E5%81%B4%E9%82%8A%E9%80%9A%E9%81%93%E5%BC%B1%E9%BB%9E%E7%9A%84%E6%8C%87%E5%BC%95-2f965763-00e2-8f98-b632-0d96f30c8c8e",
        "Wikipedia": "https://zh.wikipedia.org/wiki/%E7%86%94%E6%AF%81_%28%E5%AE%89%E5%85%A8%E6%BC%8F%E6%B4%9E%29"
    },
    "CVE-2018-3639": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3639",
        "Microsoft": "https://support.microsoft.com/zh-hk/topic/kb4072698-windows-server-%E5%92%8C-azure-stack-hci-%E4%BF%9D%E8%AD%B7%E6%99%B6%E7%89%87%E5%9E%8B%E5%BE%AE%E7%B5%90%E6%A7%8B%E5%92%8C%E6%8E%A8%E6%B8%AC%E6%80%A7%E5%9F%B7%E8%A1%8C%E5%81%B4%E9%82%8A%E9%80%9A%E9%81%93%E5%BC%B1%E9%BB%9E%E7%9A%84%E6%8C%87%E5%BC%95-2f965763-00e2-8f98-b632-0d96f30c8c8e"
    },
    "CVE-2018-3620": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3620",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-3620"
    },
    "CVE-2018-12126": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12126",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-12126",
        "Intel": "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00233.html",
        "Red Hat": "https://access.redhat.com/security/vulnerabilities/mds",
        "Oracle": "https://blogs.oracle.com/security/post/intel-processor-mds-vulnerabilities-cve-2019-11091-cve-2018-12126-cve-2018-12130-and-cve-2018-12127"
    },
    "CVE-2018-12127": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12127",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-12127",
        "Intel": "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00233.html",
        "Red Hat": "https://access.redhat.com/security/vulnerabilities/mds",
        "Oracle": "https://blogs.oracle.com/security/post/intel-processor-mds-vulnerabilities-cve-2019-11091-cve-2018-12126-cve-2018-12130-and-cve-2018-12127"
    },
    "CVE-2018-12130": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12130",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2018-12130",
        "Intel": "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00233.html",
        "Red Hat": "https://access.redhat.com/security/vulnerabilities/mds",
        "Oracle": "https://blogs.oracle.com/security/post/intel-processor-mds-vulnerabilities-cve-2019-11091-cve-2018-12126-cve-2018-12130-and-cve-2018-12127"
    },
    "CVE-2019-1125": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1125",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-1125",
        "Microsoft": "https://support.microsoft.com/en-us/topic/kb4073119-windows-client-guidance-for-it-pros-to-protect-against-silicon-based-microarchitectural-and-speculative-execution-side-channel-vulnerabilities-35820a8a-ae13-1299-88cc-357f104f5b11"
    },
    "CVE-2019-11091": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11091",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2019-11091",
        "Intel": "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00233.html",
        "Red Hat": "https://access.redhat.com/security/vulnerabilities/mds",
        "Oracle": "https://blogs.oracle.com/security/post/intel-processor-mds-vulnerabilities-cve-2019-11091-cve-2018-12126-cve-2018-12130-and-cve-2018-12127"
    },
    "CVE-2020-0601": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0601",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-0601",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0601",
        "CISA": "https://www.cisa.gov/uscert/ncas/alerts/aa20-014a"
    },
    "CVE-2020-0796": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0796",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-0796",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796",
        "CISA": "https://www.cisa.gov/uscert/ncas/alerts/aa20-126a"
    },
    "CVE-2021-1675": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1675",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-1675",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675"
    },
    "CVE-2021-34527": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34527",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"
    },
    "CVE-2021-26855": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26855",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-26855",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855",
        "CISA": "https://www.cisa.gov/uscert/ncas/alerts/aa21-062a"
    },
    "CVE-2021-34473": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34473",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34473",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473",
        "Fortinet": "https://www.fortinet.com/blog/threat-research/microsoft-exchange-zero-day-vulnerability-updates",
        "Kaspersky": "https://securelist.com/cve-2022-41040-and-cve-2022-41082-zero-days-in-ms-exchange/108364/"
    },
    "CVE-2021-34523": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34523",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-34523",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34523",
        "Fortinet": "https://www.fortinet.com/blog/threat-research/microsoft-exchange-zero-day-vulnerability-updates",
        "Kaspersky": "https://securelist.com/cve-2022-41040-and-cve-2022-41082-zero-days-in-ms-exchange/108364/"
    },
    "CVE-2021-31207": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31207",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-31207",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31207",
        "Fortinet": "https://www.fortinet.com/blog/threat-research/microsoft-exchange-zero-day-vulnerability-updates",
        "Kaspersky": "https://securelist.com/cve-2022-41040-and-cve-2022-41082-zero-days-in-ms-exchange/108364/"
    },
    "CVE-2022-21907": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21907",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-21907",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21907"
    },
    "CVE-2022-26809": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-26809",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-26809",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26809"
    },
    "CVE-2022-26925": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-26925",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-26925",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26925",
        "CISA": "https://www.cisa.gov/news-events/alerts/2022/05/13/cisa-temporarily-removes-cve-2022-26925-known-exploited-vulnerability"
    },
    "CVE-2022-30190": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30190",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30190",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190"
    },
    "CVE-2022-22005": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22005",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22005",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22005"
    },
    "CVE-2022-34713": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-34713",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-34713",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-34713"
    },
    "CVE-2022-41040": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-41040",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-41040",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41040",
        "Microsoft Security Blog": "https://www.microsoft.com/en-us/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/",
        "Kaspersky": "https://securelist.com/cve-2022-41040-and-cve-2022-41082-zero-days-in-ms-exchange/108364/"
    },
    "CVE-2022-41082": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-41082",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-41082",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41082",
        "Microsoft Security Blog": "https://www.microsoft.com/en-us/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/",
        "Kaspersky": "https://securelist.com/cve-2022-41040-and-cve-2022-41082-zero-days-in-ms-exchange/108364/"
    },
    "CVE-2023-23397": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23397",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-23397",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397",
        "Microsoft Security Blog": "https://www.microsoft.com/en-us/security/blog/2023/03/24/guidance-for-investigating-attacks-using-cve-2023-23397/"
    },
    "CVE-2023-28252": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28252",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-28252",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28252"
    },
    "CVE-2023-21554": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-21554",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-21554",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21554",
        "CrowdStrike Blog": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-april-2023/"
    },
    "CVE-2023-24932": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-24932",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-24932",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24932",
        "Microsoft Support": "https://support.microsoft.com/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d"
    },
    "CVE-2022-30216": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30216",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-30216"
    },
    "CVE-2022-38028": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-38028",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-38028",
        "Wikipedia": "https://en.wikipedia.org/wiki/GooseEgg"
    },
    "CVE-2024-21338": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21338",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-21338",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21338",
        "GitHub": "https://github.com/hakaioffsec/CVE-2024-21338",
        "Crowdfense": "https://www.crowdfense.com/windows-applocker-driver-lpe-vulnerability-cve-2024-21338/",
        "Twingate": "https://www.twingate.com/blog/tips/cve-2024-21338"
    },
    "CVE-2024-38063": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38063",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38063",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38063",
        "Strobes Security Blog": "https://strobes.co/blog/cve-2024-38063-an-in-depth-look-at-the-critical-remote-code-execution-vulnerability/",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-august-2024/"
    },
    "CVE-2024-21302": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21302",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-21302",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21302",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-august-2024/"
    },
    "CVE-2024-38202": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38202",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-38202",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38202",
        "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-august-2024/"
    },
    "CVE-2022-26134": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-26134",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-26134",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-215a"
    },
    "CVE-2021-44228": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "Apache": "https://logging.apache.org/log4j/2.x/security.html",
        "Wikipedia": "https://zh.wikipedia.org/wiki/Log4Shell",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-215a"
    },
    "CVE-2022-1388": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1388",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-1388",
        "F5": "https://support.f5.com/csp/article/K23605346",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-215a"
    },
    "CVE-2022-22954": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22954",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22954",
        "VMware": "https://www.vmware.com/security/advisories/VMSA-2022-0011.html",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-215a",
        "SOC Prime": "https://socprime.com/blog/cve-2022-22960-and-cve-2022-22954-detection-cisa-warns-of-exploitation-attempts-of-unpatched-vmware-vulnerabilities/"
    },
    "CVE-2022-22960": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22960",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22960",
        "VMware": "https://www.vmware.com/security/advisories/VMSA-2022-0011.html",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-215a",
        "SOC Prime": "https://socprime.com/blog/cve-2022-22960-and-cve-2022-22954-detection-cisa-warns-of-exploitation-attempts-of-unpatched-vmware-vulnerabilities/"
    },
    "CVE-2021-26084": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26084",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-26084",
        "GitHub": "https://github.com/TesterCC/exp_poc_library/blob/master/exp_poc/CVE-2021-26084_Confluence_OGNL_injection/CVE-2021-26084.md"
    },
    "CVE-2022-38025": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-38025",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-38025",
        "DEVCORE": "https://devco.re/research/cve/"
    },
    "CVE-2022-38043": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-38043",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-38043",
        "DEVCORE": "https://devco.re/research/cve/"
    },
    "CVE-2022-34719": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-34719",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-34719",
        "DEVCORE": "https://devco.re/research/cve/"
    },
    "CVE-2023-1192": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1192",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-1192",
        "DEVCORE": "https://devco.re/research/cve/"
    },
    "CVE-2023-1193": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1193",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-1193",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2023-1193",
        "Tenable": "https://www.tenable.com/plugins/nessus/225899"
    },
    "CVE-2023-1194": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1194",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-1194",
        "Ubuntu": "https://ubuntu.com/security/CVE-2023-1194"
    },
    "CVE-2023-1195": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1195",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-1195"
    },
    "CVE-2023-32154": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32154",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-32154",
        "CVE.org": "https://www.cve.org/CVERecord?id=CVE-2023-32154"
    },
    "CVE-2022-21974": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21974",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-21974",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21974"
    },
    "CVE-2022-21996": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21996",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-21996",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21996"
    },
    "CVE-2022-22047": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22047",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22047",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22047"
    },
    "CVE-2022-22049": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22049",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22049",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22049"
    },
    "CVE-2022-22057": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22057",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22057",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2022-22057",
        "GitHub Discussion": "https://github.com/github/securitylab/discussions/715",
        "GitHub Blog": "https://github.blog/security/vulnerability-research/the-android-kernel-mitigations-obstacle-race/"
    },
    "CVE-2022-22058": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22058",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22058",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2022-22058"
    },
    "CVE-2022-22059": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22059",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22059",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2022-22059"
    },
    "CVE-2022-22060": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22060",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22060",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2022-22060"
    },
    "CVE-2022-22061": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22061",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22061"
    },
    "CVE-2022-22062": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22062",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22062",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22062"
    },
    "CVE-2022-22063": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22063",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22063",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22063",
        "GitHub": "https://github.com/msm8916-mainline/CVE-2022-22063"
    },
    "CVE-2022-22064": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22064",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22064",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22064"
    },
    "CVE-2022-22065": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22065",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22065"
    },
    "CVE-2022-22066": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22066",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22066",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22066"
    },
    "CVE-2022-22067": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22067",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22067",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22067"
    },
    "CVE-2022-22068": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22068",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22068",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22068"
    },
    "CVE-2022-22069": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22069",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22069",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22069"
    },
    "CVE-2022-22070": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22070",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22070",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22070"
    },
    "CVE-2022-22071": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22071",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22071"
    },
    "CVE-2022-22072": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22072",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22072",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22072"
    },
    "CVE-2022-22073": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22073",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22073",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22073"
    },
    "CVE-2022-22074": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22074",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22074",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22074"
    },
    "CVE-2022-22075": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22075",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22075",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22075"
    },
    "CVE-2022-22076": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22076",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22076"
    },
    "CVE-2022-22077": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22077",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22077",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22077"
    },
    "CVE-2022-22078": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22078",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22078",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22078"
    },
    "CVE-2022-22079": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22079",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22079",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22079"
    },
    "CVE-2022-22080": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22080",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22080",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22080"
    },
    "CVE-2022-22081": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22081",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-22081",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22081"
    },
    "CVE-2023-29336": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-29336",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-29336",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29336"
    },
    "CVE-2023-28206": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28206",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-28206",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28206"
    },
    "CVE-2023-29360": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-29360",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-29360",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29360"
    },
    "CVE-2023-23415": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23415",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-23415",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23415"
    },
    "CVE-2023-21715": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-21715",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-21715",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21715"
    },
    "CVE-2023-21674": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-21674",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-21674",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21674"
    },
    "CVE-2022-41099": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-41099",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2022-41099",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41099"
    },
    "CVE-2023-35352": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35352",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-35352",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35352"
    },
    "CVE-2023-24941": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-24941",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-24941",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24941"
    },
    "CVE-2023-24880": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-24880",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-24880",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24880"
    },
    "CVE-2023-28231": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28231",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-28231",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28231",
        "ZDI Blog": "https://www.thezdi.com/blog/2023/5/1/cve-2023-28231-rce-in-the-microsoft-windows-dhcpv6-service"
    },
    "CVE-2023-21716": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-21716",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-21716",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21716",
        "Picus Security": "https://www.picussecurity.com/resource/blog/cve-2023-21716-microsoft-word-remote-code-execution-exploit-explained"
    },
    "CVE-2023-31204": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-31204",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-31204",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-31204"
    },
    "CVE-2023-28302": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28302",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-28302",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28302"
    },
    "CVE-2023-28287": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28287",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-28287",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28287"
    },
    "CVE-2023-35384": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35384",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-35384",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35384"
    },
    "CVE-2023-24881": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-24881",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-24881",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24881"
    },
    "CVE-2023-23416": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23416",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-23416",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23416",
        "Field Effect": "https://fieldeffect.com/blog/cve-analysis-red-october-one-ping-too-many"
    },
    "CVE-2023-28230": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28230",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-28230",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28230"
    },
    "CVE-2023-24882": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-24882",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-24882",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24882"
    },
    "CVE-2023-23925": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23925",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-23925",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23925"
    },
    "CVE-2023-28204": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28204",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-28204",
        "Red Hat": "https://access.redhat.com/security/cve/cve-2023-28204"
    },
    "CVE-2023-35385": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35385",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-35385",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35385"
    },
    "CVE-2023-35395": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35395",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-35395",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35395"
    },
    "CVE-2023-23392": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23392",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-23392",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23392"
    },
    "CVE-2023-21718": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-21718",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-21718",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21718"
    },
    "CVE-2023-28232": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28232",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-28232",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28232"
    },
    "CVE-2023-35339": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35339",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-35339",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35339"
    },
    "CVE-2023-21541": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-21541",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-21541",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21541"
    },
    "CVE-2023-29332": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-29332",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-29332",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29332",
        "GitHub": "https://github.com/Azure/AKS/issues/3904"
    },
    "CVE-2023-23599": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23599",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-23599",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23599"
    },
    "CVE-2023-35581": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35581",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-35581",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35581"
    },
    "CVE-2023-21683": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-21683",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-21683",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21683"
    },
    "CVE-2023-21685": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-21685",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-21685",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21685"
    },
    "CVE-2023-23419": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23419",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2023-23419",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23419"
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