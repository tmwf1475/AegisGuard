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
DATA_PATH = "/home/st335/CTIAgent/autoagent_final/data/vulnerability_data_W2.json"

# 建立資料夾
os.makedirs("data", exist_ok=True)

# Define URLs
urls={
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
    },
    "CVE-2020-0796": {
        "CVE": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0796",
        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2020-0796",
        "Wikipedia": "https://en.wikipedia.org/wiki/SMBGhost"
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