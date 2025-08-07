import csv
import requests
import sys
import json
import re
from functools import lru_cache
import os
import concurrent.futures
from loguru import logger
from requests.auth import HTTPBasicAuth
from aegis_config import settings

SAVE_PATH = "./data/cve"
BASEURL = "https://www.opencve.io/"


if not BASEURL.endswith("/"):
    BASEURL += "/"


@lru_cache
def getCVERe():
    cvere = re.compile(r"CVE-(\d+)-(\d+)")
    return cvere


def getCVEJson(cve: str):
    # check cve is in format "CVE-xxx-xxx"
    if not cve:
        return None
    cve = cve.upper().strip()
    if not getCVERe().match(cve):
        return None
    url = f"{BASEURL}api/cve/{cve}"

    logger.info(f"{url}")

    if "opencve" in url:
        req = requests.get(url, auth=HTTPBasicAuth(
            settings['OPENCVE_USER'], settings['OPENCVE_PASSWORD']), timeout=10)
    else:
        req = requests.get(url)

    if req.ok:
        return json.loads(req.text)

    logger.debug(f"{url} failed {req}")
    return None


def saveCVE(cve: str):
    if not cve:
        return
    cve = cve.upper().strip()
    if not getCVERe().match(cve):
        return
    if os.path.exists(f"{SAVE_PATH}/{cve}.json"):
        logger.info(f"{cve} already exists")
        return
    json.dump(getCVEJson(cve), open(f"{SAVE_PATH}/{cve}.json", 'w'), indent=4)
    logger.info(f"{cve} saved")


def getCveList():
    # \[CVE-(\d+)-(\d+)\]
    cvere = re.compile(r"\[CVE-(\d+)-(\d+)\]")

    res = []
    with open("cvelist.txt", 'r') as f:
        for line in f:
            cve = cvere.search(line)
            if cve:
                res.append(f"CVE-{cve.group(1)}-{cve.group(2)}")
    return res


def runInParallel():
    cvelist = getCveList()
    # with concurrent.futures.ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
    #     futures = [executor.submit(saveCVE, cve)
    #                for cve in cvelist]
    #     for fu in concurrent.futures.as_completed(futures):
    #         pass
    for cve in cvelist:
        saveCVE(cve)


def processCVEs():
    cves = []
    with open("cves.csv") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve = row["ID"]
            # saveCVE(cve)
            json = getCVEJson(cve)
            # logger.debug(json)
            desc = json['summary']
            cvelink = f"{BASEURL}cve/{cve}"
            # ID,CVE Link,Description
            cves.append({"ID": cve, "CVE Link": cvelink, "Description": desc})

    fields = ['ID', 'CVE Link', 'Description', 'Patch',
              'Patch Link', 'POC', 'POC Link', 'Writeup', 'Writeup Link']
    with open("cvesw.csv", "w") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)

        # writing headers (field names)
        writer.writeheader()

        # writing data rows
        writer.writerows(cves)


if __name__ == "__main__":
    # runInParallel()
    processCVEs()
