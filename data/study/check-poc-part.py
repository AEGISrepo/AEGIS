# -*- coding: utf-8 -*-

import os
import json
import multiprocessing
from functools import partial
from collections import defaultdict
import random

CVE_ROOT_DIR = './'

TEXT_FILE_EXTENSIONS = {
    '.txt', '.md', '.log', '.rtf', '.csv', '.tsv',
    '.json', '.xml', '.yaml', '.yml', '.ini', '.conf', '.cfg', '.toml',
    '.py', '.c', '.h', '.cpp', '.hpp', '.java', '.js', '.ts', '.go', '.rb',
    '.php', '.cs', '.sh', '.bat', '.ps1',
}


def read_cve_ids(file_path):
    if not os.path.exists(file_path):
        print(f"Error: CVE file '{file_path}' does not exist.")
        return []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            cve_ids = [line.strip() for line in f if line.strip()
                       and not line.startswith('#') and line.strip().startswith("CVE-")]
        return cve_ids
    except Exception as e:
        print(f"Error reading CVE file: {e}")
        return []


def load_cve_details(cve_list, cve_dir):
    print("[*] Preloading detailed information (references and descriptions) for all CVEs...")
    cve_details_map = {}

    cves_by_year = defaultdict(list)
    for cve_id in cve_list:
        try:
            year = cve_id.split('-')[1]
            cves_by_year[year].append(cve_id)
        except IndexError:
            print(f"Warning: Invalid CVE ID format '{cve_id}', skipped.")
            continue

    for year, cves_in_year in cves_by_year.items():
        json_file_path = os.path.join(cve_dir, f'nvdcve-2.0-{year}.json')
        if not os.path.exists(json_file_path):
            print(
                f"Warning: JSON file for year {year} not found: '{json_file_path}'")
            continue

        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            target_cves_set = set(cves_in_year)
            for cve_item in data.get('vulnerabilities', []):
                cve_details = cve_item.get('cve', {})
                current_cve_id = cve_details.get('id')

                if current_cve_id in target_cves_set:
                    references = cve_details.get('references', [])
                    urls = [ref.get('url', '')
                            for ref in references if ref.get('url')]

                    descriptions_list = cve_details.get('descriptions', [])
                    descriptions = [
                        desc.get('value', '') for desc in descriptions_list if desc.get('value')]

                    cve_details_map[current_cve_id] = {
                        'references': urls,
                        'descriptions': descriptions
                    }

                    target_cves_set.remove(current_cve_id)

        except (json.JSONDecodeError, KeyError) as e:
            print(f"Warning: Error processing file '{json_file_path}': {e}")

    print(
        f"[+] Preloading completed, loaded data for {len(cve_details_map)} CVEs.")
    return cve_details_map


def search_worker(cve_id, search_dir):
    search_term = cve_id.replace('CVE-', '')
    found_locations = []

    if not os.path.isdir(search_dir):
        return (cve_id, [])

    for root, dirs, files in os.walk(search_dir):
        if search_term in root:
            found_locations.append(f"Directory name: {root}")

        for file_name in files:
            if search_term in file_name:
                location = os.path.join(root, file_name)
                found_locations.append(f"File name: {location}")

            _, file_ext = os.path.splitext(file_name)
            if file_ext.lower() in TEXT_FILE_EXTENSIONS:
                file_path = os.path.join(root, file_name)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            if search_term in line:
                                found_locations.append(
                                    f"File content: {file_path}")
                                break
                except (IOError, OSError):
                    pass

    return (cve_id, sorted(list(set(found_locations))))


def main():
    cve_file = 'pet_cve_list.txt'
    # cve_file = 'rq1-no-poc.txt'
    pocs_dir = './pocs'

    if not os.path.isdir(pocs_dir):
        print(f"Error: Pocs directory '{pocs_dir}' does not exist. Exiting.")
        return

    print(f"[*] Reading CVE IDs")
    cve_list = read_cve_ids(cve_file)
    if not cve_list:
        print("[!] No valid CVE IDs found, exiting.")
        return
    print(f"[*] Read {len(cve_list)} CVE IDs.")

    print(f"[*] Sampling {len(cve_list)} CVE IDs.")

    cve_details = load_cve_details(cve_list, CVE_ROOT_DIR)
    print("-" * 60)

    num_processes = os.cpu_count() or 4
    print(f"[*] Using {num_processes} processes to search in '{pocs_dir}'...")
    print("[*] Note: File content search is limited to text files (e.g., .py, .txt, .json).")

    with multiprocessing.Pool(processes=num_processes) as pool:
        worker_func = partial(search_worker, search_dir=pocs_dir)
        results = pool.map(worker_func, cve_list)

    print("\n[*] All search tasks completed, consolidating and performing secondary checks...")
    print("-" * 60)

    found_count = 0
    not_found_count = 0

    for cve_id, locations in results:
        search_term = cve_id.replace('CVE-', '')
        print(f"  -> Result for {cve_id} (keyword: {search_term})")

        if locations:
            print(f"  [+] Found! (File system)")
            for loc in locations:
                print(f"    - {loc}")
            found_count += 1
        else:
            found_reason = None
            found_details = ""

            details_for_cve = cve_details.get(
                cve_id, {'references': [], 'descriptions': []})

            for url in details_for_cve.get('references', []):
                if 'syzkaller' in url.lower():
                    found_reason = "Syzkaller reference"
                    found_details = f"Found syzkaller dashboard in NVD reference link: {url}"
                    break

            if not found_reason:
                for desc in details_for_cve.get('descriptions', []):
                    desc_lower = desc.lower()
                    keywords = ["syzkaller", "kasan", "syzbot", "sanitizer"]
                    if any(keyword in desc_lower for keyword in keywords):
                        found_reason = "Keywords in description"
                        found_details = "Found keywords in NVD description"
                        break

            if found_reason:
                print(f"  [+] Found! ({found_reason})")
                print(f"    - {found_details}")
                found_count += 1
            else:
                print(f"  [-] Not found")
                not_found_count += 1
        print("-" * 60)

    print("\n[✔] Final Summary!")
    total_checked = found_count + not_found_count
    print(f"Total checked: {total_checked} CVE IDs")
    print(
        f"Total found with PoC: {found_count}: {found_count / total_checked:.2%}")
    print(f"Total not found with PoC: {not_found_count}")

    # with open("cve_sample.txt", "w") as f:
    #     for cve_id in cve_list:
    #         f.write(cve_id + "\n")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
