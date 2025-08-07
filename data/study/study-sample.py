import os
import json
from pathlib import Path
import sys
from collections import defaultdict
import re
import random

CVE_ROOT_DIR = './'

TARGET_KEYWORDS = [
    'linux kernel',
    'linux_kernel',
    'glibc', 'systemd', 'bash',
    'openssl', 'openssh', 'grub', 'binutils', 'coreutils', 'gcc',
    'gnutls', 'sudo', 'PolicyKit', 'Polkit',
]

PET_SPECIAL_CWE_CATEGORIES = {
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-787": "Out-of-Bounds Write",
    "CWE-126": "Buffer Over-read",
    "CWE-129": "Improper Validation of Array Index",
    "CWE-131": "Incorrect Calculation of Buffer Size",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-191": "Integer Underflow (Wrap or Wraparound)",
    "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-457": "Use of Uninitialized Variable",
    "CWE-823": "Use of Out-of-range Pointer Offset",
    "CWE-908": "Use of Uninitialized Resource",
}


def search_keywords_in_cve(cve_item, keywords):
    lower_keywords = [k.lower() for k in keywords]
    searchable_text = []
    try:
        cve_details = cve_item.get('cve', {})
        if not cve_details:
            return False
        for desc in cve_details.get('descriptions', []):
            if 'value' in desc:
                searchable_text.append(desc['value'].lower())
        for config in cve_details.get('configurations', []):
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    if 'criteria' in cpe_match:
                        searchable_text.append(cpe_match['criteria'].lower())
        full_text_to_search = ' '.join(searchable_text)
        for keyword in lower_keywords:
            if keyword in full_text_to_search:
                return True
    except (KeyError, TypeError) as e:
        cve_id = cve_item.get('cve', {}).get('id', 'Unknown CVE_ID')
        print(f"Warning: Error parsing CVE ({cve_id}): {e}", file=sys.stderr)
    return False


def extract_cwe(cve_item):
    cwe_ids = set()
    try:
        cve_details = cve_item.get('cve', {})
        if not cve_details:
            return []
        for weakness in cve_details.get('weaknesses', []):
            for desc in weakness.get('description', []):
                if 'value' in desc and desc['value'].strip().upper().startswith('CWE-'):
                    cwe_ids.add(desc['value'].strip())
    except (KeyError, TypeError) as e:
        cve_id = cve_item.get('cve', {}).get('id', 'Unknown CVE_ID')
        print(
            f"Warning: Error extracting CWE ({cve_id}): {e}", file=sys.stderr)
    return list(cwe_ids)


def main():
    cve_dir = Path(CVE_ROOT_DIR)
    if not cve_dir.is_dir():
        print(
            f"Error: Directory '{CVE_ROOT_DIR}' does not exist or is not a directory.", file=sys.stderr)
        sys.exit(1)
    print(
        f"Starting to scan NVD vulnerability files in '{cve_dir}' (>= {2017})...")
    print(f"Using keywords: {', '.join(TARGET_KEYWORDS)}\n")

    cwe_classification = defaultdict(list)
    found_cve_count = 0
    total_cves_processed = 0

    json_files = list(cve_dir.glob('nvdcve-2.0-*.json'))
    if not json_files:
        print("Error: No 'nvdcve-2.0-*.json' files found in the specified directory.")
        return

    print(
        f"Found {len(json_files)} annual JSON files, starting filtering and parsing...")

    for json_file in sorted(json_files):
        year_match = re.search(r'(\d{4})\.json$', json_file.name)
        if not year_match:
            print(
                f"Warning: Unable to parse year from filename '{json_file.name}', skipped.", file=sys.stderr)
            continue
        year = int(year_match.group(1))
        if year < 2017:
            continue

        print(f"\n--- Processing file: {json_file.name} ---")
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                print(
                    f"Warning: No 'vulnerabilities' list found or empty in '{json_file.name}'.")
                continue

            total_cves_processed += len(vulnerabilities)

            for cve_item in vulnerabilities:
                if search_keywords_in_cve(cve_item, TARGET_KEYWORDS):
                    cve_details = cve_item.get('cve', {})
                    cve_id = cve_details.get('id', 'Unknown CVE_ID')
                    cwe_list = extract_cwe(cve_item)
                    if cwe_list:
                        found_cve_count += 1
                        for cwe in cwe_list:
                            cwe_classification[cwe].append(cve_id)
        except json.JSONDecodeError:
            print(
                f"Warning: File '{json_file}' is not valid JSON, skipped.", file=sys.stderr)
        except Exception as e:
            print(
                f"Unknown error processing file '{json_file}': {e}", file=sys.stderr)

    print(f"\nScan completed! Processed {total_cves_processed} CVE entries.")
    print(
        f"Found {found_cve_count} relevant vulnerabilities that match keywords and have CWE information.")

    if not cwe_classification:
        print("No matching vulnerabilities found, analysis cannot proceed.")
        return

    cwe_counts = {cwe: len(cves) for cwe, cves in cwe_classification.items()}
    total_vulnerabilities_with_cwe = found_cve_count

    print("\n========================================")
    print("      CWE Vulnerability Count (Descending)")
    print("========================================")
    sorted_cwes = sorted(cwe_counts.items(),
                         key=lambda item: item[1], reverse=True)
    for cwe_id, count in sorted_cwes:
        print(f"{cwe_id}: {count} vulnerabilities")

    print("\n========================================")
    print("             Overall Statistics")
    print("========================================")
    print(
        f"Total vulnerabilities with CWE information: {total_vulnerabilities_with_cwe}")
    all_special_cwes = set(PET_SPECIAL_CWE_CATEGORIES.keys())
    unique_covered_cves = set()
    for cwe_id in all_special_cwes:
        if cwe_id in cwe_classification:
            unique_covered_cves.update(cwe_classification[cwe_id])
    covered_vulnerabilities = len(unique_covered_cves)
    if total_vulnerabilities_with_cwe > 0:
        coverage_percentage = (covered_vulnerabilities /
                               total_vulnerabilities_with_cwe) * 100
        print(
            f"The specified {len(all_special_cwes)} special CWE types cover: {covered_vulnerabilities} vulnerabilities ({coverage_percentage:.2f}%)")
    else:
        print(
            f"The specified {len(all_special_cwes)} special CWE types cover: 0 vulnerabilities")

    print("\n========================================")
    print("      Special CWE Coverage Details")
    print("========================================")
    sorted_special_list = sorted(
        PET_SPECIAL_CWE_CATEGORIES.items(),
        key=lambda item: int(item[0].split('-')[1])
    )
    for cwe_id, description in sorted_special_list:
        if cwe_id in cwe_counts:
            count = cwe_counts[cwe_id]
            print(
                f"{cwe_id}: {description.split(' (')[0]}  <-- ★★★ (found {count} vulnerabilities)")
        else:
            print(f"{cwe_id}: {description.split(' (')[0]}")

    print("\n========================================")
    print("      CWE -> CVE Detailed List (by count)")
    print("========================================")
    sorted_detailed_list = sorted(
        cwe_classification.items(),
        key=lambda item: len(item[1]),
        reverse=True
    )
    for cwe, cve_list in sorted_detailed_list:
        sorted_cves = sorted(cve_list)
        print(f"CWE: {cwe} (Total {len(sorted_cves)} vulnerabilities)")
        print(f"  Affected CVEs: {', '.join(sorted_cves)}")
        print("-" * 30)

    print("\n======================================================================")
    print(
        f"★★★ Final Report: List of all CVE IDs belonging to {len(PET_SPECIAL_CWE_CATEGORIES)} special CWE types ★★★")
    print("======================================================================")
    final_cve_list = sorted(list(unique_covered_cves))
    if final_cve_list:
        print(f"Found {len(final_cve_list)} unique CVE IDs. List:\n")
        print(', '.join(final_cve_list))
    else:
        print("No related CVEs found in the specified special CWE categories.")

    print("\n======================================================================")
    print("      ★★★ Random Sampling 10% and Output to File ★★★")
    print("======================================================================")
    if final_cve_list:
        sample_size = int(len(final_cve_list) * 0.1)
        if sample_size == 0 and len(final_cve_list) > 0:
            sample_size = 1
        sampled_cves = random.sample(list(set(final_cve_list)), sample_size)
        output_filename = "pet_cve_list.txt"
        try:
            with open(output_filename, 'w', encoding='utf-8') as f:
                for cve_id in sorted(sampled_cves):
                    f.write(f"{cve_id}\n")
            print(
                f"Successfully sampled {len(sampled_cves)} from {len(final_cve_list)} matching CVEs.")
            print(f"Results saved to file: {output_filename}")
        except IOError as e:
            print(
                f"Error: Cannot write to file {output_filename}: {e}", file=sys.stderr)
    else:
        print("No CVEs available for sampling.")


if __name__ == '__main__':
    main()
