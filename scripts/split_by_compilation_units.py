import argparse
import os
import logging
import re
from datetime import datetime
from typing import List, Dict


class CUSpliter:
    def __init__(self, delimiter: str = "DW_TAG_compile_unit", min_unit_length: int = 1):
        self.delimiter = delimiter
        self.min_unit_length = min_unit_length
        self.compile_units: List[List[str]] = []
        self.total_lines: int = 0
        self.total_units: int = 0

    def _read_file(self, file_path: str) -> List[str]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Input file '{file_path}' not found.")
        with open(file_path, 'r', encoding="utf-8") as infile:
            lines = infile.readlines()
        self.total_lines = len(lines)
        return lines

    def _validate_unit(self, unit: List[str]) -> bool:
        return len(unit) >= self.min_unit_length

    def _split_lines(self, lines: List[str]) -> List[List[str]]:
        units = []
        current_unit: List[str] = []
        for line in lines:
            if self.delimiter in line:
                if current_unit and self._validate_unit(current_unit):
                    units.append(current_unit)
                    current_unit = []
            current_unit.append(line)
        if current_unit and self._validate_unit(current_unit):
            units.append(current_unit)
        self.total_units = len(units)
        return units

    def _write_unit_to_file(self, unit: List[str], output_dir: str, index: int) -> None:
        file_name = f"compile_unit_{index:03d}.txt"
        output_path = os.path.join(output_dir, file_name)
        try:
            with open(output_path, 'w', encoding="utf-8") as outfile:
                outfile.writelines(unit)
        except Exception as e:
            logging.error(
                f"Failed to write compile unit {index} to '{output_path}': {e}")
            raise

    def _create_output_dir(self, output_dir: str) -> None:
        os.makedirs(output_dir, exist_ok=True)

    def process(self, input_file: str, output_dir: str) -> Dict[str, int]:
        lines = self._read_file(input_file)
        self.compile_units = self._split_lines(lines)
        self._create_output_dir(output_dir)
        for idx, unit in enumerate(self.compile_units, start=1):
            self._write_unit_to_file(unit, output_dir, idx)
        return {"total_units": self.total_units, "total_lines": self.total_lines}


def generate_report(stats: Dict[str, int], output_dir: str) -> None:
    report_lines = []
    report_lines.append(
        f"Compilation Units Splitting Report - {datetime.now().isoformat()}\n")
    report_lines.append(f"Output Directory: {output_dir}\n")
    report_lines.append(
        f"Total Lines Processed: {stats.get('total_lines', 0)}\n")
    report_lines.append(
        f"Total Compile Units Created: {stats.get('total_units', 0)}\n")
    report_content = "".join(report_lines)
    report_file = os.path.join(output_dir, "split_report.txt")
    try:
        with open(report_file, "w", encoding="utf-8") as report:
            report.write(report_content)
    except Exception as e:
        logging.error(f"Error writing report to '{report_file}': {e}")
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Split a large DWARF debug file into smaller files based on DW_TAG_compile_unit occurrences."
    )
    parser.add_argument("input_file", type=str,
                        help="Path to the large DWARF debug file.")
    parser.add_argument("output_dir", type=str,
                        help="Directory to save the split compile units.")
    parser.add_argument("--delimiter", type=str, default="DW_TAG_compile_unit",
                        help="Delimiter string used to split the file. Default is 'DW_TAG_compile_unit'.")
    parser.add_argument("--min_lines", type=int, default=1,
                        help="Minimum number of lines required for a compile unit to be considered valid.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s: %(message)s")
    logging.info("Starting splitting process.")
    splitter = CUSpliter(
        delimiter=args.delimiter, min_unit_length=args.min_lines)
    try:
        stats = splitter.process(args.input_file, args.output_dir)
        generate_report(stats, args.output_dir)
        logging.info(
            f"Successfully split file into {stats.get('total_units', 0)} compile units.")
        print(
            f"Split into {stats.get('total_units', 0)} compile units. Files saved in '{args.output_dir}'.")
    except Exception as error:
        logging.error(f"An error occurred during processing: {error}")


if __name__ == "__main__":
    main()
