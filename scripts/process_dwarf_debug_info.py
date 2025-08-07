import argparse
import logging
import os
import re
import pickle
from concurrent.futures import ProcessPoolExecutor, as_completed, ThreadPoolExecutor
from collections import defaultdict
from loguru import logger


class Location:
    def __init__(self):
        self.ranges = []  #

    def add_range(self, operation, start=None, end=None):
        """

        :param start: 
        :param end:  ( None, )
        :param operation: （ DW_OP_reg0 RAX  DW_OP_addr 0x4040）
        """
        if end is None:  # ,  global variable
            self.ranges.append({"operation": operation})
        else:  #
            self.ranges.append({
                "start": start,
                "end": end,
                "operation": operation
            })

    def __len__(self):
        return len(self.ranges)

    def __bool__(self):
        return len(self) > 0


class Variable:
    def __init__(self, name="", var_type="", location=None):
        self.name = name  #
        self.type = var_type  #
        self.location = location if location is not None else Location()  #

    def __bool__(self):
        return bool(self.location) and bool(self.name)


class Subprogram:
    def __init__(self):
        self.name = ""
        self.frame_base = ""
        self.low_pc = 0
        self.high_pc = 0
        self.variables: dict[str, list[Variable]] = defaultdict(
            list)  # {"name" : list[Variable]}

    def __bool__(self):
        return bool(self.frame_base) or bool(self.low_pc) or bool(self.high_pc)


class File:
    def __init__(self):
        self.name = ""
        self.comp_dir = ""
        self.gvariable: dict[str, list[Variable]] = defaultdict(
            list)  # {"name" : list[Variable]}
        self.subprograms: dict[str, list[Subprogram]
                               ] = defaultdict(list)  # {"name" : Subprogram}


def scan_compile_unit(file_path):
    def extract_AT_name(line: str):
        match = re.search(r'DW_AT_\w+\s+\(.*"([^"]+)"\)', line)
        if match:
            return match.group(1)  #
        else:
            assert False, "Invalid DW_AT_name line"

    def extract_AT_type(line: str):
        match = re.search(r'"([^"]*)"', line)
        if match:
            return match.group(1)  #
        else:
            assert False, "Invalid DW_AT_type line"

    def extract_AT_pc(line: str):
        match = re.search(r'\(([^)]+)\)', line)
        if match:
            return match.group(1)  #
        else:
            assert False, "Invalid DW_AT_pc line"

    def extract_AT_location(line):
        #
        pattern = r'\[\s*(0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+)\)\s*:\s*(.*)'
        match = re.match(pattern, line)

        if match:
            start_address = match.group(1).strip()  #
            end_address = match.group(2).strip()  #
            operation = match.group(3).strip()  #
            if operation[-1] == ')':
                operation = operation[:-1]
            return start_address, end_address, operation
        else:
            return None, None, None

    file = File()

    with open(file_path, 'r') as openfile:
        state = "BEGIN"
        cur_variable = Variable()
        cur_subprogram = Subprogram()
        current_state = None
        for line in openfile:
            line = line.strip()

            if "DW_TAG_" in line:
                match = re.search(r'DW_TAG_([a-zA-Z_]+)', line)
                if match:
                    current_state = match.group(1)

            if not line:
                # commit
                if state == "GVARIABLELOCATION":
                    state = "GVARIABLE"
                elif state == "VARIABLELOCATION":
                    state = "VARIABLE"

                if state == "GVARIABLE" and cur_variable:
                    # assert file.gvariable.get(cur_variable.name) is None
                    file.gvariable[cur_variable.name].append(cur_variable)
                elif state == "VARIABLE" and cur_variable:
                    cur_subprogram.variables[cur_variable.name].append(
                        cur_variable)

                cur_variable = Variable()

            if "DW_TAG_compile_unit" in line:
                assert state == "BEGIN"
                state = "COMPILE_UNIT"

            if "DW_TAG_variable" in line:
                if state == "COMPILE_UNIT" or state == "GVARIABLE":
                    state = "GVARIABLE"
                elif state == "SUBPROGRAM" or state == "VARIABLE":
                    state = "VARIABLE"
                else:
                    assert False, "Invalid state"

            if "DW_TAG_subprogram" in line:
                state = "SUBPROGRAM"
                if cur_subprogram:
                    # assert file.subprograms.get(cur_subprogram.name) is None
                    file.subprograms[cur_subprogram.name].append(
                        cur_subprogram)
                cur_subprogram = Subprogram()

            if "DW_TAG_formal_parameter" in line and state != "COMPILE_UNIT":
                state = "VARIABLE"

            if "DW_AT_comp_dir" in line:
                assert state == "COMPILE_UNIT"
                file.comp_dir = extract_AT_name(line)

            if "DW_AT_abstract_origin" in line and '"' in line:
                name = extract_AT_name(line)
                if (state == "GVARIABLE" or state == "VARIABLE") and (
                        current_state == "variable" or current_state == "formal_parameter"):
                    cur_variable.name = name
                elif state == "SUBPROGRAM" and current_state == "subprogram":
                    cur_subprogram.name = name

            if "DW_AT_name" in line:
                name = extract_AT_name(line)
                if state == "COMPILE_UNIT" and not file.name and current_state == "compile_unit":
                    file.name = name
                elif (state == "GVARIABLE" or state == "VARIABLE") and (
                        current_state == "variable" or current_state == "formal_parameter"):
                    cur_variable.name = name
                elif state == "SUBPROGRAM" and current_state == "subprogram":
                    cur_subprogram.name = name

            if "DW_AT_type" in line:
                if state == "GVARIABLE" or state == "VARIABLE":
                    cur_variable.type = extract_AT_type(line)

            if "DW_AT_location" in line and current_state != 'dwarf_procedure':
                assert state == "GVARIABLE" or state == "VARIABLE" or current_state == "call_site_parameter"
                if state == "VARIABLE":
                    state = "VARIABLELOCATION"
                # one line , like :   DW_AT_location  (DW_OP_addr 0x4060)
                if ")" in line and current_state == "variable":
                    match = re.search(r'\(([^)]+)\)', line)
                    assert match
                    cur_variable.location.add_range(match.group(1))
                elif state == "GVARIABLE":
                    state = "GVARIABLELOCATION"

            if "DW_AT_low_pc" in line and state == "SUBPROGRAM":
                cur_subprogram.low_pc = extract_AT_pc(line)
            if "DW_AT_high_pc" in line and state == "SUBPROGRAM":
                cur_subprogram.high_pc = extract_AT_pc(line)
            if "DW_AT_frame_base" in line:
                assert state == "SUBPROGRAM"
                cur_subprogram.frame_base = extract_AT_pc(line)

            if state == "GVARIABLELOCATION" or state == "VARIABLELOCATION":
                start_address, end_address, operation = extract_AT_location(
                    line)
                if start_address and end_address and operation:
                    cur_variable.location.add_range(
                        operation, start_address, end_address)
        if cur_subprogram.name:
            # assert file.subprograms.get(cur_subprogram.name) is None
            file.subprograms[cur_subprogram.name].append(cur_subprogram)

    if len(file.gvariable) == 0 and len(file.subprograms) == 0:
        return None
    return file


def process_file(file_path):
    return scan_compile_unit(file_path)
    # try:
    #     ret = scan_compile_unit(file_path)
    #     return ret
    # except Exception as e:
    #     print(f"Error processing file {file_path}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Process dwarf debug info file dumped by llvm-dwarfdump")
    parser.add_argument('path', type=str,
                        help='Path to the debug_info file or directory')
    args = parser.parse_args()

    if os.path.isdir(args.path):
        # Process all files in the directory
        file_paths = [os.path.join(args.path, f) for f in os.listdir(args.path) if
                      os.path.isfile(os.path.join(args.path, f))]
    elif os.path.isfile(args.path):
        file_paths = [args.path]
    else:
        raise ValueError("Invalid path")

    results = []
    with ProcessPoolExecutor() as executor:
        future_to_file = [executor.submit(
            process_file, file_path) for file_path in file_paths]
        for future in as_completed(future_to_file):
            file = future.result()
            if file:
                results.append(file)
                logger.info(
                    f"Processed file: {file.name}\t\tsubprograms: {len(file.subprograms)}\t\tvariables: {len(file.gvariable)}")
    # Save result to a pickle file
    with open("debug.info.pkl", "wb") as f:
        pickle.dump(results, f, protocol=-1)


if __name__ == "__main__":
    main()
