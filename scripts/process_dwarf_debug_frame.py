import argparse
import re
import pickle
import sympy as sp
from collections import defaultdict


class FDE:
    class AddressItem:
        def __init__(self):
            self.pc_start = 0
            self.cfa = sp.Eq(sp.symbols('l'), sp.symbols('r'))
            self.regs = dict()

    def __init__(self):
        self.pc_start = 0
        self.pc_end = 0
        self.address_table = []


def parse_cfa_expression(cfa_str: str):
    """
     'CFA=RBP+16' ， RBP + 16。
    ， sympy.symbols 。
    """
    if '[' in cfa_str or ']' in cfa_str:
        cfa_str = cfa_str.replace('[', '').replace(']', '')

    #  "CFA=+"
    pattern = r"([A-Za-z0-9]+)=([A-Za-z0-9]+)([+-]\d+)"

    match = re.match(pattern, cfa_str)

    if match:
        regl = match.group(1)  #
        regr = match.group(2)  #
        offset = int(match.group(3))  #

        #
        regl_symbol = sp.symbols(regl)
        regr_symbol = sp.symbols(regr)

        #
        return sp.Eq(regl_symbol, regr_symbol + offset)

    # A = B
    pattern = r"([A-Za-z0-9]+)=([A-Za-z0-9]+)"
    match = re.match(pattern, cfa_str)

    if match:
        regl = match.group(1)  #
        regr = match.group(2)  #

        #
        regl_symbol = sp.symbols(regl)
        regr_symbol = sp.symbols(regr)

        #
        return sp.Eq(regl_symbol, regr_symbol)

    raise ValueError(f"Invalid CFA expression: {cfa_str}")


def scan_file(file_path):
    fde_tables: list[FDE] = []
    with open(file_path, 'r') as file:
        state = "BEGIN"
        for line in file:
            line = line.strip()

            #  FDE
            if "FDE" in line and "cie" in line:
                assert state == "BEGIN" or state == "ADDRESSITEM"
                state = "FDE"

                pattern = r"pc=([0-9a-fA-F]+)\.\.\.([0-9a-fA-F]+)"
                match = re.search(pattern, line)
                assert match
                pc_start = int(match.group(1), 16)
                pc_end = int(match.group(2), 16)

                current_fde = FDE()
                current_fde.pc_start = pc_start
                current_fde.pc_end = pc_end

                fde_tables.append(current_fde)
                continue

            pattern = r"^\s*0x([0-9a-fA-F]+):\s+CFA="
            if re.match(pattern, line):
                assert state == "FDE" or state == "ADDRESSITEM"
                state = "ADDRESSITEM"

                current_addressitem = FDE.AddressItem()

                spil = line.split(":")
                address = int(spil[0].strip(), 16)

                current_addressitem.pc_start = address

                cfs_expr = spil[1].strip()

                eq = parse_cfa_expression(cfs_expr)

                current_addressitem.cfa = eq

                exprs = spil[-1].split(',')

                for expr in exprs:
                    expr = expr.strip()
                    if expr == "" or "undefined" in expr:
                        continue
                    eq = parse_cfa_expression(expr)
                    current_addressitem.regs[str(eq.lhs)] = eq

                fde_tables[-1].address_table.append(current_addressitem)

                assert address >= fde_tables[-1].pc_start and address < fde_tables[-1].pc_end

    return fde_tables


def main():
    parser = argparse.ArgumentParser(
        description="Process dwarf debug frame file dumped by llvm-dwarfdump")
    parser.add_argument('file_path', type=str,
                        help='Path to the debug_frame file')

    args = parser.parse_args()

    frame_tables = scan_file(args.file_path)

    print(f"Found {len(frame_tables)} frame tables.")

    # pickle dump to file
    with open("debug.frame.pkl", "wb") as f:
        pickle.dump(frame_tables, f, protocol=-1)


if __name__ == "__main__":
    main()
