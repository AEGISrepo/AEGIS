from dwarf_engine import dwarf_cal_engine
import pickle
import re
import os
from loguru import logger
from collections import defaultdict
import sympy as sp
from functools import cache


class LineTable:
    class FileNames:
        def __init__(self):
            self.name: str = ""
            self.dir_index: int = 0
            pass

    # Address            Line   Column File   ISA Discriminator Flags

    class AddressItem:
        def __init__(self):
            self.address = 0
            self.line = 0
            self.column = 0
            self.fileidx = 0

    def __init__(self):
        self.include_directories: list[str] = []
        self.file_names: list[LineTable.FileNames] = []
        self.address_table: list[LineTable.AddressItem] = []


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

    def __str__(self):
        return f"Location(ranges={self.ranges})"


class Variable:
    def __init__(self, name="", var_type="", location=None):
        self.name = name  #
        self.type = var_type  #
        self.location = location if location is not None else Location()  #

    def __bool__(self):
        return bool(self.location) and bool(self.name)

    def __str__(self):
        return f"Variable(name={self.name}, type={self.type}, location={self.location})"


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

    def __str__(self):
        return f"Subprogram(name={self.name}, frame_base={self.frame_base}, low_pc={self.low_pc}, high_pc={self.high_pc}, variables={self.variables})"


class File:
    def __init__(self):
        self.name = ""
        self.comp_dir = ""
        self.gvariable: dict[str, list[Variable]] = defaultdict(
            list)  # {"name" : list[Variable]}
        self.subprograms: dict[str, list[Subprogram]] = defaultdict(
            list)  # {"name" : Subprogram}


class FDE:
    class AddressItem:
        def __init__(self):
            self.pc_start = 0
            self.cfa = sp.Eq(sp.symbols('l'), sp.symbols('r'))
            self.regs = dict()

    def __init__(self):
        self.pc_start = 0
        self.pc_end = 0
        self.address_table: list[FDE.AddressItem] = []


PREFIXPATH = "/"

with open(PREFIXPATH+'debug.line.pkl', 'rb') as f:
    line_table: list[LineTable] = pickle.load(f)

with open(PREFIXPATH+'debug.frame.pkl', 'rb') as f:
    fde_table: list[FDE] = pickle.load(f)

with open(PREFIXPATH+'debug.info.pkl', 'rb') as f:
    file_table: list[File] = pickle.load(f)


linesmap = defaultdict(list)


def process_linetable(lt: LineTable):
    include_dirs = lt.include_directories
    file_names = lt.file_names
    for addritem in lt.address_table:
        addr = addritem.address
        line = addritem.line
        column = addritem.column
        fileidx = addritem.fileidx
        file = file_names[fileidx]
        dirname = include_dirs[file.dir_index]
        filename = file.name
        fullname = os.path.join(dirname, filename)
        linesmap[fullname].append((line, column, addr))
        # linesmap[fullname].sort(key=lambda x: x[0])
        # (fullname, line, column, addr)


for lt in line_table:
    process_linetable(lt)

for key in linesmap.keys():
    linesmap[key].sort()


def get_file(file_name):
    for file in file_table:
        # check is absolute path
        name = None
        if os.path.isabs(file.name):
            name = file.name
        else:
            name = os.path.join(file.comp_dir, file.name)
        file.name = name
        if name == file_name:
            return file
    return None


#

def get_func_addr(file_name, func_name):
    file = get_file(file_name)
    if not file:
        return None
    subprogs = file.subprograms.get(func_name)
    if not subprogs:
        return None
    assert len(subprogs) == 1
    logger.debug(f'{subprogs[0].low_pc} {subprogs[0].high_pc}')
    return (int(subprogs[0].low_pc, 16), int(subprogs[0].high_pc, 16))


def find_nearest(sorted_list: list, target: int):
    #
    sorted_list.sort(key=lambda x: x[1])

    #
    nearest = sorted_list[0]
    min_diff = abs(sorted_list[0][1] - target)

    # ，
    for item in sorted_list:
        diff = abs(item[1] - target)
        if diff < min_diff:
            min_diff = diff
            nearest = item
    logger.debug(nearest)
    return nearest


def get_line_addr(file_name, line, column):
    addrs = linesmap.get(file_name)
    if not addrs:
        return None
    tmp = []
    addrs.sort()
    for li, colu, addr in addrs:
        if li == line:
            tmp.append((addr, colu))
    if not tmp:
        for i in range(len(addrs)):
            li, colu, addr = addrs[i]
            nli = addrs[i + 1][0] if i + 1 < len(addrs) else -1
            # logger.debug(f"li:{li} nli:{nli}")
            if nli == -1 and not tmp:
                logger.debug(li)
                assert False, "Out of range"
            if li <= line < nli:
                tmp.append((addr, colu))
                logger.debug(f"li:{li} nli:{nli}")
    logger.debug(tmp)
    return find_nearest(tmp, column)[0]


@cache
def get_cfa(addr: int):
    ret = []
    for fde in fde_table:
        if fde.pc_start <= addr < fde.pc_end:
            #   register
            for i in range(len(fde.address_table)):
                addritem = fde.address_table[i]
                start = addritem.pc_start
                end = fde.address_table[i + 1].pc_start if i + \
                    1 < len(fde.address_table) else fde.pc_end
                if start <= addr < end:
                    ret.append(addritem.cfa)
    return ret


PREFIXBUILD = '/'


@cache
def line2addr_abs(filename: str, lno: int, column: int = 0):
    """line2addr - Return the offset from the start of the function containing the given line number.
    """
    logger.debug(f'{PREFIXPATH}/{filename}')
    addr = get_line_addr(
        f'{PREFIXPATH}/{filename}', lno, column)

    return addr


@cache
def func2addr_abs(funcname: str, filename: str):
    """func2addr - Return the offset from the start of the function containing the given line number.
    """
    lowpc, highpc = get_func_addr(
        f'{PREFIXPATH}/{filename}', funcname)
    return lowpc, highpc


@cache
def get_variable_location(file_name: str, func_name: str, addr: int, var_name: str):
    file = get_file(file_name)
    if not file:
        return None
    gvars = file.gvariable
    tgvarlist = gvars.get(var_name)
    ret = []
    if tgvarlist:
        for tgvar in tgvarlist:
            loc = tgvar.location
            for ran in loc.ranges:
                lowpc = int(ran.get('start', '0x0'), 16)
                highpc = int(ran.get('end', '0xFFFFFFFFFFFFFFFF'), 16)
                op = ran.get('operation')
                logger.debug(f"lowpc: {hex(lowpc)}, highpc: {
                             hex(highpc)}, op: {op}")
                assert op
                if lowpc <= addr < highpc:
                    logger.info(f"{tgvar}")
                    ret.append(op)
    subprogs = file.subprograms.get(func_name)
    if subprogs:
        for sub in subprogs:
            assert sub.frame_base == 'DW_OP_call_frame_cfa'
            locvars = sub.variables
            tgvarlist = locvars.get(var_name)
            if tgvarlist:
                for tgvar in tgvarlist:
                    for ran in tgvar.location.ranges:
                        lowpc = int(ran.get('start', '0x0'), 16)
                        highpc = int(ran.get('end', '0xFFFFFFFFFFFFFFFF'), 16)
                        op = ran.get('operation')
                        logger.debug(f"lowpc: {hex(lowpc)}, highpc: {
                                     hex(highpc)}, op: {op}")
                        assert op
                        if lowpc <= addr < highpc:
                            logger.info(f"{tgvar}")
                            ret.append(op)

    return ret


def var2loc(file_name: str, func_name: str, addr: int, var_name: str):
    return get_variable_location(f'{PREFIXPATH}/{file_name}', func_name, addr, var_name)
