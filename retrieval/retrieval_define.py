from functools import lru_cache
import sys
import os
import re
import mmap
from loguru import logger
from timebudget import timebudget
import concurrent.futures
from multiprocessing import Value
from collections import deque


@timebudget
def getAllfilePaths(path, exts=[".h"]):
    allfile = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if any(file.endswith(ext) for ext in exts):
                # logger.info(os.path.join(root, file))
                allfile.append(os.path.join(root, file))
    logger.info(f"{path} has {len(allfile)} with {exts}")
    return allfile


# "(?:__extension__ )?typedef (.+) (.+);"gm
typedef_re = re.compile(r"(?:__extension__ )?typedef (.+) (.+);")

# enum\s?(\w+)?\s?([\s\w\{\}=,\(\)]+);
enum_re = re.compile(r"enum\s?(\w+)?\s?([\s\w\{\}=,\(\)]+);")


def getEnumDefs(content: str):
    res = []
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if len(line) <= 2:
            continue
        parts = [p.strip(" \n\r,") for p in line.split('=')]
        res.append(parts)
    return res


flag = Value("i", 0)


@lru_cache
def getDefineRegex(name):
    restr = rf"#define\s+{name}\s+"
    logger.debug(f"{restr}")
    return re.compile(restr)


def getEnumRegex(name):
    # ^\s+{name}
    restr = rf"^\s+{name}"
    logger.debug(f"{restr}")
    return re.compile(restr)


def findDefine(path, name):

    retval = []

    try:
        with open(path, "r") as f:
            # s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            ringq = deque(maxlen=11)
            for lno, line in enumerate(f):
                ringq.append(line)

                if len(ringq) < 11:
                    continue

                """
                [0-4] prev content
                [5] this line
                [6-10] post content
                """
                line = str(ringq[5])
                prev_context = "".join(ringq[i] for i in range(0, 5))
                post_context = "".join(ringq[i] for i in range(6, 11))

                pos = line.find(name)
                if pos == -1:
                    continue

                reg1 = getDefineRegex(name)
                reg2 = getEnumRegex(name)
                if not reg1.search(line) and not reg2.search(line):
                    continue

                logger.info(f"{path}:{lno - 4} {line.strip()}")
                retval.append((f"{path}:{lno - 4}", f"{line.strip()}"))
    except Exception as e:
        logger.error(f"{path}:{e}")
    return retval


def extractFromFile(pos: str, line):
    # ../kernel/linux-5.10.209/fs/open.c:763
    print(f"// {pos}")
    if "define" in line:
        print(line)
        return

    path = pos.split(":")[0]
    lno = int(pos.split(":")[1])
    with open(path, "r") as f:
        ringq = deque(maxlen=100)
        iter = enumerate(f)
        for linenum, line in iter:
            ringq.append(line)
            if linenum + 1 != lno:
                continue
            for i in range(len(ringq) - 1, -1, -1):
                if "enum" in ringq[i] or i == 0:
                    for j in range(i, len(ringq)):
                        print(ringq[j], end='')
                    break

            for linenum, line in iter:
                print(line, end='')
                if "}" in line:
                    break
            break
    print()


@timebudget
def runInParallel(allfile, name="seq_printf"):
    with concurrent.futures.ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = [executor.submit(findDefine, file, name)
                   for file in allfile]
        ques = []
        for fu in concurrent.futures.as_completed(futures):
            retval = fu.result()
            if len(retval) > 0:
                for pos, line in retval:
                    ques.append((pos, line))

        for pos, line in ques:
            extractFromFile(pos, line)
            pass


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python mergeifile.py <folder path> <name>")
        sys.exit(1)

    timebudget.set_quiet()  # don't show measurements as they happen
    # timebudget.report_at_exit()  # Generate report when the program exits

    allfiles = getAllfilePaths(sys.argv[1])
    runInParallel(allfiles, sys.argv[2])
