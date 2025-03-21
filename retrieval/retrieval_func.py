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
def getAllfilePaths(path, exts=[".c", ".h"]):
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
def getFunImlpRegex(name):
    # "(?: |\*|\n|\r)+do_dentry_open\s*\((?:.|\s)*?\)\s*\{"gm
    restr = rf"(?: |\*|\n|\r)+{name}\s*\((?:\s|\w|-|>|\*|,|\(|\))*?\)\s*\{{"
    # restr = restr.replace(r"{name}", name)
    logger.debug(f"{restr}")
    return re.compile(restr)


def findNameImpl(path, name):

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

                prev = line[:pos]

                if len(prev) > 0 and (prev[-1].isalnum() or prev[-1].isalpha() or prev[-1] == "_"):
                    # Not this function
                    continue

                cont = prev_context + line
                nowp = len(prev_context) + pos

                isImpl = True
                for i in reversed(cont[:nowp]):
                    if i.isspace():
                        continue
                    # if i in ['{', '}', '(', ')', '[', ']', ';', '/', '"', "'", "<", '>']:
                    if not (i.isalpha() or i.isalnum() or i in '_*'):
                        isImpl = False
                    break

                parts = line.split(f"{name}")

                if not isImpl:
                    continue

                cont += post_context
                reg = getFunImlpRegex(name)
                res = reg.search(cont)
                # logger.debug(f"{path}:{lno + 1} {line.strip()}")
                if not res:
                    continue

                cont = line + post_context
                cont = cont[pos + len(name):]
                stack = []
                for ch in cont:
                    if ch == '(':
                        stack.append(ch)
                        continue
                    elif ch == ')':
                        if len(stack) == 0:
                            isImpl = False
                            break
                        else:
                            stack.pop()
                    elif ch.isalpha() or ch.isalnum() or ch == '_':
                        continue
                    elif ch.isspace() or ch in ",*->":
                        continue
                    elif ch == ';':
                        isImpl = False
                        break
                    else:
                        if len(stack):
                            isImpl = False
                        break
                if not isImpl:
                    continue

                logger.info(f"{path}:{lno - 4} {line.strip()}")
                retval.append((f"{path}:{lno - 4}", f"{line.strip()}"))
    except Exception as e:
        logger.error(f"{path}:{e}")
    return retval


def extractFromFile(pos: str):
    # ../kernel/linux-5.10.209/fs/open.c:763
    print(f"// {pos}")
    path = pos.split(":")[0]
    lno = int(pos.split(":")[1])
    with open(path, "r") as f:
        ringq = deque(maxlen=20)
        iter = enumerate(f)
        for linenum, line in iter:
            ringq.append(line)
            if linenum + 1 != lno:
                continue
            for i in range(len(ringq) - 1, -1, -1):
                if ringq[i].isspace() or i == 0:
                    for j in range(i+1, len(ringq)):
                        print(ringq[j], end='')
                    break
            stacknum = 0
            flag = False
            stacknum += line.count('{')
            if stacknum > 0:
                flag = True
            stacknum -= line.count('}')
            for linenum, line in iter:
                print(line, end='')
                stacknum += line.count('{')
                if stacknum > 0:
                    flag = True
                stacknum -= line.count('}')
                if stacknum <= 0 and flag:
                    break
            break
    print()


@timebudget
def runInParallel(allfile, name="seq_printf"):
    with concurrent.futures.ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = [executor.submit(findNameImpl, file, name)
                   for file in allfile]
        ques = []
        for fu in concurrent.futures.as_completed(futures):
            retval = fu.result()
            if len(retval) > 0:
                for pos, line in retval:
                    ques.append(pos)

        for pos in ques:
            extractFromFile(pos)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python mergeifile.py <folder path> <name>")
        sys.exit(1)

    timebudget.set_quiet()  # don't show measurements as they happen
    # timebudget.report_at_exit()  # Generate report when the program exits

    allfiles = getAllfilePaths(sys.argv[1])
    runInParallel(allfiles, sys.argv[2])
