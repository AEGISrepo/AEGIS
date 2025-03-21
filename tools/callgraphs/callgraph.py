import sys
import re
from collections import defaultdict
from sqlitedict import SqliteDict

cdefs = []
callermaps = defaultdict(set)  # [k,v] : [caller, callee]
calleemaps = defaultdict(set)  # [k,v] : [callee, caller]


def processCallGraph(filename):

    # "^\"([\w.]+)\" \[(.*)\];"gm
    # "HUF_decompress4X2_usingDTable" [];
    # "mul_n_basecase.isra.0" [label="mul_n_basecase.isra"];
    defre = re.compile(r'^\"([\w.]+)\" \[(.*)\];')

    labelre = re.compile(r'label=\"([\w.]+)\"')

    # "^\"([\w.]+)\" -> \"([\w.]+)\" \[(.*)\];"gm
    # "addrconf_dad_work" -> "printk" [style=solid];
    callre = re.compile(r'^\"([\w.]+)\" -> \"([\w.]+)\" \[(.*)\];')

    with open(filename, 'r') as f:
        for line in f:
            defres = defre.match(line)
            if defres:
                cdefs.append(defres.group(1))
                if defres.group(2):
                    labelres = labelre.match(defres.group(2))
                    if labelres:
                        cdefs.append(labelres.group(1))
                continue
            callres = callre.match(line)
            if callres:
                callermaps[callres.group(1)].add(callres.group(2))
                calleemaps[callres.group(2)].add(callres.group(1))


def saveToSqllite(path: str):
    with SqliteDict(path, autocommit=True, tablename="callermap") as db:
        for k, v in callermaps.items():
            db[k] = v

    with SqliteDict(path, autocommit=True, tablename="calleemap") as db:
        for k, v in calleemaps.items():
            db[k] = v


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 callgraph.py <callgraph.dot path> [save path]")
        sys.exit(1)
    path = "".join(sys.argv[1].split(".dot")) + ".sqlite"
    if len(sys.argv) == 3:
        path = sys.argv[2]
        if not path.endswith(".sqlite"):
            path += ".sqlite"
    processCallGraph(sys.argv[1])
    saveToSqllite(path)
