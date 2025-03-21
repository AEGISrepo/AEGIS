import sys
import os
from sqlitedict import SqliteDict


def searchCallGraph(path, tableName, funcName):
    # check exists path
    if os.path.exists(path) == False:
        print(f"{path} not exists", file=sys.stderr)
        sys.exit(1)

    with SqliteDict(path, tablename=tableName, flag='r') as db:
        try:
            return db[funcName]
        except:
            return set()


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 callgraphsearch.py <path> <caller|callee> <funcName>")
        sys.exit(1)
    tablename = sys.argv[2]
    if "caller" in tablename:
        tablename = "calleemap"
    else:
        tablename = "callermap"

    res = searchCallGraph(sys.argv[1], tablename, sys.argv[3])

    for i in res:
        if "sanitizer" in i:
            continue
        if not all(ch.isalpha() or ch.isdigit() or ch == "_" for ch in str(i)):
            continue
        print(i)
