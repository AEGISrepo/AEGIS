import toml
import json
import csv
from loguru import logger
from collections import defaultdict, OrderedDict
import pickle
from fuzzywuzzy import fuzz, process


def main():
    kv = defaultdict(list)
    with open("probes.txt") as f:
        lines = f.readlines()
        for idx, line in enumerate(lines):
            if ":" in line:
                kv[line.strip()]

                for nextidx in range(idx + 1, len(lines)):
                    nextline = lines[nextidx]
                    if ":" in nextline:
                        break
                    kv[line.strip()].append(nextline.strip())

    keys = []
    for k, v in kv.items():
        spilted = str(k).strip().split(":")
        if spilted[-1].startswith("__"):  # ! May be BUG
            continue
        keys.append((spilted[-1], spilted))
        if spilted[-1] == "vfs_open":
            logger.debug(k)

    keys = sorted(keys)

    with open("probesname.csv", "w") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "probename"])
        for key in keys:
            writer.writerow([key[0], ":".join(key[1])])

    values = []
    for key in keys:
        l = kv[":".join(key[1])]
        values.append([line.strip() for line in l])
    ordereddict = OrderedDict()
    jsonobj = []
    for i in range(len(keys)):
        probename = ":".join(keys[i][1])
        ordereddict[probename] = values[i]
        jsonobj.append({"name": probename, "args": values[i]})

    toml.dump(ordereddict, open("probes.toml", "w"))

    json.dump(jsonobj, open("probes.json", "w"), indent=4)
    with open("probes_sorted.txt", "w") as f:
        for key in keys:
            name = ":".join(key[1])
            f.write(name + "\n")
            for line in kv[name]:
                f.write("    " + line + "\n")


probes = defaultdict(list)


def main2():

    kv = defaultdict(list)
    with open("probes.txt") as f:
        lines = f.readlines()
        for idx, line in enumerate(lines):
            if ":" in line:
                kv[line.strip()]

                for nextidx in range(idx + 1, len(lines)):
                    nextline = lines[nextidx]
                    if ":" in nextline:
                        break
                    kv[line.strip()].append(nextline.strip())

    keys = []
    for k, v in kv.items():
        spilted = str(k).strip().split(":")
        if spilted[-1].startswith("__"):  # ! May be BUG
            continue
        keys.append((spilted[-1], spilted))
        if spilted[-1] == "vfs_open":
            logger.debug(k)

    keys = sorted(keys)

    values = []
    for key in keys:
        l = kv[":".join(key[1])]
        values.append([line.strip() for line in l])

        # short name key[0]
        # full name ":".join(key[1])
        # args
        fullname = ":".join(key[1])
        probes[key[0]].append((fullname, "\n".join(l)))


if __name__ == "__main__":
    # main()
    # main2()
    # with open('probes.pickle', 'wb') as fp:
    #     pickle.dump(probes, fp, protocol=pickle.HIGHEST_PROTOCOL)

    """
        probes[short name] = [(full name1, args),(full name2, args),........]
    """

    with open('probes.pickle', 'rb') as fp:
        probes = pickle.load(fp)
    # print(probes['vfs_open'])
    keyslist = list(probes.keys())

    """
    sys_enter_*
    sys_exit_*
    do_sys_*
    """

    ans = process.extractOne(
        "socket", keyslist, scorer=fuzz.ratio)

    print(ans[0])
    print(probes[ans[0]])
