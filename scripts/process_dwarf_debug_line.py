import argparse
import re
import pickle


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


# class LineTable:
#     class FileNames:
#         name = ""
#         dir_index = 0

# # Address            Line   Column File   ISA Discriminator Flags
#     class AddressItem:
#         address = 0
#         line = 0
#         column = 0
#         fileidx = 0

#     include_directories = []
#     file_names = []
#     address_table = []


def scan_file(file_path):
    linetables = []
    with open(file_path, 'r') as file:
        state = "BEGIN"
        filenameidx = 0
        for line in file:
            if "Line table prologue" in line:
                state = "ENTER"
                linetables.append(LineTable())
                continue

            if "include_directories[" in line:
                assert state == "ENTER" or state == "INCLUDE_DIRECTORIES"
                state = "INCLUDE_DIRECTORIES"
                pattern = r'\[\s*(\d+)\s*\]\s*=\s*"(.*?)"'
                match = re.search(pattern, line)
                assert match
                assert match.group(1)
                number = int(match.group(1))  #
                path = match.group(2)  #
                assert path
                while len(linetables[-1].include_directories) <= number:
                    linetables[-1].include_directories.append("")
                linetables[-1].include_directories[number] = path
                continue

            if "file_names[" in line:
                assert state == "INCLUDE_DIRECTORIES" or state == "FILE_NAMES"
                state = "FILE_NAMES"
                pattern = r'\[\s*(\d+)\s*\]'
                match = re.search(pattern, line)
                assert match
                number = int(match.group(1))  #
                filenameidx = number
                while len(linetables[-1].file_names) <= number:
                    linetables[-1].file_names.append(LineTable.FileNames())
                continue

            if "name:" in line:
                assert state == "FILE_NAMES"
                pattern = r'name:\s*"(.*?)"'
                match = re.search(pattern, line)
                assert match
                name = match.group(1)
                assert name
                linetables[-1].file_names[filenameidx].name = name
                continue

            if "dir_index:" in line:
                assert state == "FILE_NAMES"
                pattern = r'dir_index:\s*(\d+)'
                match = re.search(pattern, line)
                assert match
                assert match.group(1)
                number = int(match.group(1))  #
                linetables[-1].file_names[filenameidx].dir_index = number
                continue

            if "Address" in line and "Discriminator" in line:
                assert state == "FILE_NAMES" or state == "ADDRESS_TABLE"
                state = "ADDRESS_TABLE"
                continue

            pattern = r'^0x[0-9a-fA-F]+\s+.*$'
            if re.match(pattern, line):
                assert state == "ADDRESS_TABLE"
                sp = line.split()
                address = int(sp[0], 16)
                line = int(sp[1])
                column = int(sp[2])
                fileidx = int(sp[3])
                linetables[-1].address_table.append(LineTable.AddressItem())
                linetables[-1].address_table[-1].address = address
                linetables[-1].address_table[-1].line = line
                linetables[-1].address_table[-1].column = column
                linetables[-1].address_table[-1].fileidx = fileidx
                continue

    return linetables


def main():
    parser = argparse.ArgumentParser(
        description="Process dwarf debug line file dumped by llvm-dwarfdump")
    parser.add_argument('file_path', type=str,
                        help='Path to the debug_line file')

    args = parser.parse_args()

    linetables = scan_file(args.file_path)
    # scan_file("test.debug.line")
    print(len(linetables))
    # pickle dump to file
    with open("debug.line.pkl", "wb") as f:
        pickle.dump(linetables, f, protocol=-1)


if __name__ == "__main__":
    main()
