#!/usr/bin/python3
"""Create an MSI file with storages, and check the storages of a file."""

import struct
import sys

SECTOR_SIZE = 512
MINI_SECTOR_SIZE = 64
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF
STORAGE, STREAM, ROOT = 1, 2, 5
SIGNATURES = ("\x05DigitalSignature", "\x05MsiDigitalSignatureEx")

# Storages are (name, children) tuples, streams are names.
TREES = {
    # nested and empty storages followed by further siblings
    "nested": [
        ("A", ["a1", ("B", ["b1", ("C", ["c1"]), ("Empty", [])]), "a2"]),
        "r1",
        ("D", ["d1"]),
        ("E", []),
        "r2",
    ],
    # no streams, so the mini stream is empty without a signature,
    # and enough entries for a directory of several sectors
    "no_streams": [
        ("A", [("B", []), ("C", [("D", [])])]),
        ("E", []),
    ],
    # an invalid file with two adjacent DigitalSignature streams,
    # which must both be replaced or removed
    "duplicate_signature": ["a", SIGNATURES[0], SIGNATURES[0], "b"],
}


def expected(tree: list, prefix: str = "") -> dict:
    """Return the paths of the storages (None) and streams (their data)."""
    paths = {}
    for node in tree:
        if node in SIGNATURES:
            continue  # replaced or removed by osslsigncode
        if isinstance(node, str):
            paths[prefix + node] = f"data of {prefix}{node}".encode()
        else:
            paths[prefix + node[0] + "/"] = None
            paths.update(expected(node[1], prefix + node[0] + "/"))
    return paths


def flatten(tree: list) -> list:
    """Return the directory entries of a tree as [name, type, children, data] lists,
    the children are given by their indexes."""
    nodes = [["Root Entry", ROOT, [], b""]]

    def add(node, prefix: str) -> int:
        index = len(nodes)
        if isinstance(node, str):
            nodes.append([node, STREAM, [], f"data of {prefix}{node}".encode()])
        else:
            nodes.append([node[0], STORAGE, [], b""])
            nodes[index][2] = [add(child, f"{prefix}{node[0]}/") for child in node[1]]
        return index

    nodes[0][2] = [add(node, "") for node in tree]
    return nodes


def dir_entries(nodes: list, streams: list, ministream: tuple) -> bytes:
    """Return the directory entries, the root entry holds the mini stream
    given by its first sector and its length."""
    # link the children of each storage as a list of right siblings
    right = {}
    for node in nodes:
        right.update(zip(node[2], node[2][1:]))
    entries = b""
    for index, (name, kind, children, data) in enumerate(nodes):
        if kind == ROOT:
            location = struct.pack("<IQ", *ministream)
        elif kind == STREAM:
            location = struct.pack("<IQ", streams.index(index), len(data))
        else:
            location = bytes(12)
        encoded = (name + "\0").encode("utf-16le")
        entries += encoded.ljust(64, b"\0")
        entries += struct.pack("<HBBIII", len(encoded), kind, 1, NOSTREAM,
                               right.get(index, NOSTREAM), children[0] if children else NOSTREAM)
        entries += bytes(36) + location
    return entries


def make(path: str, tree: list) -> None:
    """Write a version 3 compound file with the tree and small streams."""
    nodes = flatten(tree)
    streams = [index for index, node in enumerate(nodes) if node[1] == STREAM]
    ministream = b"".join(nodes[i][3].ljust(MINI_SECTOR_SIZE, b"\0") for i in streams)
    # sector 0: FAT, sector 1: MiniFAT if needed, then the mini stream and the directory
    fat = [FATSECT] + ([ENDOFCHAIN] if streams else [])
    chains = []
    for length in (len(ministream), len(nodes) * 128):
        first, count = len(fat), -(-length // SECTOR_SIZE)
        chains.append(first if count else ENDOFCHAIN)
        if count:
            fat += [first + i + 1 for i in range(count - 1)] + [ENDOFCHAIN]
    if len(fat) > SECTOR_SIZE // 4 or len(streams) > SECTOR_SIZE // 4:
        raise ValueError("the tree is too large")
    # each stream gets a single mini sector and a single MiniFAT entry
    if any(len(nodes[i][3]) > MINI_SECTOR_SIZE for i in streams):
        raise ValueError("a stream is longer than a mini sector")
    fat += [FREESECT] * (SECTOR_SIZE // 4 - len(fat))
    minifat = b""
    if streams:
        minifat = struct.pack("<128I", *([ENDOFCHAIN] * len(streams)
                                         + [FREESECT] * (SECTOR_SIZE // 4 - len(streams))))

    header = bytes.fromhex("D0CF11E0A1B11AE1") + bytes(16)
    header += struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + bytes(6)
    header += struct.pack("<IIIIIIIII", 0, 1, chains[1], 0, 4096,
                          1 if streams else ENDOFCHAIN, len(minifat) // SECTOR_SIZE, ENDOFCHAIN, 0)
    header += struct.pack("<109I", 0, *([FREESECT] * 108))
    with open(path, "wb") as file:
        file.write(header + struct.pack("<128I", *fat) + minifat)
        file.write(ministream.ljust(-(-len(ministream) // SECTOR_SIZE) * SECTOR_SIZE, b"\0"))
        entries = dir_entries(nodes, streams, (chains[0], len(ministream)))
        file.write(entries.ljust(-(-len(entries) // SECTOR_SIZE) * SECTOR_SIZE, b"\0"))


class CompoundFile:
    """Minimal reader of the storages and streams of a compound file."""

    def __init__(self, path: str):
        with open(path, "rb") as file:
            self.data = file.read()
        self.sector_size = 1 << struct.unpack_from("<H", self.data, 30)[0]
        first_dir, _, cutoff, first_minifat = struct.unpack_from("<IIII", self.data, 48)
        self.cutoff = cutoff
        first_difat, difat_count = struct.unpack_from("<II", self.data, 68)
        fat_sectors = list(struct.unpack_from("<109I", self.data, 76))
        per_sector = self.sector_size // 4
        sector = first_difat
        for _ in range(difat_count):
            difat = struct.unpack_from(f"<{per_sector}I", self.data, self.offset(sector))
            fat_sectors += difat[:-1]
            sector = difat[-1]
        self.fat = []
        for sector in fat_sectors:
            if sector < FATSECT:
                self.fat += struct.unpack_from(f"<{per_sector}I", self.data,
                                               self.offset(sector))
        directory = self.read_chain(first_dir)
        self.entries = [directory[i:i + 128] for i in range(0, len(directory), 128)]
        root = self.entry(0)
        self.ministream = self.read_chain(root["start"])[:root["size"]]
        minifat = self.read_chain(first_minifat) if first_minifat < FATSECT else b""
        self.minifat = struct.unpack(f"<{len(minifat) // 4}I", minifat)

    def offset(self, sector: int) -> int:
        """Return the file offset of a sector, the header occupies the first one."""
        return (sector + 1) * self.sector_size

    def chain(self, fat, start: int):
        """Yield the sectors of a chain."""
        sector, seen = start, set()
        while sector < FATSECT:
            if sector in seen or sector >= len(fat):
                raise ValueError("corrupted sector chain")
            seen.add(sector)
            yield sector
            sector = fat[sector]

    def read_chain(self, start: int) -> bytes:
        """Read the data of a chain of sectors."""
        return b"".join(self.data[self.offset(sector):self.offset(sector) + self.sector_size]
                        for sector in self.chain(self.fat, start))

    def entry(self, index: int) -> dict:
        """Parse a directory entry."""
        raw = self.entries[index]
        name_len, kind, _, left, right, child = struct.unpack_from("<HBBIII", raw, 64)
        start, size = struct.unpack_from("<II", raw, 116)
        return {"name": raw[:max(name_len - 2, 0)].decode("utf-16le"), "type": kind,
                "left": left, "right": right, "child": child, "start": start, "size": size}

    def read_stream(self, entry: dict) -> bytes:
        """Read the data of a stream from the mini stream or from sectors."""
        if entry["size"] >= self.cutoff:
            return self.read_chain(entry["start"])[:entry["size"]]
        data = b"".join(self.ministream[sector * MINI_SECTOR_SIZE:(sector + 1) * MINI_SECTOR_SIZE]
                        for sector in self.chain(self.minifat, entry["start"]))
        return data[:entry["size"]]

    def paths(self, storage: int = 0, prefix: str = "", seen=None) -> dict:
        """Return the paths of the storages (None) and streams (their data)."""
        seen = set() if seen is None else seen
        paths = {}
        pending = [self.entry(storage)["child"]]
        while pending:
            index = pending.pop()
            if index == NOSTREAM:
                continue
            if index in seen or index >= len(self.entries):
                raise ValueError(f"corrupted directory entry ID {index}")
            seen.add(index)
            entry = self.entry(index)
            pending += [entry["left"], entry["right"]]
            path = prefix + entry["name"] + ("/" if entry["type"] == STORAGE else "")
            if path in paths:
                raise ValueError(f"duplicate directory entry {path!r}")
            if entry["type"] == STORAGE:
                paths[path] = None
                paths.update(self.paths(index, path, seen))
            elif entry["type"] == STREAM:
                paths[path] = self.read_stream(entry)
            else:
                raise ValueError(f"unexpected directory entry type {entry['type']}")
        return paths


def check(path: str, tree: list) -> int:
    """Return 0 when the file contains exactly the storages and streams of the tree."""
    try:
        compound_file = CompoundFile(path)
        found = compound_file.paths()
    except (ValueError, IndexError, struct.error) as err:
        print(f"{path}: {err}", file=sys.stderr)
        return 1
    for name in SIGNATURES:
        found.pop(name, None)
    if found != expected(tree):
        print(f"{path}: unexpected storages or streams:\n{found}", file=sys.stderr)
        return 1
    # reported so that a test can require the case of an empty mini stream
    empty = ", mini stream empty" if not compound_file.ministream else ""
    print(f"{path}: storages and streams preserved{empty}")
    return 0


def main() -> None:
    """Parse the command line."""
    if len(sys.argv) == 4 and sys.argv[1] in ("make", "check") and sys.argv[3] in TREES:
        tree = TREES[sys.argv[3]]
        if sys.argv[1] == "make":
            make(sys.argv[2], tree)
        else:
            sys.exit(check(sys.argv[2], tree))
    else:
        print(f"Usage:\n\t{sys.argv[0]} make OUTFILE TREE\n\t{sys.argv[0]} check FILE TREE"
              f"\nTREE: {', '.join(TREES)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()


# pylint: disable=pointless-string-statement
"""Local Variables:
    c-basic-offset: 4
    tab-width: 4
    indent-tabs-mode: no
End:
    vim: set ts=4 expandtab:
"""
