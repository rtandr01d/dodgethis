#!/usr/bin/env python3

import argparse
import os
import re
from collections import defaultdict

from elftools.elf.elffile import ELFFile


# Suspicious imported functions
SUSPICIOUS_IMPORTS = {
    "ptrace": "Debugger detection",
    "process_vm_readv": "Memory inspection",
    "process_vm_writev": "Memory modification",
    "prctl": "Process protection",
    "seccomp": "Sandbox / syscall filtering",
    "sigaction": "Signal handler manipulation",
    "signal": "Signal handler manipulation",
    "raise": "Self-triggered signal",
    "kill": "Process termination",
    "tgkill": "Thread termination",
    "abort": "Intentional crash",
    "__android_log_assert": "Assertion crash",
    "__system_property_get": "System property inspection",
    "mprotect": "Executable page modification",
    "mmap": "Memory mapping",
    "munmap": "Memory unmapping",
    "dl_iterate_phdr": "Loaded module inspection",
    "dlopen": "Dynamic library loading",
    "dlsym": "Symbol lookup",
    "open": "Filesystem inspection",
    "openat": "Filesystem inspection",
    "access": "Filesystem inspection",
    "readlink": "Filesystem inspection",
    "fopen": "Filesystem inspection",
    "stat": "Filesystem inspection",
    "lstat": "Filesystem inspection",
    "getauxval": "Runtime environment inspection",
}

# Interesting strings
STRING_PATTERNS = {
    "frida": "Frida detection",
    "gum": "Frida Gum",
    "gadget": "Frida Gadget",
    "xposed": "Xposed detection",
    "substrate": "Substrate detection",
    "magisk": "Root detection",
    "zygisk": "Root detection",
    "riru": "Root detection",
    "edxp": "EdXposed detection",
    "lsposed": "LSPosed detection",
    "/proc/self/maps": "Memory map inspection",
    "/proc/self/status": "Status inspection",
    "/proc/net/tcp": "Port scan",
    "TracerPid": "Debugger detection",
    "ro.debuggable": "Android debug property",
    "ro.secure": "Android security property",
    "android.os.Debug": "Debugger API",
    "JDWP": "Java debugger",
    "LIBFRIDA": "Frida detection",
    "frida-server": "Frida detection",
}

WEIGHTS = {
    "Debugger detection": 3,
    "Frida detection": 5,
    "Frida Gum": 5,
    "Root detection": 2,
    "Memory map inspection": 4,
    "Executable page modification": 2,
    "Loaded module inspection": 4,
    "Filesystem inspection": 2,
    "Signal handler manipulation": 2,
    "Runtime environment inspection": 2,
}


def extract_strings(data, minimum=4):
    regex = rb"[\x20-\x7e]{%d,}" % minimum
    return [s.decode(errors="ignore") for s in re.findall(regex, data)]


def scan_symbols(elf):
    findings = []

    for secname in [".dynsym", ".symtab"]:
        section = elf.get_section_by_name(secname)
        if not section:
            continue

        for sym in section.iter_symbols():
            name = sym.name

            if name in SUSPICIOUS_IMPORTS:
                findings.append(
                    (
                        "IMPORT",
                        name,
                        SUSPICIOUS_IMPORTS[name],
                    )
                )

    return findings


def scan_strings(data):
    findings = []

    strings = extract_strings(data)

    for s in strings:
        low = s.lower()

        for pattern, desc in STRING_PATTERNS.items():
            if pattern.lower() in low:
                findings.append(("STRING", s, desc))

    return findings


def summarize(findings):
    score = 0
    categories = defaultdict(list)

    for typ, item, desc in findings:
        categories[desc].append(item)
        score += WEIGHTS.get(desc, 1)

    return score, categories


def scan_file(filename):
    with open(filename, "rb") as f:
        data = f.read()

    with open(filename, "rb") as f:
        elf = ELFFile(f)

        findings = []
        findings.extend(scan_symbols(elf))
        findings.extend(scan_strings(data))

    score, cats = summarize(findings)

    print("=" * 70)
    print(filename)
    print("=" * 70)

    print(f"Hardened Score: {score}\n")

    if not cats:
        print("No obvious anti-hooking indicators found.")
        return

    for cat in sorted(cats):
        print(f"[+] {cat}")

        for item in sorted(set(cats[cat])):
            print(f"      {item}")

        print()


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "path",
        help=".so file or directory",
    )

    args = parser.parse_args()

    if os.path.isdir(args.path):
        for root, _, files in os.walk(args.path):
            for f in files:
                if f.endswith(".so"):
                    scan_file(os.path.join(root, f))
    else:
        scan_file(args.path)


if __name__ == "__main__":
    main()
