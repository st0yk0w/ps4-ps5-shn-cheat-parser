#!/usr/bin/env python3
"""
PS4/PS5 .shn Cheat Parser by stoykow
------------------------------------

This script parses a PS4/PS5 .shn cheat XML file and displays it neatly.

Usage:
    python parse_shn_cheats.py <cheat.shn>
"""

import sys
import xml.etree.ElementTree as ET
import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Match registers
REGISTER_PATTERN = re.compile(
    r"\b("
    r"r[0-9]{1,2}[bwd]?|"               # 64bit GPRs
    r"[er]?(ax|bx|cx|dx|si|di|sp|bp)|"  # common regs
    r"(x|y|z)mm\d+"                     # SSE/AVX
    r")\b",
    re.IGNORECASE
)

# Match numeric constants
CONSTANT_PATTERN = re.compile(r"\b0x[0-9A-Fa-f]+\b|\b\d+\b")

# Set of jump/call mnemonics
JUMP_CALL_SET = {
    "call", "jmp", "ja", "jae", "jb", "jbe", "jc", "je", "jecxz", "jg", "jge",
    "jl", "jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge",
    "jnl", "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo", "js", "jz"
}

def disassemble_bytes(code_bytes, start_addr=0):
    """
    Disassembles 'code_bytes' at base 'start_addr';
    Returns a list of (hex_str, mnemonic, op_str, abs_addr, size).
    """
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = []
    for ins in md.disasm(code_bytes, start_addr):
        # Convert opcodes to an uppercase hex string
        hex_str = " ".join(f"{b:02X}" for b in ins.bytes)
        instructions.append((hex_str, ins.mnemonic, ins.op_str, ins.address, ins.size))
    return instructions

def colorize_mnemonic_and_operands(mnemonic, operand_str):
    """
    Colorize rules:
      - Jumps/calls => green
      - Others => yellow
      - Registers => red
      - Constants => cyan
    """
    if mnemonic.lower() in JUMP_CALL_SET:
        mnemonic_colored = f"{Fore.GREEN}{mnemonic}{Style.RESET_ALL}"
    else:
        mnemonic_colored = f"{Fore.YELLOW}{mnemonic}{Style.RESET_ALL}"

    def highlight(match):
        text = match.group(0)
        # If it's a reg
        if REGISTER_PATTERN.match(text):
            return f"{Fore.RED}{text}{Style.RESET_ALL}"
        # Else it's a const
        if text.lower().startswith("0x"):
            prefix = text[:2]
            rest = text[2:].upper()
            return f"{Fore.CYAN}{prefix}{rest}{Style.RESET_ALL}"
        else:
            return f"{Fore.CYAN}{text.upper()}{Style.RESET_ALL}"

    # Apply highlighting
    colored_ops = CONSTANT_PATTERN.sub(highlight, operand_str)
    colored_ops = REGISTER_PATTERN.sub(highlight, colored_ops)

    return mnemonic_colored, colored_ops

def annotate_cave_jump(mnemonic, operand_str, known_cave_offsets):
    """
    If mnemonic is a jump/call, and it jumps to an offset in 'known_cave_offsets',
    append "(cave)" at the end of the line.
    """
    if mnemonic.lower() not in JUMP_CALL_SET:
        return operand_str
    match = re.search(r"0x[0-9A-Fa-f]+", operand_str)
    if not match:
        return operand_str
    target_str = match.group(0)
    try:
        target_val = int(target_str, 16)
    except ValueError:
        return operand_str
    if target_val in known_cave_offsets:
        return operand_str.replace(
            target_str,
            f"{target_str} {Fore.WHITE}(cave){Style.RESET_ALL}"
        )
    return operand_str

def print_disassembly(
    code_bytes, 
    base_addr=0, 
    known_cave_offsets=None
):
    """
    Disassemble 'code_bytes' at 'base_addr'. If a jump/call targets an offset in
    known_cave_offsets, we append "(cave)" in white at the end.
    """
    if known_cave_offsets is None:
        known_cave_offsets = set()

    instructions = disassemble_bytes(code_bytes, base_addr)
    if not instructions:
        return

    max_hex_len = max(len(i[0]) for i in instructions)

    for (hex_str, mnemonic, ops, abs_addr, size) in instructions:
        mnemonic_colored, ops_colored = colorize_mnemonic_and_operands(mnemonic, ops)
        ops_annotated = annotate_cave_jump(mnemonic, ops_colored, known_cave_offsets)

        addr_str = f"{abs_addr:08X}"
        addr_colored = f"{Fore.WHITE}{addr_str}{Style.RESET_ALL}"

        print(
            f"{addr_colored}:  "
            f"{Fore.BLUE}{hex_str.ljust(max_hex_len)}{Style.RESET_ALL}\t"
            f"{mnemonic_colored:10}\t"
            f"{ops_annotated}"
        )

def main(filename):
    try:
        tree = ET.parse(filename)
    except ET.ParseError as e:
        print(f"{Fore.RED}Error parsing .shn: {e}{Style.RESET_ALL}")
        sys.exit(1)

    root = tree.getroot()

    game_name = root.get("Game", "Unknown Game")
    version_name = root.get("Version", "Unknown Version")
    author_name = root.get("Moder", "Unknown Author")

    print()
    print(f"Game: {Fore.RED}{game_name}{Style.RESET_ALL}")
    print(f"Version: {Fore.RED}{version_name}{Style.RESET_ALL}")
    print(f"Author: {Fore.RED}{author_name}{Style.RESET_ALL}\n")

    # Store discovered cave offsets in a set
    known_cave_offsets = set()

    for cheat in root.findall("Cheat"):
        cheat_text = cheat.get("Text", "Unknown Cheat")
        desc = cheat.get("Description")
        if desc:
            print(f"Cheat: {Fore.LIGHTMAGENTA_EX}{cheat_text}{Style.RESET_ALL} ({desc})")
        else:
            print(f"Cheat: {Fore.LIGHTMAGENTA_EX}{cheat_text}{Style.RESET_ALL}")
        print("-" * 6)
        print()

        # For each <Cheatline> in cheat
        for cheatline in cheat.findall("Cheatline"):
            offset_el = cheatline.find("Offset")
            if offset_el is None or not offset_el.text:
                print(f"{Fore.RED}Missing <Offset> for a <Cheatline>. Skipping.{Style.RESET_ALL}")
                continue

            offset_str = offset_el.text.strip()
            try:
                base_addr = int(offset_str, 16)
            except ValueError:
                base_addr = 0

            value_off_el = cheatline.find("ValueOff")
            value_on_el  = cheatline.find("ValueOn")

            valoff_str = value_off_el.text.strip() if (value_off_el is not None and value_off_el.text) else ""
            valon_str  = value_on_el.text.strip()  if (value_on_el  is not None and value_on_el.text)  else ""

            try:
                valoff_bytes = bytes.fromhex(valoff_str.replace("-", "")) if valoff_str else b""
            except ValueError:
                print(f"{Fore.RED}Error parsing ValueOff hex: {valoff_str}{Style.RESET_ALL}")
                valoff_bytes = b""
            try:
                valon_bytes  = bytes.fromhex(valon_str.replace("-", ""))  if valon_str  else b""
            except ValueError:
                print(f"{Fore.RED}Error parsing ValueOn hex: {valon_str}{Style.RESET_ALL}")
                valon_bytes = b""

            # Decide if line is a "cave line" or normal
            if all(b == 0 for b in valoff_bytes):
                # Cave line
                print(f"Cave Address: {Fore.GREEN}0x{offset_str}{Style.RESET_ALL}")
                print(f"Cave Length:  {Fore.GREEN}{len(valoff_bytes)}{Style.RESET_ALL}")
                print("Cave Code:")

                # Record it's offset in known caves
                known_cave_offsets.add(base_addr)

                # Disassemble ValueOn
                print_disassembly(valon_bytes, base_addr=base_addr, known_cave_offsets=known_cave_offsets)
                print()
            else:
                # Normal
                print(f"Address: {Fore.GREEN}0x{offset_str}{Style.RESET_ALL}")
                print("Original Code:")
                print_disassembly(valoff_bytes, base_addr=base_addr, known_cave_offsets=known_cave_offsets)
                print()

                print("Modified Code:")
                print_disassembly(valon_bytes, base_addr=base_addr, known_cave_offsets=known_cave_offsets)
                print()

        print()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    main(sys.argv[1])
