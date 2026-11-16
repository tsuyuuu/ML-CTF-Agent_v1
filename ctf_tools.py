import shlex


def inspect_binary(solver, path):
    """
    Inspect a contestant binary using bounded commands
    inside the isolated Docker solver.
    """

    if not isinstance(path, str):
        return {"error": "Path must be a string"}

    if not path.startswith(("/challenge/", "/work/")):
        return {"error": "Path outside allowed directories"}

    quoted = shlex.quote(path)

    commands = {
        "file_type": f"file {quoted}",
        "elf_header": (
            f"readelf -h {quoted} 2>/dev/null | head -35"
        ),
        "interesting_strings": (
            f"strings -a {quoted} | "
            "grep -Ei 'flag|password|correct|wrong|"
            "error|success|denied|input|usage' | head -30"
        ),
    }

    results = {}

    for name, command in commands.items():
        result = solver.run_command(command, timeout_s=60)
        results[name] = {
            "output": result.get("stdout", "")[:2000],
            "error": result.get("stderr", "")[:300],
            "exit_code": result.get("exit_code"),
        }

    return results


def disassemble_binary(solver, path, start_address, stop_address):
    """
    Return bounded Intel-syntax disassembly from a binary.

    Addresses must be hexadecimal strings, e.g. 0x400f10.
    The maximum allowed address range is 8192 bytes, enough to read a whole
    function in one call (a 512-byte cap forced dozens of chunked calls on
    larger functions, which wasted steps and tokens).
    """
    import re

    if not all(isinstance(x, str) for x in (
        path, start_address, stop_address
    )):
        return {"error": "Arguments must be strings"}

    if not re.fullmatch(r"0x[0-9a-fA-F]+", start_address):
        return {"error": "Invalid start address"}

    if not re.fullmatch(r"0x[0-9a-fA-F]+", stop_address):
        return {"error": "Invalid stop address"}

    start = int(start_address, 16)
    stop = int(stop_address, 16)

    if start >= stop:
        return {"error": "Stop address must exceed start address"}

    if stop - start > 8192:
        return {"error": "Address range exceeds 8192 bytes"}

    quoted = shlex.quote(path)

    command = (
        f"objdump -d -M intel "
        f"--start-address={start} "
        f"--stop-address={stop} "
        f"{quoted}"
    )

    result = solver.run_command(command, timeout_s=60)

    output = result.get("stdout", "")

    return {
        "disassembly": output[:24000],
        "truncated": len(output) > 24000,
        "exit_code": result.get("exit_code"),
        "error": result.get("stderr", "")[:500],
    }


def extract_stack_constants(solver, path, function_name="main"):
    """
    Extract immediate-byte assignments to rbp-relative stack
    locations from an ELF function.

    Return contiguous blocks in memory order, not the order
    in which instructions appear.
    """
    import re

    if not isinstance(path, str) or not path.startswith(
        ("/challenge/", "/work/")
    ):
        return {"error": "Invalid contestant path"}

    if (
        not isinstance(function_name, str)
        or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.$@]*", function_name)
        or len(function_name) > 100
    ):
        return {"error": "Invalid function name"}

    command = (
        "objdump -d -M intel --no-show-raw-insn "
        f"--disassemble={shlex.quote(function_name)} "
        f"{shlex.quote(path)}"
    )

    result = solver.run_command(command, timeout_s=60)

    if result.get("exit_code") != 0:
        return {
            "error": "Disassembly failed",
            "details": result.get("stderr", "")[:300],
        }

    if result.get("truncated"):
        return {"error": "Disassembly output truncated"}

    output = result.get("stdout", "")

    pattern = re.compile(
        r"\bmov\s+BYTE PTR\s*\[rbp-0x([0-9a-f]+)\]"
        r"\s*,\s*0x([0-9a-f]+)\b",
        re.IGNORECASE,
    )

    values = {}
    duplicates = []

    for offset_hex, value_hex in pattern.findall(output):
        offset = int(offset_hex, 16)
        value = int(value_hex, 16)

        if not (0 <= value <= 255):
            continue

        if offset in values:
            duplicates.append(hex(offset))

        values[offset] = value

    if not values:
        return {
            "error": "No supported byte assignments found",
            "function": function_name,
        }

    # Group adjacent stack addresses into contiguous blocks.
    # Descending rbp-relative offsets correspond to ascending
    # addresses within the stack buffer.
    offsets = sorted(values, reverse=True)
    blocks = []
    current = []

    def finish_block(items):
        if not items:
            return
        blocks.append({
            "first_offset": hex(items[0]),
            "last_offset": hex(items[-1]),
            "count": len(items),
            "hex_bytes": bytes(values[x] for x in items).hex(),
        })

    for offset in offsets:
        if current and current[-1] - offset != 1:
            finish_block(current)
            current = []
        current.append(offset)

    finish_block(current)

    return {
        "function": function_name,
        "assignment_count": len(values),
        "duplicate_offsets": duplicates,
        "blocks": blocks,
        "note": (
            "Byte values are raw stored constants, not "
            "necessarily plaintext. Determine any transformation "
            "from the program logic."
        ),
    }
