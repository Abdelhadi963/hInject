#!/usr/bin/env python3
import argparse
import sys

def xor_encrypt(data: bytes, key: str) -> bytes:
    key_bytes = key.encode()
    key_len = len(key_bytes)
    return bytes([data[i] ^ key_bytes[i % key_len] for i in range(len(data))])

def generate_c_array(data: bytes, array_name="shellcode", output_file=None):
    lines = [f"unsigned char {array_name}[] = {{"]
    for i in range(0, len(data), 12):  # 12 bytes per line
        chunk = data[i:i+12]
        line = ", ".join(f"0x{b:02X}" for b in chunk)
        if i + 12 < len(data):
            line += ","
        lines.append("    " + line)
    lines.append("};")
    lines.append(f"size_t {array_name}_len = sizeof({array_name});")
    result = "\n".join(lines)
    
    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(result)
            print(f"[+] C array saved to: {output_file}")
        except Exception as e:
            print(f"[-] Error saving C array to file: {e}")
    else:
        print(result)

def generate_hex_shellcode(data: bytes) -> str: 
    print(f"[*] Size: {len(data)} bytes")
    return data.hex()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="shellcode_helper",
    )

    parser.add_argument("--file", "-f", required=True, help="Path to binary input file")
    parser.add_argument("--xor-key", help="Optional XOR key for encryption")
    parser.add_argument("--carray", action="store_true", help="Generate C-style shellcode array")
    parser.add_argument("--carray-out", help="Optional file path to save C array")
    parser.add_argument("--hexshellcode", action="store_true", help="Generate hex shellcode string")
    parser.add_argument("--binout", help="Write output as raw binary file")
    parser.add_argument("--array-name", default="shellcode", help="C array name (default: shellcode)")

    args = parser.parse_args()

    if(len(sys.argv)==1):
        parser.print_help()
        sys.exit(1)

    try:
        with open(args.file, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"[-] File not found: {args.file}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading file: {e}")
        sys.exit(1)

    if not data:
        print("[-] Error: Input file is empty.")
        sys.exit(1)

    # Optional XOR encryption
    if args.xor_key:
        data = xor_encrypt(data, args.xor_key)
        print(f"[+] Data encrypted with key: {args.xor_key}")

    # Output options
    if args.carray:
        generate_c_array(data, args.array_name, args.carray_out)

    if args.hexshellcode:
        print(generate_hex_shellcode(data))

    if args.binout:
        try:
            with open(args.binout, "wb") as f:
                f.write(data)
            print(f"[+] Binary output written to: {args.binout}")
        except Exception as e:
            print(f"[-] Error writing binary output: {e}")
            sys.exit(1)

    if not args.carray and not args.hexshellcode and not args.binout:
        print("[!] No action specified.\n")
        parser.print_help()
