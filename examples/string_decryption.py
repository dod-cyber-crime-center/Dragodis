# Tested with Ghidra 9.1.2 and IDA 7.4, 7.5

import os

import dragodis


EXAMPLE_BINARY = os.path.join(os.path.dirname(__file__), "strings.exe")
DECRYPT_CALLER_ADDR = 0x401030  # Address of the function that calls the decryption function on each string


# Simple xor cipher
def decrypt(data, key):
    return bytes(datum ^ key for datum in data)


def process(disassembler):
    func = disassembler.get_function_containing(DECRYPT_CALLER_ADDR)
    func_heads = func.get_heads()
    for head in func_heads:
        if disassembler.get_mnemonic_at(head) == "push":
            if disassembler.get_mnemonic_at(disassembler.next_head(head)) == "push":
                key = disassembler.get_operand_value(head, 0)
                enc_string_loc = disassembler.get_operand_value(disassembler.next_head(head), 0)
                enc_data = bytearray()

                next_byte = disassembler.get_byte(enc_string_loc)
                while next_byte != 0:
                    enc_data.append(next_byte)
                    enc_string_loc += 1
                    next_byte = disassembler.get_byte(enc_string_loc)
                enc_data = bytes(enc_data)

                print(f"key: {hex(key)}, encrypted data: {enc_data}")
                print(f"decrypted string: {decrypt(enc_data, key).decode('utf-8')}")


# # Run disassembler commands with IDA
# with dragodis.IDA(EXAMPLE_BINARY) as disassembler:
#     print("Start of IDA results")
#     process(disassembler)
#     print("End of IDA results")

# Run disassembler commands with Ghidra
with dragodis.Ghidra(EXAMPLE_BINARY) as disassembler:
    print("Start of Ghidra results")
    process(disassembler)
    print("End of Ghidra results")
