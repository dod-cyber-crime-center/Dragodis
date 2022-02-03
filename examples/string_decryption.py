# Tested with Ghidra 9.1.2 and IDA 7.4, 7.5

import dragodis


DECRYPT_CALLER_ADDR = 0x401030  # Address of the function that calls the decryption function on each string


# Simple xor cipher
def decrypt(data, key):
    return bytes(datum ^ key for datum in data)


def process(dis):
    func = dis.get_function(DECRYPT_CALLER_ADDR)
    key = None
    for insn in func.instructions():
        if insn.mnemonic != "push":
            key = None
            continue

        if not key:
            key = insn.operands[0].value
            continue

        enc_string_addr = insn.operands[0].value
        print(hex(insn.address), hex(enc_string_addr))
        enc_string = dis.get_string_bytes(enc_string_addr, bit_width=8)
        if enc_string is None or key is None:
            print(repr(enc_string), repr(key))
        dec_string = decrypt(enc_string, key).decode("utf-8")

        print(f"key: {hex(key)}, encrypted data: {repr(enc_string)}")
        print(f"decrypted string: {dec_string}")
        key = None  # clear for next round.


if __name__ == "__main__":
    # Run script with whichever disassembler user has set up.
    with dragodis.open_program("strings.exe") as dis:
        print(f"Start of {dis.name}")
        process(dis)
        print(f"End of {dis.name} results")
