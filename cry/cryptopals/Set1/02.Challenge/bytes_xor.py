def _byte_xor(a:bytes , b:bytes , quiet=True , check_lens=False) -> bytes:
    if not quiet:
        print(a, " xor " , b)
    if check_lens and len(a) != len(b):
        raise ValueError("bytestring lengths aren't equal")
    return bytes(byte1 ^ byte2 for byte1,byte2 in zip(a,b))

def bytes_xor(*args:bytes , quiet=True , check_lens=False):
    assert len(args) > 0
    result = args[0]
    for arg in args[1:]:
        result = _byte_xor(result , arg , quiet=quiet , check_lens=check_lens)
    return result

if __name__ == "__main__":
    a = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    b = bytes.fromhex("686974207468652062756c6c277320657965")
    result = bytes_xor(a,b , quiet=False)
    print(result)
    print(result.hex())

