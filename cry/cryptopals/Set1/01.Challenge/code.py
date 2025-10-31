import base64
text = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
b16d = base64.b16decode(text , casefold=True)
b64 = base64.b64encode(b16d)
print(b64.decode())

