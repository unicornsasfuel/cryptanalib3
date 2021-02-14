import ca3 as ca

key = b'crypto'
message = b'originalmessage'

payload = b'originalmessage\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa8admin'

hmsg = ca.sha1(key + message)
extended = ca.sha1_extend(message, 6, b'admin', hmsg)

assert extended == ca.sha1(key + payload)

key = b'strawberry'
message = b'fields'

payload = b'fields\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00forever'

hmsg = ca.MD4(key + message).hexdigest()
extended = ca.md4_extend(message, 10, b'forever', hmsg)

# resetting the original chunks because python changes the state after calling once
assert extended == ca.MD4(key + payload, h=[ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476], size=0).hexdigest()

