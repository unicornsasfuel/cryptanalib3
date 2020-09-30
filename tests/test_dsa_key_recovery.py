import ca3 as ca
from binascii import unhexlify

r = unhexlify(hex(2584600559599262630013650841090856)[2:])
sig1 = unhexlify(hex(3270745407167110613002216741426642)[2:])
sig2 = unhexlify(hex(1024704976491997075830153512952688)[2:])

results = ca.dsa_repeated_nonce_attack(r,b"foobar",sig1,b"foobaz",sig2,0xdb7c2abf62e35e7628dfac6561c5, verbose=True)
if results != (0x1e240,0x12345):
   raise Exception('ECDSA repeated nonce private key recovery is broken.')

msg1 = b"Students reported that students post to discussion forums more frequently and are irrevocable provided the stated conditions are met."
msg2 = b"But is this enough? And what new threats could be using it as a friend or fan.[2]"
r = unhexlify("a0289c0fa7e87f1ab1e94b577f43691ebd70c04b0e62ca7eaaf1791983d512e7bbc843ee3a2a0430455e9f755f832ccd")
s1 = unhexlify("cd7a46d769ee43467a01453214868094ca228cb5eebc953a39fb9bbaf865f4dbe1dad9b5f9f1bed75671e0db5433f0ed")
s2 = unhexlify("54d4f8306fe11bd4a28a491ddf596c64cd98c93d7fa9a05acead17e42e96ed1a190a2fddd7c695b8d9bce43f221b4e1b")
n = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643

results = ca.dsa_repeated_nonce_attack(r,msg1,s1,msg2,s2,n,verbose=True)
if results != (0x24185d3e943536f3f9b886b60361fc94ddddffd5a7b1bad57dfcf000912408756ed638e38e38e38e38e38e38e38e38e3,0x63683073336e5f62795f663469725f646963655f726f6c6c5f677572616e743333645f746f5f62655f72406e64306d):
   raise Exception('ECDSA repeated nonce private key recovery is broken.')
