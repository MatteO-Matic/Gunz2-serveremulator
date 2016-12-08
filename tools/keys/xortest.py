#!/usr/bin/python
import sys
import select

def xor(data, key): 
    return bytearray(a^b for a, b in zip(*map(bytearray, [data, key])))


message = "abcde"
secret = "\x97\xfb\xae\xfa\xfe\x0b\x02\x93\x9f\x1f\xb7V\xd3\x0f\xde\xcf\xaf\x13\xa7\x0f\xcf\x13\xff\x0bp\xea\x96"



decrypted = xor(message,secret)

print bytearray(b"decrypted")



back = xor(decrypted, secret)
print back


#>>> one_time_pad = 'shared secret' 
#>>> plaintext = 'unencrypted' 
#>>> ciphertext = xor(plaintext, one_time_pad) 
#>>> ciphertext 
#bytearray(b'\x06\x06\x04\x1c\x06\x16Y\x03\x11\x06\x16') 
#>>> decrypted = xor(ciphertext, one_time_pad) 
#>>> decrypted
#bytearray(b'unencrypted')
#>> plaintext == str(decrypted)
#True