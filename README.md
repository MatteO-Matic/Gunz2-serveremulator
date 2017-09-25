# Gunz2-serveremulator
Unfinished private server to gunz 2, current code in python isn't written for being a private server, it's just to help furthering the research and reversing packets.

## Packet encryption/decryption unravel
### Grabbing the cryptkey
Packet encryption starts at 00EE4F5
```assembly
00EEF4F5  /$  55            PUSH EBP                                 ;  $Function WSASend 9 Encyption happens here
00EEF4F6  |.  8BEC          MOV EBP,ESP
00EEF4F8  |.  8A45 08       MOV AL,BYTE PTR [EBP+8]
00EEF4FB  |.  3245 0C       XOR AL,BYTE PTR [EBP+C]                                 ; xor with cryptkey
00EEF4FE  |.  8B49 24       MOV ECX,DWORD PTR [ECX+24]
00EEF501  |.  0FB6C0        MOVZX EAX,AL
00EEF504  |.  66:D3E0       SHL AX,CL                                ; Always shifts with 2
00EEF507  |.  0FB7C8        MOVZX ECX,AX
00EEF50A  |.  8BC1          MOV EAX,ECX
00EEF50C  |.  0FB6C9        MOVZX ECX,CL
00EEF50F  |.  C1E8 08       SHR EAX,8
00EEF512  |.  0BC1          OR EAX,ECX
00EEF514  |.  35 F0000000   XOR EAX,0F0
00EEF519  |.  5D            POP EBP
00EEF51A  \.  C2 0800       RET 8
```
Set a log breakpoint at 00EEF4FB where the function xor the next byte in the array with the cryptkey. Make sure the client send a packet with longer payload then 32 bytes to get the full key. (I'd recommend sending a chat message with bunch of a's).

Output of the cryptkey sample
```
\x57\x02\x5b\x04\xe1\x3c\x01\x08\x37\x0a\x12\x69\x41\x38\x0f\x78\x1b\x04\x24\x22\x43\x01\x49\x53\x50\x05\x13\x35\x4f\x02\x4d\x05
```

Bytes at position 4 and 5(e1,3c) is different for each new connection, the bytes are set by the initial packet when the connection are established.

### Packet header
#### Packet flags
### Initial packet
```
if gpacket.pid_name == "UF2C::NTF_CONNECT_UFS": # init packet
  seed = struct.unpack("!H", data[41:43])
  packet_crypt.init_cryptkey(seed[0])
```
To get the correct 2 bytes for the cryptkey grab the unsigned short(Big-Endian) from the initial packet "NTF_CONNECT_UFS" and xor it with a key \x34\x06.
I got the key through bruteforce.

```
def init_cryptkey(seed):
    cryptkey = "\x57\x02\x5B\x04\x00\x00\x01\x08\x37\x0A\x12\x69\x41\x38\x0F\x78\x1B\x04\x24\x22\x43\x01\x49\x53\x50\x05\x13\x35\x4F\x02\x4D\x05"
    key = "\x34\x06"
    xored = seed ^ struct.unpack("!H", key)[0]
    packed = struct.pack("!H", xored)
    cryptkey = cryptkey[:4] + packed + cryptkey[6:]
```

### Packet ID's and names
### Compression/Decompresstion
### Encyption translated into python
```python
def _encrypt(msgchar, cryptkey):
    newstring = ""
    for i, c in enumerate(msgchar):
        a = ord(c)
        a ^= ord(cryptkey[i % 32])
        a <<= 2
        b = a >> 8
        b |= (a & 0xFF)
        b ^= 0xF0

        newstring += (chr(b))

    return newstring
```
