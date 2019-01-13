"""recv """
#!/usr/bin/python
#pylint: disable=line-too-long,too-few-public-methods
import binascii
import re
import struct
import zlib
import string
import os

import packet_crypt
import gunz2packet


SERVERNAME = ('54.193.89.40', 20100)

class Options(object):
    """ Should contain settings how to handle the recived data

    c-like struct
    https://stackoverflow.com/questions/16722337/c-struct-python-equivalent
    """
    __slots__ = ["show_output", "show_data", "show_data_decrypted", "show_flags", "show_decrypted_text", "save_tofile", "emulate"]

    def __init__(self):
        self.show_output = 1
        self.show_data = 1
        self.show_data_decrypted = 1
        self.show_flags = 1
        self.show_decrypted_text = 1
        self.save_tofile = 1
        self.emulate = 0

def modrecv(self):
    """modrecv"""
    data = self.data
    options = Options()

    #sender = "server" if self.s.getpeername() == SERVERNAME else "client"
    is_server = 1 if self.s.getpeername() == SERVERNAME else 0

    # Put recv data in our packet class
    gpacket = gunz2packet.Gunz2Packet(data)

    options.show_data_decrypted = gpacket.flags.is_encrypted
    options.show_data = not gpacket.flags.is_encrypted #pylint: disable=redefined-variable-type

    if options.emulate:
        emulate_packet(self)

    #if gpacket.pid_name == "C2UF::REQ_LOGIN":
    #    self.data = ""
    #    return
    #if gpacket.pid_name == "UF2C::ACK_LOGIN":
    #    self.data = ""
    #    return
    if gpacket.pid_name == "UF2C::NTF_INFO":
        self.data = ""
        return
    if gpacket.pid_name == "UF2C::NTF_CHARACTERLIST":
        self.data = ""
        return
    if gpacket.pid_name == "UF2C::NTF_USER_CASH":
        self.data = ""
        return
    if gpacket.pid_name == "UF2C::NTF_OWN_SCENARIO_INFO":
        self.data = ""
        return
    if gpacket.pid_name == "UF2C::NTF_PLAYER_SETUP_DATAS":
        self.data = ""
        return
    if gpacket.pid_name == "UF2C::NTF_MAIL_LIST":
        self.data = ""
        return
    if gpacket.pid_name == "UF2C::NTF_OWN_ACHIEVEMENT_INFO":
        self.data = ""
        return
    if gpacket.pid_name == "UF2C::NTF_ITEM_INSTANCE_LIST":
        self.data = ""
        return
    #if gpacket.pid_name == "UF2C::NTF_CHANGE_STATE":
    #    self.data = ""
    #    return
    if gpacket.pid_name == "UF2C::NTF_CLAN_GET_CLANINFOS":
        self.data = ""
        return
    if gpacket.pid_name == "UF2C::NTF_CLAN_GET_CLANINVITES":
        self.data = ""
        return
    if gpacket.pid_name == "UF2C::NTF_FRIENDLIST":
        self.data = ""
        return
    if gpacket.pid_name == "C2UF::REQ_SELECT_CHARACTER":
        self.data = ""
        return
    if gpacket.pid_name == "UF2C::ACK_SELECT_CHARACTER":
        self.data = ""
        return
    if gpacket.pid_name == "UF2C::NTF_SELECT_CHARACTER":
        self.data = ""
        return
    if gpacket.pid_name == "UF2C::NTF_ITEM_INSTANCE_LIST":
        self.data = ""
        return
    if gpacket.pid_name == "C2UF::REQ_CHANGE_USERBLOB":
        self.data = ""
        return
    #if gpacket.pid_name == "UF2C::NTF_CHANGE_STATE":
    #    self.data = ""
    #    return
    if gpacket.pid_name == "UF2C::NTF_PARTY_INFO":
        self.data = ""
        return
    if gpacket.pid_name == "C2UF::REQ_EVENT_INFO":
        self.data = ""
        return
    if gpacket.pid_name == "UF2C::NTF_MISSION_CURRENT_LIST":
        self.data = ""
        return
    if gpacket.pid_name == "UF2C::NTF_DAILY_ATTEND_INFO":
        self.data = ""
        return
    if gpacket.pid_name == "UF2C::NTF_ITEM_INSTANCE_LIST":
        self.data = ""
        return
    if gpacket.pid_name == "UF2C::ACK_CHANGE_USERBLOB":
        self.data = ""
        return
    if gpacket.pid_name == "UF2C::ACK_EVENT_INFO":
        self.data = ""
        return
    if gpacket.pid_name == "C2UF::REQ_TESLA_MACHINE_LIST":
        self.data = ""
        return

    if gpacket.pid_name == "cmd::LOCAL::NTF_ACCEPT":
        options.show_output = 0
    elif gpacket.pid_name == "cmd::P2H::REQ_OBJECT_SYNC":
        options.show_output = 0

    if len(data) < 25:  # assume it's a keep alive packet
        pass
        # handle_ping(self)
    elif data[16:18] == '\x06\x00':  # NTF_AUTH_FAILED
        pass
    elif data[16:18] == '\x08\x00':  # Some initial from client
        pass
    elif data[16:18] == '\xfe\x10':  # NTF_MATCH_PLAYER_COUNT
        options.show_output = 0
    elif data[16:18] == '\xec\04':  # REQ_CHATTING_CHAT_CHANNEL
        pass
    elif data[16:18] == '\x24\x0e':
        pass
    elif data[16:18] == '\x1C\x0C':  # init packet (NTF_CONNECT_UFS)
        seed = struct.unpack("!H", data[41:43])
        packet_crypt.init_cryptkey(seed[0])
    else:
        pass

    if options.show_output:
        # Socket data
        socket_info = "SData | S:{0} | L:{1}".format(
            is_server,
            len(data))
        print(socket_info)

        # Header
        packet_header = "Hdata | Size:{2} | Counter:{3} | Checksum:{4:X} | PID: {1:X}({0})".format(
            gpacket.pid_name,
            gpacket.pid,
            gpacket.size,
            gpacket.counter,
            gpacket.checksum)

        print(packet_header)

        # Save pretty data to file
        pretty_data = ""

        # Print binary flags
        if options.show_flags:
            print_flags = "Flags | Normal:{0} | Ping:{1} | Encrypted:{2} | Compressed:{3} | AppSessionID:{4} | SenderID(S=13;C=9):{5} | Rand:{6} | SessionID:{7}".format(
                gpacket.flags.is_normal,
                gpacket.flags.is_ping,
                gpacket.flags.is_encrypted,
                gpacket.flags.is_compressed,
                gpacket.flags.app_session_id,
                gpacket.flags.sender_id,
                (gpacket.flags.rawflags >> 8) & 0xFF,
                (gpacket.flags.rawflags >> 16) & 0xFF
                #gpacket.flags.rand_seed
            )
            #self.session_id = (rawflags >> 5) & 0xFF
            print("{0:b}".format(gpacket.rawflags))
            print(print_flags)

        if options.show_data:
            # show header without decrypting
            print_hex(data[:20])
            print("-----")
            print_hex(data[20:])
            pretty_data = pretty_hex(data[20:])

        if options.show_data_decrypted:
            if packet_crypt.isInit:
                # show header without decrypting
                print_hex(data[:20])
                print("-----")
                cdata = packet_crypt.decrypt(data[20:])
                if gpacket.flags.is_compressed:
                    decdata = (zlib.decompress(cdata[4:]))
                    print_hex(decdata)
                    pretty_data = pretty_hex(decdata)
                else:
                    print_hex(cdata)
                    pretty_data = pretty_hex(cdata)
                # printing out payload
                # plength = struct.unpack("I", cdata[:4])
                # print (plength)

        if options.show_decrypted_text:
            if gpacket.flags.is_compressed:
                decdata = zlib.decompress(cdata[4:])

                print_plain = (
                    "".join((
                        c if (c in string.printable) else '.') for c in decdata))
                print(print_plain)
            else:
                # Don't include header
                print_plain = (
                    '\n' + packet_crypt.decrypt_printsafe(data[20:]))
                print(print_plain)

        print("\n")

        if options.save_tofile:
            if gpacket.flags.is_normal:
                pid_name_safe = re.sub('[^\w\-_\. ]', '_', gpacket.pid_name)
            else:
                pid_name_safe = "None"


            with open("out/orderinfo", 'a+') as f:
                f.write(pid_name_safe)
                f.write("\n")
#            while not os.path.isfile("out/{0}_{1}".format(pid_name_safe, i)):
                #i = i + 1
            with open("out/{0}".format(pid_name_safe), 'a+') as f:
                f.write("\n")
                f.write("\n")
                f.write(socket_info)
                f.write("\n")
                f.write(packet_header)
                f.write("\n")
                f.write("{0:b}".format(gpacket.rawflags))
                f.write("\n")
                f.write(print_flags)
                f.write("\n")
                f.write(pretty_hex(data[:20])) # header bytes
                f.write("\n-----\n")
                if pid_name_safe == "None":
                    f.write(pretty_hex(data))
                else:
                    f.write(pretty_data)
                f.write("\n")
                f.write(print_plain)
                f.write("\n")

def print_hex(data):
    """print out hex data in "AB CD EF" fashion"""
    _it = iter(binascii.b2a_hex(data))
    pdata = " ".join(a + b for a, b in zip(_it, _it))

    print_data = (re.sub("(.{60})", "\\1\n", pdata, 0, re.DOTALL))
    print(print_data)

def pretty_hex(data):
    """print out hex data in "AB CD EF" fashion"""
    _it = iter(binascii.b2a_hex(data))
    pdata = " ".join(a + b for a, b in zip(_it, _it))

    print_data = (re.sub("(.{60})", "\\1\n", pdata, 0, re.DOTALL))
    return print_data

def emulate_packet(self):
    """emulate_packet"""
    data = self.data

    pid = data[16:18]

    if pid == '\x05\x00':  # NTF_HOLEPUNCHING_RESULT
        self.data = "\x02\x00\x00\x00\x14\x00\x00\x00\x00\x98\x07\x00\x00\x00\x00\x00\x05\x00\x00\x00"
    elif pid == '\x07\x00': #NONE 007
        pass
    elif pid == '\xEC\x04': # REQ_CHATTING_CHAT_CHANNEL
        # self.da
        # calculate checksum
        print("------------")
        gpacket = gunz2packet.Gunz2Packet(data)
        checksum = calc_checksum(data[20:], gpacket.size)
        print("calc: {0:X} / {1:X}".format(checksum, gpacket.checksum))
        print("------------")
    else:
        pass


def calc_checksum(payload, packet_size):
    checksum = 0
    for c in payload:
        checksum += ord(c)
    return checksum - (packet_size + 1)

# def handle_ping(self):
#     data = self.data
#
#     # if sender == "client":
#     #     print "Client"
#     #     print (":".join("{:02x}".format(ord(c)) for c in data))
#     #   own packt
#     punknown = "\xa2\xd1\x27\xf3"
#     pisping = "\x18"
#     punknown2 = "\x00\x00\x00\x00\xf8\x3a\x0e"
#     pcounter = data[12:18]
#     punknown3 = "\x00\x00\x33\x43\x54\xd1"
#
#     pdata = punknown + pisping + punknown2 + pcounter + punknown3
#
#     # if(hex(ord(data[0])) == hex(ord(pdata[0]))):
#
#     if show_output:
#         print("Swapping to forged packet")
#         print(":".join("{:02x}".format(ord(c)) for c in pdata))
#         print("--->")
#         print(":".join("{:02x}".format(ord(c)) for c in data))
#         print("\n")
#     # self.data = pdata
