#!/usr/bin/env python
# -*- coding: utf-8 -*-

from asyncio import get_event_loop
from random import randrange
from socket import AF_INET, SOCK_DGRAM, socket, timeout
from sys import argv
from time import sleep


SERVER_ADDR = "localhost"
ADDR_TO_CONNECT = "localhost"
PORT = 65530

CARBONARO_ENC_TABLE = dict(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "OPGTIVCHEJKRNMABQLZDUFWXYS"))
CARBONARO_DEC_TABLE = {v: k for k, v in CARBONARO_ENC_TABLE.items()}

AFFINE_ENCRYPT_A_VALUES = {}
for i in range (26):
    for j in range(26):
        if (i * j) % 26 == 1: # (a * dec_a) % 26 = 1
            AFFINE_ENCRYPT_A_VALUES[i] = j


class CryptedMessage:
    '''
    The encryption and decryption management.

    Message C struc:
    #define DIM_WORM 16
    #define DIM_MESSAGE 256
    struct message {
        uint8_t algoritm; // cesare_encrypt=0, ROT13=1, atbash=2, carbonaro=3, affine_encrypt=4, vigenere_encrypt=5, baconian_encrypt=6
        uint8_t a;
        uint8_t b;
        char worm[DIM_WORM+1];
        char mess[DIM_MESSAGE+1];
    }
    C struct message size: 1 + 1 + 1 + 17 (16+1) + 257 (256+1) = 277
    '''
    algoritm = 0
    a = 0
    b = 0
    worm = b""
    mess = b"" # Encrypted message


    def __init__(self, message_bytes=None):
        '''
        '''
        if message_bytes:
            self.algoritm = int.from_bytes(message_bytes[0:1], "big")
            self.a = int.from_bytes(message_bytes[1:2], "big")
            self.b = int.from_bytes(message_bytes[2:3], "big")
            self.worm = message_bytes[3:20].replace(b"\0", b"")
            self.mess = message_bytes[20:277]


    def encrypt(self, msg:str):
        '''
        '''
        self.mess = b""

        # cesare_encrypt
        if self.algoritm == 0:
            for c in msg:
                if c.islower():
                    crypted_ord = ord('a') + (ord(c) - ord('a') + 3) % 26
                elif c.isupper():
                    crypted_ord = ord('A') + (ord(c) - ord('A') + 3) % 26
                else:
                    crypted_ord = 95 # '_'
                self.mess += chr(crypted_ord).encode("utf-8")
        # ROT13
        elif self.algoritm == 1:
            for c in msg:
                if c.islower():
                    crypted_ord = ord('a') + (ord(c) - ord('a') + 13) % 26
                elif c.isupper():
                    crypted_ord = ord('A') + (ord(c) - ord('A') + 13) % 26
                else:
                    crypted_ord = 95 # '_'
                self.mess += chr(crypted_ord).encode("utf-8")
        # adbash
        elif self.algoritm == 2:
            for c in msg:
                if c.islower():
                    crypted_ord = ord('a') + (ord('z') - ord(c)) % 26
                elif c.isupper():
                    crypted_ord = ord('A') + (ord('Z') - ord(c)) % 26
                else:
                    crypted_ord = 95 # '_'
                self.mess += chr(crypted_ord).encode("utf-8")
        # carbonaro
        elif self.algoritm == 3:
            for c in msg:
                if c.islower():
                    crypted_c = CARBONARO_ENC_TABLE[c.upper()].lower()
                elif c.isupper():
                    crypted_c = CARBONARO_ENC_TABLE[c]
                else:
                    crypted_c = '_'
                self.mess += crypted_c.encode("utf-8")
        # affine_encrypt
        if self.algoritm == 4:
            for c in msg:
                if c.islower():
                    crypted_ord = ord('a') + (self.a * (ord(c) - ord('a')) + self.b) % 26
                elif c.isupper():
                    crypted_ord = ord('A') + (self.a * (ord(c) - ord('A')) + self.b) % 26
                else:
                    crypted_ord = 95 # '_'
                self.mess += chr(crypted_ord).encode("utf-8")
        # vigenere_encrypt
        elif self.algoritm == 5:
            msg = msg.upper()
            worm = self.worm.upper()
            for i, c in enumerate(msg):
                if c.isupper():
                    crypted_ord = ord('A') + (ord(c) - ord('A') + worm[i%len(worm)]) % 26
                else:
                    crypted_ord = 95 # '_'
                self.mess += chr(crypted_ord).encode("utf-8")
        # baconian_encrypt
        if self.algoritm == 6:
            msg = msg.upper()
            for c in msg:
                if c.isupper():
                    crypted_ord = ord(c) - ord('A')
                else:
                    crypted_ord = 95 - ord('A') # '_'
                self.mess += f"{crypted_ord:05b}".replace("0", "a").replace("1", "b").encode("utf-8")


    def decrypt(self)->str:
        '''
        '''
        decrypted_msg = ""

        # cesare_encrypt
        if self.algoritm == 0:
            for c_ord in self.mess:
                if ord('a') <= c_ord <= ord('z'):
                    decrypted_ord = ord('a') + (c_ord - ord('a') - 3) % 26
                elif ord('A') <= c_ord <= ord('Z'):
                    decrypted_ord = ord('A') + (c_ord - ord('A') - 3) % 26
                elif c_ord != 0:
                    decrypted_ord = 95 # '_'
                if c_ord > 0:
                    decrypted_msg += chr(decrypted_ord)
        # ROT13
        elif self.algoritm == 1:
            for c_ord in self.mess:
                if ord('a') <= c_ord <= ord('z'):
                    decrypted_ord = ord('a') + (c_ord - ord('a') - 13) % 26
                elif ord('A') <= c_ord <= ord('Z'):
                    decrypted_ord = ord('A') + (c_ord - ord('A') - 13) % 26
                elif c_ord != 0:
                    decrypted_ord = 95 # '_'
                if c_ord > 0:
                    decrypted_msg += chr(decrypted_ord)
        # adbash
        if self.algoritm == 2:
            for c_ord in self.mess:
                if ord('a') <= c_ord <= ord('z'):
                    decrypted_ord = ord('a') + (ord('z') - c_ord) % 26
                elif ord('A') <= c_ord <= ord('Z'):
                    decrypted_ord = ord('A') + (ord('Z') - c_ord) % 26
                elif c_ord != 0:
                    decrypted_ord = 95 # '_'
                if c_ord > 0:
                    decrypted_msg += chr(decrypted_ord)
        # carbonaro
        if self.algoritm == 3:
            for c_ord in self.mess:
                if ord('a') <= c_ord <= ord('z'):
                    decrypted_c = CARBONARO_DEC_TABLE[chr(c_ord).upper()].lower()
                elif ord('A') <= c_ord <= ord('Z'):
                    decrypted_c = CARBONARO_DEC_TABLE[chr(c_ord)]
                elif c_ord != 0:
                    decrypted_c = '_'
                if c_ord > 0:
                    decrypted_msg += decrypted_c
        # affine_encrypt
        if self.algoritm == 4:
            dec_a = AFFINE_ENCRYPT_A_VALUES[self.a] # dec_letter = dec_a * (enc_letter - b)
            for c_ord in self.mess:
                if ord('a') <= c_ord <= ord('z'):
                    decrypted_ord = ord('a') + dec_a * ((c_ord - ord('a')) - self.b) % 26
                elif ord('A') <= c_ord <= ord('Z'):
                    decrypted_ord = ord('A') + dec_a * ((c_ord - ord('A')) - self.b) % 26
                elif c_ord != 0:
                    decrypted_ord = 95 # '_'
                if c_ord > 0:
                    decrypted_msg += chr(decrypted_ord)
        # vigenere_encrypt
        elif self.algoritm == 5:
            worm = self.worm.upper()
            for i, c_ord in enumerate(self.mess):
                if ord('A') <= c_ord <= ord('Z'):
                    decrypted_ord = ord('A') + (c_ord - ord('A') - worm[i%len(worm)]) % 26
                elif c_ord != 0:
                    decrypted_ord = 95 # '_'
                if c_ord > 0:
                    decrypted_msg += chr(decrypted_ord)
        # baconian_encrypt
        if self.algoritm == 6:
            crypted_msg = self.mess.replace(b"\0", b"")
            c_bin_ords = [crypted_msg[i: i+5] for i in range(0, len(crypted_msg), 5)]
            for c_bin_ord in c_bin_ords:
                decrypted_msg += chr(ord('A') + int(c_bin_ord.replace(b"a", b"0").replace(b"b", b"1"), 2))

        return decrypted_msg


    def get_bytes(self)->str:
        '''
        '''
        message_bytes = self.algoritm.to_bytes(1, "big")
        message_bytes += self.a.to_bytes(1, "big")
        message_bytes += self.b.to_bytes(1, "big")
        message_bytes += self.worm + b"\0"*(17-len(self.worm))
        message_bytes += self.mess + b"\0"*(257-len(self.mess))
        return message_bytes


class ServerProtocol():
    '''
    '''
    transport = None


    def connection_made(self, transport):
        '''
        '''
        self.transport = transport


    def datagram_received(self, message_bytes, addr):
        '''
        '''
        message = CryptedMessage(message_bytes)
        decrypted_message = message.decrypt()
        print(f"Received {decrypted_message} from {addr}")
        response = CryptedMessage()
        response.algoritm = message.algoritm
        response.a = message.a
        response.b = message.b
        response.worm = message.worm
        response.encrypt(decrypted_message+" ok")
        self.transport.sendto(response.get_bytes(), addr)


if __name__ == '__main__':
    print()
    print("Flags:")
    print("-s\t\truns the server")
    print("-h IP_ADDRESS\truns the client connecting to IP_ADDRESS")
    print("-l \t\tintroduces a delay of 200ms between calls for slow server")
    print("Without -h flag runs client connecting to localhost")
    print()

    run_server = "-s" in argv

    if "-h" in argv:
        ind = argv.index("-h")
        ADDR_TO_CONNECT = argv[ind+1]

    slows = "-l" in argv

    if run_server: # Server
        loop = get_event_loop()
        print("Starting UDP server")
        print("Press ^C to terminate")

        listen = loop.create_datagram_endpoint(ServerProtocol, (SERVER_ADDR, PORT))
        transport, protocol = loop.run_until_complete(listen)

        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass

        transport.close()
        loop.close()

    else: # Client
        algoritms = {
            0: "cesare_encrypt",
            1: "ROT13",
            2: "adbash",
            3: "carbonaro",
            4: "affine_encrypt",
            5: "vigenere_encrypt",
            6: "baconian_encrypt",
        }

        addr = (ADDR_TO_CONNECT, PORT)

        msg_sent = "Ciao Ragazzo"
        message = CryptedMessage()
        a_values = list(AFFINE_ENCRYPT_A_VALUES.keys())
        message.a = a_values[randrange(len(a_values))]
        message.b = randrange(10)
        message.worm = b"CRIPTO"

        for i, a in algoritms.items():
            client = socket(AF_INET, SOCK_DGRAM)
            client.settimeout(1.0)

            message.algoritm = i
            message.encrypt(msg_sent)

            message_bytes = message.get_bytes()

            # print(message_bytes)
            client.sendto(message_bytes, addr)
            try:
                response_bytes, server = client.recvfrom(277)
                response_message = CryptedMessage(response_bytes)
                print(f"{a}: {msg_sent} -> {response_message.decrypt()}")
            except timeout:
                print(f"{a}: REQUEST TIMED OUT")
                print(message_bytes)
            client.close()

            if slows:
                sleep(.2)
