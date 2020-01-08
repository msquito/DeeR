# H Ryan Harasimowicz | 9421622 | 2016.10.23
# css539 Security in Emerging Environments | Dr. Lagesse
# code adapted from 
# css 527 Cryptography and Data Assurance | Dr. Lagesse
# triple DES implementation
# note - taught myself python with this assignment, please forgive the spaghetti...

# imports
import argparse
import psutil


import copy
import time
import hashlib
import random
from bitstring import BitArray
from enum import Enum

# enum block chaining modes
class DESMode(Enum):
    ECB = 0
    CBC = 1
    CTR = 2

# enum functions
class DESFunction(Enum):
    encrypt = 0
    decrypt = 1

# PC1 permutation table
_PC1 = (57, 49, 41, 33, 25, 17, 9,
        1,  58, 50, 42, 34, 26, 18,
        10, 2,  59, 51, 43, 35, 27,
        19, 11, 3,  60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7,  62, 54, 46, 38, 30, 22,
        14, 6,  61, 53, 45, 37, 29,
        21, 13, 5,  28, 20, 12, 4)

# PC2 permutation table
_PC2 = (14, 17, 11, 24, 1,  5,
        3,  28, 15, 6,  21, 10,
        23, 19, 12, 4,  26, 8,
        16, 7,  27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32 )

# Key schedule rotations
_KSR = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

# Initial permutation table
_IP = ( 58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7 )

# Expansion permutation table
_EP = ( 32, 1,  2,  3,  4,  5,
        4,  5,  6,  7,  8,  9,
        8,  9,  10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1 )

# P permutation table
_PF = ( 16, 7,  20, 21, 29, 12, 28, 17,
        1,  15, 23, 26, 5,  18, 31, 10,
        2,  8,  24, 14, 32, 27, 3,  9,
        19, 13, 30, 6,  22, 11, 4,  25 )

# final permutation table
_FP = ( 40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41,  9, 49, 17, 57, 25 )

# S box tables
_SB = 8 * [64 * [0]]

_SB[0] = (14, 4,  13, 1, 2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0, 7,  # 00    0
          0,  15, 7,  4, 14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3, 8,  # 01    1
          4,  1,  14, 8, 13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5, 0,  # 10    2
          15, 12, 8,  2, 4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6, 13) # 11    3

_SB[1] = (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
           3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
           0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
           13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9)

_SB[2] = (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
           13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
           13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
           1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12)

_SB[3] = (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
           13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
           10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
           3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14)

_SB[4] = (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
           14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
           4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
           11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3)

_SB[5] = (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
           10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
           9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
           4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13)

_SB[6] = (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
           13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
           1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
           6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12)

_SB[7] = (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
           1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
           7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
           2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11)

# PC1 permutation
def PC1 (_keyPre):
    _keyPost = BitArray(bytes=8)
    for index, item in enumerate(_PC1, start=0):
        _keyPost[index] = _keyPre[item-1]
    del _keyPost[-8:]
    return _keyPost

# PC2 permutation
def PC2 (_keyPre):
    _keyPost = BitArray(bytes=7)
    for index, item in enumerate(_PC2, start=0):
        _keyPost[index] = _keyPre[item-1]
    return _keyPost

# Initial permutation
def IP (_pTextPre):
    # initial permutation
    _pTextPost = BitArray(bytes=8)
    for index, item in enumerate(_IP, start=0):
        _pTextPost[index] = _pTextPre[item-1]
    return _pTextPost

# Expansion permutation
def EP (_bits32):
    # print("_bits32:", _bits32)
    _bits48 = BitArray(bytes=6)
    for index, item in enumerate(_EP, start=0):
        _bits48[index] = _bits32[item-1]

    # print("_bits48:", _bits48)
    return _bits48

# Final permutation
def FP (_bits64_pre):
    _bits64_post = BitArray(bytes=8)
    for index, item in enumerate(_FP, start=0):
        _bits64_post[index] = _bits64_pre[item-1]
    return _bits64_post

# Sbox substitutions
def SB (_splits):
    sub32 = BitArray(bytes=4)
    sub4 = BitArray(bin='0000')
    # for each sBox
    for index, item in enumerate (_SB, start=0):
        # print(index)
        # print(_splits[index])
        bitFront = _splits[index][0]
        bitRear = _splits[index][5]
        bitBracket = BitArray(bin='00')
        bitBracket[0] = bitFront
        bitBracket[1] = bitRear

        bitMid = _splits[index][1:5]

        index_SB = (bitBracket.uint * 16) + bitMid.uint
        sub4 = _SB[index][index_SB]
        sub32 [(index * 4):(index * 4)+4] = sub4

        # print("f: ", bitFront)
        # print("r: ", bitRear)
        # print(bitBracket)
        # print(bitBracket.uint)
        # print(bitMid.bin)
        # print(bitMid.uint)
        # print()
        # print("ISB: ", index_SB)
        # print("val: ", bin(sub4))
        # print("32: ", sub32.bin)
        # print()

    return sub32

# P permutation
def PF (_bits32):
    spunSub32 = BitArray(bytes=4)
    for index, item in enumerate(_PF, start=0):
        spunSub32[index] = _bits32[item-1]
    return spunSub32

# read data in from file return as BitArray
def inputFromFile(_file):
    f = open(_file, 'rb')
    inputBits = BitArray(f)
    # print("iBHex: ",inputBits.hex)
    # print("iBBin - len: ", len(inputBits),inputBits.bin)
    return inputBits

# wrapper for tripleDES
def tripleDESWrapper(_input, _function, _mode):
    if _mode == "ECB":
        chainingMode = DESMode.ECB
    elif _mode == "CBC":
        chainingMode = DESMode.CBC
    elif _mode == "CTR":
        chainingMode = DESMode.CTR
    else:
        print("error - invalid chaining mode, please select from 'ECB', 'CBC' or 'CTR'")
        exit()

    pText_bits = inputFromFile(_input)

    if _function == DESFunction.encrypt:
        pkcs5_encode(pText_bits)
        cipher = tripleDES(pText_bits, _function, chainingMode)

    if _function == DESFunction.decrypt:
        cipher = tripleDES(pText_bits, _function, chainingMode)
        pkcs5_decode(cipher)

    return cipher

# tripleDES for ECB, CBC and CTR modes - returns a cipher string
def tripleDES(_inboundBits, _function, _mode):

    pText_chunks = plainText_split(_inboundBits)

    cText_chunks = []


    # chaining mode ECB
    if _mode == DESMode.ECB:
        for index, item in enumerate(pText_chunks, start=0):
            if _function == DESFunction.encrypt:
                chunk00 = FP(copy.copy(Feistel(pText_chunks[index], keySchedule_01, DESFunction.encrypt)))
                chunk01 = FP(copy.copy(Feistel(chunk00, keySchedule_02, DESFunction.decrypt)))
                chunk02 = FP(copy.copy(Feistel(chunk01, keySchedule_03, DESFunction.encrypt)))
            elif _function == DESFunction.decrypt:
                chunk00 = FP(copy.copy(Feistel(pText_chunks[index], keySchedule_03, DESFunction.decrypt)))
                chunk01 = FP(copy.copy(Feistel(chunk00, keySchedule_02, DESFunction.encrypt)))
                chunk02 = FP(copy.copy(Feistel(chunk01, keySchedule_01, DESFunction.decrypt)))

            cText_chunks.append(chunk02)


    # chaining mode CBC
    elif _mode == DESMode.CBC:
        if _function == DESFunction.encrypt:
            initVect = IV()
            initVectBA = BitArray(bin(initVect))
            del initVectBA[64:]

            for index, item in enumerate(pText_chunks, start=0):
                if index == 0:
                    chunk00 = FP(copy.copy(Feistel((initVectBA ^ pText_chunks[index]), keySchedule_01, DESFunction.encrypt)))
                    chunk01 = initVectBA ^ (FP(copy.copy(Feistel(chunk00, keySchedule_02, DESFunction.decrypt))))
                    chunk02 = FP(copy.copy(Feistel((initVectBA ^ chunk01), keySchedule_03, DESFunction.encrypt)))

                    cText_chunks.append(chunk02)
                else:
                    chunk00 = FP(copy.copy(Feistel((cText_chunks[index-1] ^ pText_chunks[index]), keySchedule_01, DESFunction.encrypt)))
                    chunk01 = pText_chunks[index-1] ^ (FP(copy.copy(Feistel(chunk00, keySchedule_02, DESFunction.decrypt))))
                    chunk02 = FP(copy.copy(Feistel((cText_chunks[index-1] ^ chunk01), keySchedule_03, DESFunction.encrypt)))

                    cText_chunks.append(chunk02)

            # insert IV into cipher
            cText_chunks.insert(0, initVectBA)

        # note cTex in decrypt = plaintext and pText = cipherText
        elif _function == DESFunction.decrypt:
            # # peel original IV out of the cipher (first 64 bits)
            initVectBA = pText_chunks.pop(0)

            for index, item in enumerate(pText_chunks, start=0):
                if index == 0:
                    chunk00 = initVectBA ^ (FP(copy.copy(Feistel(pText_chunks[index],    keySchedule_03, DESFunction.decrypt))))
                    chunk01 = FP(copy.copy(Feistel((initVectBA ^ chunk00), keySchedule_02, DESFunction.encrypt)))
                    chunk02 = initVectBA ^ (FP(copy.copy(Feistel(chunk01,                keySchedule_01, DESFunction.decrypt))))

                    cText_chunks.append(chunk02)
                else:
                    chunk00 = pText_chunks[index-1] ^ (FP(copy.copy(Feistel(pText_chunks[index],    keySchedule_03, DESFunction.decrypt))))
                    chunk01 = FP(copy.copy(Feistel((cText_chunks[index-1] ^ chunk00), keySchedule_02, DESFunction.encrypt)))
                    chunk02 = pText_chunks[index-1] ^ (FP(copy.copy(Feistel(chunk01,                keySchedule_01, DESFunction.decrypt))))

                    cText_chunks.append(chunk02)


    # chaining mode CTR
    elif _mode == DESMode.CTR:
        ctr = BitArray(bytes=4)
        nonceMutation = BitArray(bytes=8)

        # set and anchor nonce for encrypt
        if _function == DESFunction.encrypt:
            initVect = IV()
            initVectBA = BitArray(bin(initVect))
            del initVectBA[32:]
            nonceMutation[:32] = initVectBA

        # get nonce for decrypt
        elif _function == DESFunction.decrypt:
            nonceMutation = pText_chunks.pop(0)

        # encrypt & ^ input
        for index, item in enumerate(pText_chunks, start=0):
            ctr.uint = index
            nonceMutation[32:] = ctr
            # note for CTR mode, it is DESFunction.encrypt for both encrypt and decrypt as it's just against the mutated nonce
            if _function == DESFunction.encrypt:
                chunk00 = item ^ FP(copy.copy(Feistel(nonceMutation, keySchedule_01, DESFunction.encrypt)))
                chunk01 = chunk00 ^ FP(copy.copy(Feistel(nonceMutation, keySchedule_02, DESFunction.encrypt)))
                chunk02 = chunk01 ^ FP(copy.copy(Feistel(nonceMutation, keySchedule_03, DESFunction.encrypt)))

                cText_chunks.append(chunk02)
            elif _function == DESFunction.decrypt:
                chunk00 = item ^ FP(copy.copy(Feistel(nonceMutation, keySchedule_03, DESFunction.encrypt)))
                chunk01 = chunk00 ^ FP(copy.copy(Feistel(nonceMutation, keySchedule_02, DESFunction.encrypt)))
                chunk02 = chunk01 ^ FP(copy.copy(Feistel(nonceMutation, keySchedule_01, DESFunction.encrypt)))

                cText_chunks.append(chunk02)

        if _function == DESFunction.encrypt:
            nonceMutation[-32:] = '0x00000000'
            cText_chunks.insert(0, nonceMutation)

    cipher = cipherConcat(cText_chunks)
    return cipher

# string together list of BitArrays
def cipherConcat (_input):
    cipherText = BitArray(bytes=0)
    for cipherChunk in _input:
        cipherText += cipherChunk

    return cipherText

# return 128-bit initialization vector
def IV():
    random.seed(a=None, version=2)
    # python onboard PRNG - not CRNG
    initializationVector = random.getrandbits(128)

    return initializationVector

# split 48bits into (8) 6bit words
def Feistel_split(_xEK):
    _xEK_chunks6 = []
    for i in range(8):
        tempBits = _xEK[(i*6):(i*6) + 6]
        _xEK_chunks6.append(copy.copy(tempBits))
    return _xEK_chunks6

# single round of Feistel function
def Feistel_round (_pText, _key):
    pT32_L = _pText[:32]
    pT32_R = _pText[32:]

    # expansion permutation
    ePT48_R = EP(pT32_R)

    # round key addition
    xEK = ePT48_R ^ _key

    # sBox substitution
    # split right side
    SB_splits = Feistel_split(xEK)
    sub32_R = SB(SB_splits)
    subPerm32_R = PF(sub32_R)

    # left addition
    xLSPR = pT32_L ^ subPerm32_R

    # L(i+1) = R(i), R(i +1) = L(i) ^ f(R(i))
    output = BitArray(bytes=8)
    output[:32] = pT32_R
    output[32:] = xLSPR

    return output

# 16 rounds of Feistel...
def Feistel (_pText_chunk, _keySchedule, _function):
    _input = copy.copy(IP(_pText_chunk))

    # encrypt plaintext
    if _function == DESFunction.encrypt:
        for key in _keySchedule:
            _input = Feistel_round(_input, key)

    # decrypt ciphertext
    elif _function == DESFunction.decrypt:
        for key in reversed(_keySchedule):
            _input = Feistel_round(_input, key)

    output = BitArray(bytes=8)
    output[:32] = _input[32:]
    output[32:] = _input[:32]

    return output

# rotations for generating key schedule
def keySched_rotate(_round, _bytesIn):
    tempBit0 = _bytesIn[0]
    tempBit1 = _bytesIn[1]
    _bytesOut = _bytesIn
    _bytesOut <<= _KSR[_round]
    _bytesOut[-1] = tempBit0
    if (_KSR[_round] == 2):
        _bytesOut[-2] = tempBit0
        _bytesOut[-1] = tempBit1
    return _bytesOut

# generate keyschedule list from key
def keySched_generate(_bytesIn):
    C0 = copy.copy(_bytesIn[:28])
    D0 = copy.copy(_bytesIn[28:])
    Keys = []
    for x in _KSR:
        C0 = keySched_rotate(x, C0)
        D0 = keySched_rotate(x, D0)
        Keys.append(PC2(C0+D0)[:48])
    return Keys

# generate keyfile from password
def keyFile_generate(_password, _keyFile):
    salt = "I ate what???"
    bPassword = _password.encode('utf-8')
    bSalt = salt.encode('utf-8')
    iterations = 100000
    algo = 'sha256'

    key = hashlib.pbkdf2_hmac(algo, bPassword, bSalt, iterations)
    a = BitArray(bytes=key)

    # outputs key string to keyfile as single 192-bit string
    keyFile = open(_keyFile, 'w')
    keyFile.write(a.bin[:192])
    keyFile.close()

# generate key-schedule from 192 bit key file
def keySched(_keyS_01, _keyS_02, _keyS_03, _keyFile):

    #imports keys from 'keyFile.txt'
    # puts each subkey into a list
    keyRead = open(_keyFile, 'r')
    keysImportString = keyRead.readline()
    if len(keysImportString) != 192:
        print("key file improperly formatted, expect 192 bit binary")
        exit()
    keysImportBA = BitArray(bin=keysImportString)
    if diagnosticMode:
        key64_01 = BitArray(bin='0000000100100011010001010110011110001001000000010010001101000101')
    else:
        key64_01 = keysImportBA[:64]
    key64_02 = keysImportBA[64:128]
    key64_03 = keysImportBA[128:192]
    keyRead.close()

    key_01_PC1 = PC1(key64_01)
    key_02_PC1 = PC1(key64_02)
    key_03_PC1 = PC1(key64_03)

    _keyS_01.extend(keySched_generate(key_01_PC1))
    _keyS_02.extend(keySched_generate(key_02_PC1))
    _keyS_03.extend(keySched_generate(key_03_PC1))

# pad non 8-bit increments
def pkcs5_encode (_input_bytes):
    padding_length = 64-(len(_input_bytes) % 64)

    padding_byteDec = int(padding_length/8)
    padding_byte = BitArray(int = padding_byteDec, length=8)
    for x in range (padding_byteDec):
        _input_bytes += padding_byte

# strip padding out
def pkcs5_decode (_input_bytes):
    padding_byte = _input_bytes[-8:]
    padding_length = padding_byte.int * 8
    del _input_bytes [-padding_length:]

# split string into list of BitArrays
def plainText_split (_input_bytes):
    byteChunks = []
    byteCount = int(len(_input_bytes)/64)

    for i in range(byteCount):
        tempByte = _input_bytes[(i*64):(i*64) + 64]
        byteChunks.append(copy.copy(tempByte))

    return byteChunks

# main function
if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    # genkey parsers
    genkey_parser = subparsers.add_parser("genkey")
    genkey_parser.add_argument("password", help="enter password string")
    genkey_parser.add_argument("keyFile", help="define output key file")
    genkey_parser.set_defaults(function = "genkey")

    # encrypt parsers
    encrypt_parser = subparsers.add_parser("encrypt")
    encrypt_parser.add_argument("inputFile", help="define plaintext file to be encrypted")
    encrypt_parser.add_argument("keyFile", help="define key file")
    encrypt_parser.add_argument("outputFile", help="define ciphertext file to be output")
    encrypt_parser.add_argument("mode", help="define block chaining mode")
    encrypt_parser.set_defaults(function = "encrypt")

    #decrypt parsers
    decrypt_parser = subparsers.add_parser("decrypt")
    decrypt_parser.add_argument("inputFile", help="define ciphertext file to be decrypted")
    decrypt_parser.add_argument("keyFile", help="define key file")
    decrypt_parser.add_argument("outputFile", help="define output file to be written")
    decrypt_parser.add_argument("mode", help="define block chaining mode")
    decrypt_parser.set_defaults(function = "decrypt")

    # diagnosticMode defaults key/plainText to abcdefgh/0123456789012345
    # for ease of comparison with website http://www.cs.bham.ac.uk/research/projects/lemsys/DES/DESPage.jsp
    diagnosticMode = 0

    keySchedule_01 = []
    keySchedule_02 = []
    keySchedule_03 = []



    results = open('results.txt', 'w')
    inputFile = 'Dune.txt'
    cTextFile = 'HRH_cypherText.txt'
    outputFile = 'checkFile.txt'
    keyFile_generate("passwordString", 'keyfile.txt')
    
    
    
    cpu0 = "cpuUsage0:" + str(psutil.cpu_percent())
    mem0 = "memUsage0:" + str(psutil.virtual_memory()) + '\n\n'
    results.write("cpu0: " + cpu0 + " mem0: " + mem0)
	
    args = parser.parse_args()

    if args.function == "genkey":
        print("generating key...")
        keyFile_generate(args.password, args.keyFile)
	


    for i in range(5):
        print("encrypting file...")
        
        start = time.perf_counter()
        keySched(keySchedule_01, keySchedule_02, keySchedule_03, 'keyfile.txt')
        cText = tripleDESWrapper(inputFile, DESFunction.encrypt, 'ECB')
        fileOut_cypher = open(cTextFile, 'wb')
        cText.tofile(fileOut_cypher)
        fileOut_cypher.close()
        end = time.perf_counter()
        cpu1 = "cpuUsage1:" + str(psutil.cpu_percent())
        mem1 = "memUsage1:" + str(psutil.virtual_memory()) + '\n'
        results.write("cpu1: " + cpu1 + " mem1: " + mem1)
        truth = "HRH encryption duration: " + str(end-start) + "\n"
        print(truth)
        results.write(truth)
        
        
        keySchedule_01.clear()
        keySchedule_02.clear()
        keySchedule_03.clear()
        
        print("decrypting file...")
        dstart = time.perf_counter()
    
        keySched(keySchedule_01, keySchedule_02, keySchedule_03, 'keyfile.txt')
        cText = tripleDESWrapper(cTextFile, DESFunction.decrypt, 'ECB')
        fileOut_plaintext = open(outputFile, 'wb')
        cText.tofile(fileOut_plaintext)
        fileOut_plaintext.close()
        dend = time.perf_counter()
        cpu2 = "cpuUsage2:" + str(psutil.cpu_percent())
        mem2 = "memUsage2:" + str(psutil.virtual_memory()) + '\n\n'
        results.write("cpu2: " + cpu2 + " mem2: " + mem2)
        dTruth = "HRH decryption duration: " + str(dend-dstart) + "\n"
        print(dTruth)
        results.write(dTruth)
        
    
    results.close()
    print("closed")
    
    exit()










