# H Ryan Harasimowicz | 9421622 | 2016.10.23
# css539 Security in Emerging Environments | Dr. Lagesse
# OOB results for AES / 3DES 

import os
import time
import psutil
from bitstring import BitArray
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# read data in from file return as BitArray
def inputFromSourceFile(_file):
    f = open(_file, 'rb')
    bits = f.read()
    return bits

algo = 'AES'
#algo = '3DES'

sourceFile  = 'Dune.txt'
results     = open('OOBResults_' + algo + sourceFile + '.csv', 'w')
cycles      = 10
cpu0        = str(psutil.cpu_percent())
mem0        = str(psutil.virtual_memory())
results.write("mode, iteration, cpu, memory stats,,,,,duration" + '\n')
results.write("baseline, 0, " + cpu0 + ", " + mem0 + '\n')


backend = default_backend()
key = os.urandom(32)
key_24  = b'24BKey-0-1-2-3-4-5-6-7-8'
iv = os.urandom(16)
iv_8    = b'8BIV-0-1'

for i in range(cycles):
    
    start = time.perf_counter()
    bits = inputFromSourceFile(sourceFile)
    
    if algo == 'AES':
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
    
        padder_128 = padding.PKCS7(128).padder()
        data_cryptography_AES_padded = padder_128.update(bits)
        data_cryptography_AES_padded += padder_128.finalize()
        ct = encryptor.update(data_cryptography_AES_padded) + encryptor.finalize()
    
    elif algo == '3DES':
        cipher  = Cipher(algorithms.TripleDES(key_24), modes.CBC(iv_8), backend=backend)
        encryptor = cipher.encryptor()
    
        padder_64 = padding.PKCS7(64).padder()
        data_cryptography_DES_padded = padder_64.update(bits)
        data_cryptography_DES_padded += padder_64.finalize()
        ct = encryptor.update(data_cryptography_DES_padded) + encryptor.finalize()
    
    ctFile = open("cipher.dnk", 'wb')
    ctFile.write(ct)
    ctFile.close()
        
    end     = time.perf_counter()
    cpu1    = str(psutil.cpu_percent())
    mem1    = str(psutil.virtual_memory())
    sDT     = str(end-start)
    results.write("Enc/Save," + str(i) + "," + cpu1 + "," + mem1 + "," + sDT + ",")
    
    dStart = time.perf_counter()
    decryptor = cipher.decryptor()
    donkey = decryptor.update(ct) + decryptor.finalize()
    baOut = BitArray(donkey)
    fileOut = open("output.txt", 'wb')
    baOut.tofile(fileOut)
    fileOut.close()
    
    dEnd    = time.perf_counter()
    cpu2    = str(psutil.cpu_percent())
    mem2    = str(psutil.virtual_memory())
    sRT     = str(dEnd-dStart)
    results.write("open/dec," + str(i) + "," + cpu2 + "," + mem2 + "," + sRT + '\n')

results.close()