# H Ryan Harasimowicz | 9421622 | 2016.10.23
# css539 Security in Emerging Environments | Dr. Lagesse
# DeeR Tier-3 prototype

import os
import math
import time
import psutil
import secrets
import datetime
from bitstring import BitArray
from enum import Enum


# transformations
#000 - nothing
#001 - bitshift 1
#010 - bitshift 2
#011 - bitshift 3
#100 - xor
#101 - xor + bitshift 1
#110 - xor + bitshift 2
#111 - xor + bitshift 3

# chunk transformations for file deconstruction
def transChunkFwd(chunk, trans, key):
    if trans    == '0b000':
        return
    elif trans  == '0b001':
        chunk.ror(1)
    elif trans  == '0b010':
        chunk.ror(2)
    elif trans  == '0b011':
        chunk.ror(3)
    elif trans  == '0b100':
        chunk ^= key
    elif trans  == '0b101':
        chunk ^= key
        chunk.ror(1)
    elif trans  == '0b110':
        chunk ^= key
        chunk.ror(2)
    elif trans  == '0b111':
        chunk ^= key
        chunk.ror(3)
    
# chunk transformations for file reconstruction
def transChunkBck(chunk, trans, key):
    if trans    == '0b000':
        return
    elif trans  == '0b001':
        chunk.rol(1)
    elif trans  == '0b010':
        chunk.rol(2)
    elif trans  == '0b011':
        chunk.rol(3)
    elif trans  == '0b100':
        chunk ^= key
    elif trans  == '0b101':
        chunk.rol(1)
        chunk ^= key
    elif trans  == '0b110':
        chunk.rol(2)
        chunk ^= key
    elif trans  == '0b111':
        chunk.rol(3)
        chunk ^= key


class bitsContainer:
    length = 0
    bits = BitArray()  
#    def __del__(self):
#        print ("deling", self)
    
paddingLengthBytes = 16
paddingLengthBits = paddingLengthBytes*8

# parity for 8 chunks - extend for n chunks if time allows...
parityEven  = [0,2,4,6]
parityOdd   = [1,3,5,7]
parityTop   = [0,1,2,3]
parityBot   = [4,5,6,7]
parityIn    = [2,3,4,5]
parityOut   = [0,1,6,7]
parity      = [parityEven, parityOdd, parityTop, parityBot, parityIn, parityOut]

# fill out n chunks with garbage chunks
def buildRandom(chunkArray, chunks):
    chunkLen = chunkArray[0].len
    for i in range(chunks-len(chunkArray)):
        chunkArray.append(BitArray(int=secrets.randbits(chunkLen-1), length = chunkLen))

# expand the transOrder to sufficient length to XOR into trans>4 chunks
def stretchKey(transOrder, keyLen):
    short   = keyLen % transOrder.len
    cycles  = math.floor(keyLen / transOrder.len)
    longKey = BitArray(bytes=0)
    
    for i in range(cycles):
        longKey.append(transOrder)
        
    longKey.append(transOrder[:short])
    
    return longKey

# randomize order of chunks in chunkArray, return origOrder key
def randoOrderChunks(chunkArray, theOrder):
    shebang     = 256
    randoLen    = len(chunkArray)*8    
    sRando      = secrets.randbits(shebang-1)
    randoBits   = BitArray(int=sRando, length=shebang)
    xKRandoBits = randoBits[randoLen:]
    randoBits   = randoBits[:randoLen]
    
    transLen    = len(chunkArray)*3
    transBits   = BitArray(int=0,length=transLen)
    
    # build transformations from randoBits
    for i in range(transLen):
        if randoBits[(i*8+i)%randoLen]:
            transBits.set(1,i)
            
    # final transOrder documentation
    transOrder = BitArray(bytes=0)
    
    # ensure xor of parity chunks
    # hard coded for 8 primary / 6 secondary
    dataChunks      = 8
    parityChunks    = 6
    for i in range(parityChunks):
        transBits.set(1,(i*3)+dataChunks*3)
        
    #####################################################################
    # rework to transform before reorder 
    
    # initialize theOrder so swapping can occur
    for i, x in enumerate(chunkArray):
        theOrder.append(i)

    for i, x in enumerate(chunkArray):
        tempBits    = randoBits[i*8:i*8+8]
        curRand     = tempBits.uint % len(chunkArray)
        
        theOrder[i],    theOrder[curRand]   = theOrder[curRand],    theOrder[i]
        chunkArray[i],  chunkArray[curRand] = chunkArray[curRand],  chunkArray[i]
       
    # apply transformations
    masterKey = stretchKey(xKRandoBits, len(chunkArray[0]))
    
    for i, chunk in enumerate(chunkArray):
        cur = transBits[i*3:i*3+3]
        transChunkFwd(chunk,cur,masterKey)
        
    # record transformations and order information  
    for i, x in enumerate(theOrder):
        cur = transBits[i*3:i*3+3]
        # append position value for indexed chunk
        transOrder.append(BitArray(int=x, length=8))
        # set transformation values in front 3 bits of each trans/order
        transOrder.overwrite(cur, i*8)
    # append the xorKey
    transOrder.append(xKRandoBits)
    return transOrder
    

# you need to re-order the chunks here, not just establish order
# transform and sort chunks back to file
def reOrderChunks(chunkArray, transOrderBits):
    # 0 - 127 "[:128]
    xorKey = transOrderBits[256-(len(chunkArray)*8):]
    transOrderBits = transOrderBits[:256-(len(chunkArray)*8)]
    origOrder   = []
    transforms  = BitArray(bytes=0)
    
    for i in range (len(chunkArray)):
        # strip out transformations
        transforms.append(transOrderBits[i*8:i*8+3])      
        transOrderBits.set(0,(i*8, i*8+1, i*8+2))
        # strip out order
        origOrder.append(transOrderBits[i*8:i*8+8].int)

    # reapply transformations
    masterKey = stretchKey(xorKey, len(chunkArray[0]))

    for i, chunk in enumerate(chunkArray):
        cur = transforms[i*3:i*3+3]
        transChunkBck(chunk,cur,masterKey)
        
    # flip origOrder array for reconstruction
    recip = [0]*len(chunkArray)
    for i in range (len(chunkArray)):
        recip[origOrder[i]] = i
        
    return recip

def buildParity(chunkArray):
    for i in range (len(parity)):
        chunkArray.append(BitArray(chunkArray[0].len))
        for j in parity[i]:
            chunkArray[-1] ^= chunkArray[j]

# confirm parity on 
def checkParity(chunkArray):
    pChunk = 8
    for i in range (3):
        chunkArray[pChunk] ^= chunkArray[parity[0][i]]
    if chunkArray[pChunk] == chunkArray[6]:
        print("parity good")
    else:
        print("parity bad")

def outputToFiles(chunkArray):
    files   = []
    text    = 'chunks'
    
    # hardcoded output location for test purposes
    loc         = os.path.dirname(os.path.abspath(__file__))
    basePath    = os.path.join(loc,'fileOutput')
    if not os.path.exists(basePath):
        print("mkdir")
        os.mkdir(basePath)
    
    newPath     = os.path.join(basePath,text)    
    if not os.path.exists(newPath):
        os.mkdir(newPath)

    for i in range (len(chunkArray)):
        filename = os.path.join(newPath) + '\\' + str(i) + ".dnk"
        tempFile = open(filename, 'wb')
        chunkArray[i].tofile(tempFile)
        files.append(filename)
        tempFile.close()
        
def inputFromFiles(directory, chunks):
    loc         = os.path.dirname(os.path.abspath(__file__))
    recChunks   = []
    
    for i in range (chunks):
        filename = os.path.join(loc) + '/fileOutput/' + directory + '/' + str(i) + '.dnk'
        f = open(filename, 'rb')
        recChunks.append(BitArray(f))

    return recChunks        

# read data in from file return as BitArray
def inputFromSourceFile(_file):
    source          = open(_file, 'rb')
    bitsCont        = bitsContainer()
    bitsCont.bits   = BitArray(source)
    bitsCont.length = bitsCont.bits.len
    return bitsCont

# determine chunk size according to equal division of file length
def setChunkSize(splitLen):
    size = 512
    while splitLen > size:
        size *= 2
    return size

# creates chunks for deconstruction
# adds padding space for deconstruction
def createChunks(bitsCont, chunks):
    paddedLen   = bitsCont.bits.len+paddingLengthBits
    chunkLen    = int(paddedLen/chunks)
    chunkSize   = setChunkSize(chunkLen)
    schunks     = [BitArray(chunkSize) for count in range(chunks)]
    return schunks

# deconstructs whole binary into fed chunks
# includes padded whole-length at start
def deconstruct(bitsCont,chunkArray):
    chunks      = len(chunkArray)
    curChunk    = 0
    pos         = -1
    pBits       = BitArray(int=bitsCont.length, length=paddingLengthBits)
    pBBits      = pBits+bitsCont.bits

    for i, c in enumerate(pBBits):
        curChunk = i%chunks
        if curChunk == 0:
            pos += 1
        if c == 1:
            chunkArray[curChunk].set(int(c), pos)
    
    curChunk = (curChunk + 1)%chunks
    if curChunk == 0:
        pos += 1
    
    # backfill chunk with garbage
    randoLen    = chunks*chunkArray[0].len - bitsCont.bits.len
    rando       = secrets.randbits(randoLen)
    randoBits   = BitArray(int=rando, length = rando.bit_length()+1)
    
    for c in randoBits:
        if pos == chunkArray[0].len:
            break
        if c == 1:
            chunkArray[curChunk].set(int(c), pos)
        curChunk = (curChunk + 1)%chunks
        if curChunk == 0:
            pos += 1            


def reconstruct(chunkArray, order, chunks):
    # peel out the padding from chunks
    padding = BitArray(paddingLengthBits)
    pPos = -1
    for i in range(paddingLengthBits):
        curChunk = i%chunks
        if curChunk == 0:
            pPos += 1
        padding.set(int(chunkArray[order[curChunk]][pPos]),i)
#    print("reconPadding:",padding.int)

    # for greater efficiency figure out how to only reassemble package
    pBBitsLen = paddingLengthBits + padding.int

    pos = -1
    recon = BitArray(pBBitsLen)
    for i in range(pBBitsLen):
        curChunk = i%chunks
        if curChunk == 0:
            pos += 1
        if chunkArray[order[curChunk]][pos] == 1:
            recon.set(chunkArray[order[curChunk]][pos],i)
    return recon[paddingLengthBits:]


# main function

if __name__ == '__main__':
    
#    sourceFile  = 'Washington_Huskies.png'
#    sourceFile  = 'DuneAbb.txt'
    sourceFile  = 'Dune.txt'
#    sourceFile  = 'Dune_jamga.jpg'
#    sourceFile  = 'Dune_407.jpg'
#    sourceFile  = 'Dune_407.txt'
#    sourceFile  = 'Dune_407.zip'
#    sourceFile  = 'DuneChildrenMessiah.tar'
    
    results     = open('deconReconResults_' + sourceFile + '.csv', 'w')
    cycles      = 10
    cpu0        = str(psutil.cpu_percent())
    mem0        = str(psutil.virtual_memory())
    results.write("mode, iteration, cpu, memory stats,,,,,duration" + '\n')
    results.write("baseline, 0, " + cpu0 + ", " + mem0 + '\n')
    
    for i in range(cycles):
        
        start           = time.perf_counter()
        chnkOrgOrder    = []   
        bits            = inputFromSourceFile(sourceFile)
        chunkArray      = createChunks(bits,8)
        
        deconstruct(bits, chunkArray)
        buildParity(chunkArray)
    #    checkParity(chunkArray)
        buildRandom(chunkArray,16)
        
        # build reconKey with transOrder info
        reconKey = randoOrderChunks(chunkArray, chnkOrgOrder)
        
        # strip transOrder info from 
        reconOrder = reOrderChunks(chunkArray, reconKey)
        
        #del bits
        outputToFiles(chunkArray)
        
        end     = time.perf_counter()
        cpu1    = str(psutil.cpu_percent())
        mem1    = str(psutil.virtual_memory())
        sDT     = str(end-start)
        results.write("DECON," + str(i) + "," + cpu1 + "," + mem1 + "," + sDT + ",")

        #######################################################################      
        # reconstruct file  
        start2 = time.perf_counter()
        
        reconArray = inputFromFiles('chunks',16)
        
        reconBits = reconstruct(reconArray, reconOrder, 8)
        
        end2    = time.perf_counter()
        cpu2    = str(psutil.cpu_percent())
        mem2    = str(psutil.virtual_memory())
        sRT     = str(end2-start2)
        results.write("RECON," + str(i) + "," + cpu2 + "," + mem2 + "," + sRT + '\n')

    results.close()
            
#    # test set to create known inequality
#    print("firstBit:", int(reconBits[0]))
#    reconBits.set(1,0)  
#    print("firstBit:", int(reconBits[0]))
        
    # check reconstructed bits for source-match
    if bits.bits == reconBits:
        print("equal")
    else:
        print("not equal")
        
    exit


