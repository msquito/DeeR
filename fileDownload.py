# H Ryan Harasimowicz | 9421622 | 2016.10.23
# css539 Security in Emerging Environments | Dr. Lagesse
# File downloading test

import time
import _thread
import urllib.request

link00 = 'http://speedtest.sea01.softlayer.com/downloads/test10.zip'
link01 = 'http://speedtest.dal01.softlayer.com/downloads/test10.zip'
link02 = 'http://speedtest.ams01.softlayer.com/downloads/test10.zip'
link10 = 'http://speedtest.sea01.softlayer.com/downloads/test100.zip'
link11 = 'http://speedtest.dal01.softlayer.com/downloads/test100.zip'
link12 = 'http://speedtest.ams01.softlayer.com/downloads/test100.zip'


outFiles = []
multiDur = []
loc = "dal"

for i in range(11):
    outFiles.append("fileDwn"+str(i))

def dlFile(link, file, resultFile, txt):
    start = time.perf_counter()
    with urllib.request.urlopen(link) as response, open(file, 'wb') as file:
        data = response.read() # a `bytes` object
        file.write(data)
        file.close()
    end = time.perf_counter()
    resultString = str(txt)  + ", " + str(end-start) + '\n'
    results = open(resultFile, 'a')
    results.write(resultString)
    results.close()
    print("thread", txt, "done")

try:    
    if loc == "sea":
        dlFile(link10, outFiles[10], "downloadResults.txt", 10)
    elif loc == "dal":
        dlFile(link11, outFiles[10], "downloadResults.txt", 11)
    else: 
        dlFile(link12, outFiles[10], "downloadResults.txt", 12)
    print("done with big download")

    for i in range(10):
        if loc == "sea":
            _thread.start_new_thread(dlFile, (link00,outFiles[i], "downloadResults.txt", i))
        elif loc == "dal":
            _thread.start_new_thread(dlFile, (link01,outFiles[i], "downloadResults.txt", i))
        else:
            _thread.start_new_thread(dlFile, (link02,outFiles[i], "downloadResults.txt", i))
        
    print("done pitching threads...")
   
except:
   print ("Error: unable to start threads")


