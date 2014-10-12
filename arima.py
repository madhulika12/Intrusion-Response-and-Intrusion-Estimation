import numpy as np
import math
import pylab
import time
import pylab
from rpy2 import robjects
#from erobj import *
r=robjects.r

if __name__=='__main__':
    
##    f1=open('R_arima_normal_UDP_packetrate.csv','r')
    f1=open('R_host_cpusystem.csv','r')
    lines=f1.readlines()#lines is list; type(lines[0]) is str
    

    #===========Initial========
    #==========================
##    print lines[0], lines[1],lines[2]
    packetinitial=[]
    initial=lines[0].split('\n')  
    data=(float(initial[0]))
    initial1=lines[1].split('\n')  
    data1=(float(initial1[0]))
##    initial2=lines[2].split('\n')  
##    data2=(float(initial1[0]))
    packetinitial.append(data)
    packetinitial.append(data1)
##    packetinitial.append(data2)
    packetarray=packetinitial
##    realDataArray=packetarray
##    packet=(float(value))
    number=len(lines)
    l_list=lines[2:number]
    ArimaList=[]
    i=3 #--i is for predict No.
    print "=====Begin====="
    j=0
    for li in l_list:
        j=j+1
        i=i+1
        Rlist=[]
        data=li.split('\n')
        value=data[0]
        packet=(float(value))
        packetarray.append(packet)
##        realDataArray.append(packet)#----For comparing true data with predicted data
        vector=robjects.FloatVector(packetarray)
##        print vector 

        r['library']("TTR")
        newdataSMA15=r['SMA'](vector, n=2)
##        if(i<81):
##            newdataSMA15=r['SMA'](vector, n=2) #<- python __
####        if(10<i<21):
####             newdataSMA15=r['SMA'](vector, n=3)
####        if(20<i<31):
####             newdataSMA15=r['SMA'](vector, n=4)
####        if(30<i<41):
####             newdataSMA15=r['SMA'](vector, n=5)
##        if(80<i):
##             newdataSMA15=r['SMA'](vector, n=8)
##        if(50<i<61):
##             newdataSMA15=r['SMA'](vector, n=7)
##        if(60<i<71):
##             newdataSMA15=r['SMA'](vector, n=8)
##        if(70<i<81):
##             newdataSMA15=r['SMA'](vector, n=9)
##        if(80<i<91):
##             newdataSMA15=r['SMA'](vector, n=10)
##        if(90<i<101):
##             newdataSMA15=r['SMA'](vector, n=12)
##        if(100<i<120):
##             newdataSMA15=r['SMA'](vector, n=15)

##        print newdataSMA15
##        r['print'](newdataSMA15)
        #r.plot(newdataSMA15)
##        r.par(ann=0)
        r['library']("forecast")
        predfit=r['auto.arima'](newdataSMA15)
##        print predfit
##        r['print'](predfit)
        f=r['forecast'](predfit)
##        print f
        forecastFile=open('forecast.txt','w')
        forecastFile.write(str(f))
        forecastFile.close()
        forecastRead=open('forecast.txt','r')
        forecastResult=forecastRead.readlines()
        forecastRead.close()
##        print"-------test IO---------"
##        print forecastResult
        NextDataAll=forecastResult[1]
        NextData=NextDataAll.split()
        PredictData=NextData[1]
        ArimaList.append(PredictData)
##        print"forecast:\n"
##        print f
##        print "real data:\n "
##        print lines[i:i+10]
##        print "=========="

        
##        if(j%10==0):
##            firstdata=packetarray[8]
##            seconddata=packetarray[9]
##            packetarray=[]
##            packetarray.append(firstdata)
##            packetarray.append(seconddata)

    f1.close()
    print packetarray
    RealData=packetarray[3:number]
    print RealData
    pylab.figure()
    pylab.plot(ArimaList,'r-',label='Estimate PacketRate')
    pylab.plot(RealData,'b-',label='Truth Value')
    pylab.legend()
            
    pylab.show()    

