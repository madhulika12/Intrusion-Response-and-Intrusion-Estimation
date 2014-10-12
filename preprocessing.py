# ---------------------------------------------------------------------
# Preprocessing raw data and output the correct format file for IDS to read-

class Preprocessing():
    def __init__(self):

        f1=open('/home/file/newsar.csv','r')
        wr=open('/home/file/test.arff','w+b')
        wr1=open('/home/file/test.csv','w+b')
        line = f1.readlines()
        sub='," ",'
        for l in line:
            if(l.find(sub)<0):        
                wr1.write(l)
        wr1.close()        
        f2=open('/home/file/test.csv','r') #processed data
        lines = f2.readlines()
        number=len(lines)
        l_list=lines[number-5:number]
        mem=34039.27  #avareage in normal case calculate delta(differences between attacks and normal data)  average values are calculated off-line
        BR=399.9571
        BS=0.056243
        PR=3.418408
        PS=0.001346
        IOR=0
        IOW=87.41735
        Id=96.91446
        Pro=1.580873
        US=1.486682
        #--------------save as .arff for WEKA to read-------------------
        wr.write( """@relation test_minus_normal \r\n@attribute 'Memory Available Bytes' numeric \r\n@attribute 'Bytes Received/sec' numeric \r\n@attribute 'Bytes Sent/sec' numeric \r\n@attribute 'Packets Received/sec' numeric \r\n@attribute 'Packets Sent/sec' numeric \r\n@attribute 'IO Read Bytes/sec' numeric \r\n@attribute 'IO Write Bytes/sec' numeric \r\n@attribute ' Idle Time' numeric \r\n@attribute ' Processor Time' numeric \r\n@attribute 'User Time' numeric \r\n@attribute TYPE {ICMP,POD,TCPSYN,UDP,Normal}\r\n@data \r\n""")
        for li in l_list:
            data=li.split(',')
            a=data[0]   
            b=data[1]
            c=data[2]
            d=data[3]
            e=data[4]
            f=data[5]
            g=data[6]
            h=data[7]
            i=data[8]
            j=data[9]                
            newmem=float(a)-mem
            newBR=float(b)-BR
            newBS= float(c)-BS
            newPR=float (d)-PR
            newPS=float (e)-PS
            newIOR=float (f)-IOR
            newIOW=float (g)-IOW
            newID=float (h)-Id
            newPro=float (i)-Pro
            newUS=float (j)-US
            wdata=str(newmem)+','+str(newBR)+','+str(newBS)+','+str(newPR)+','+str(newPS)+','+str(newIOR)+','+str(newIOW)+','+str(newID)+','+str(newPro)+','+str(newUS)+',?\r\n'
            wr.write(wdata) #save in file    
        f1.close()   
        f2.close() 
        wr.close()

 
