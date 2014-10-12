# ---------------------------------------------------------------------
# Process raw data collect by sensors (online-monitor and preprocess module)
# ------------------------------------------------------------------

class ProcessData():
    def __init__(self):        
        fpro=open('/home/file/sar.txt','r')
        wrnew1=open('/home/file/newsar.txt','w+b')    
        wrnew=open('/home/file/newsar.csv','w+b')
        string="Memory Availabe (KB),Byte Receive (Byte),Byte Sent (Byte),Packet Receive (/s),Packet Sent (/s),IO Read (Byte),IO Write (Byte),CPU Idle (%),CPU System Utilization (%),CPU User Utilization (%)\r\n"
        wrnew.write(string)
        delete="Average"
        sub="all"
        sub1="tps"
        sub2="eth0"
        sub3="kbmemfree"
        user=[]
        system=[]
        idle=[]
        IOR=[]
        IOW=[]
        pr=[]
        ps=[]
        br=[]
        bs=[]
        mem=[]
        number=0
        #--------delete missing data-------
        for line in fpro:
            if (line.find(delete)<0):
                newline=""
                split=line.split(' ')    
                for i in range (0,(len(split)-1)):
                    if(cmp(split[i],'')!=0):
                        if(cmp(split[i],'\n')!=0):                
                            newline=newline+split[i]
                            newline=newline+","    
                newline=newline+split[len(split)-1]
                wrnew1.write(newline)   
        fpro.close()
        wrnew1.close()
        #--------open new file which filtered missing data------
        fpro2=open('/home/file/newsar.txt','r')
        lines=fpro2.readlines()
        l_list=lines[0:len(lines)]
        temnum=0
        tnum=0
        #------Organize 10 features' data------------------
        for l in l_list:    
            if(l.find(sub)>=0): #cpu
                cpuall=l.split(',')       
                temp=cpuall[8][0:len(cpuall[8])-1]       
                user.append(float(cpuall[3]))   #user prcentage    
                idle.append(float(temp))        #idle time
                system.append(float(cpuall[5])) #processor system time
        
            if(l.find(sub1)>=0):  #IO
                temnum=number
            if(int(temnum+1)==int(number)):
                ioall=l.split(',')     
                if(len(ioall)==7):
                    temp=ioall[6][0:len(ioall[6])-1]
                    IOR.append(float(ioall[5])) #IO Read
                    IOW.append(float(temp)) #IO Write           
        
            if(l.find(sub2)>=0):  #network
                netall=l.split(',')      
                pr.append(float(netall[3])) #No. of packet recive 
                ps.append(float(netall[4])) #No. of packet sent
                br.append(float(netall[5])) #Total Byte receive
                bs.append(float(netall[6])) #Total Byte sent        
        
            if(l.find(sub3)>=0):  #memory available KB
                tnum=number
            if(int(tnum+1)==int(number)):
                memall=l.split(',')        
                if(len(memall)==11):
                    mem.append(float (memall[2]))
            number=number+1  
        length=len(user)
        
        #----------------write to file--------------
        for li in range(0,length):    
            data=str(mem[li])+','+str(br[li])+','+str(bs[li])+','+str(pr[li])+','+str(ps[li])+','+str(IOR[li])+','+str(IOW[li])+','+str(idle[li])+','+str(system[li])+','+str(user[li])+'\r\n'
            wrnew.write(data)
        fpro2.close()
        wrnew.close()


