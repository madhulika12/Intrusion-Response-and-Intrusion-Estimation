import os
#AttackList=['UDP','TCP_SYN','ICMP','POD','SQL','Exhaustion']
ProtectionList=['IPS','Filter','Trust Platform','Replica','Network Disconnection','Host Shutdown']#,'Terminate','ModSecurity']
#NewList=['SpeedList','CPUList','PacketList','DataList','ConnectionList','LoginList','MemList','CostList']
SmallList=['Mspeed','Mpacket','Mcpu','Mconnection','Mfalsevalue','Mlegitimate']#,'Mmem','MCost']  #Mfalsevalue LoginList /Mlegitimate lossList
BoolTest=True
#for attackname in range (0,len(AttackList)):
attack='UDP'
multi_file='/home/MWrite/'+attack
OverallList=[]
for number in range(0,len(SmallList)):  #path1/path2..../_path8
    ListName=[]
    for protect in range (0, len(ProtectionList)):#IPS,Filter...
        #check directory is true
        Check=multi_file+'_'+str(ProtectionList[protect])+'_'+SmallList[number]+'.txt'
        #print Check
        Path=os.path.isfile(Check)
        #print Path
        
        if(Path==True):
                                
            FileOpen=open(Check,'r')
            FileValue='FileValue'+str(protect+1)
            
            FileValue=FileOpen.readline()
            data=float(FileValue)
	    #print data
            ListName.append(data)
	    FileOpen.close()
        else:
            self.log.writeText(' Please Set Values for Alternaives with Each Criteria ','Red')
    #print ListName
    OverallList.append(ListName)
SpeedList=OverallList[0]
PacketList=OverallList[1]
CPUList=OverallList[2]
ConnectionList=OverallList[3]
LoginList=OverallList[4]
LossList=OverallList[5]
#DataList=OverallList[6] #Mmem
#CostList=OverallList[7]
print OverallList
