import wx,tempfile
import wx.lib.colourdb
import os
import numpy as np
import math
import pylab
import time
import pylab
import signal
import pexpect
from rpy2 import robjects
from rpy2 import *
import time
import sys
import datetime
from mcontroller import *
import thread
from globe import *
from fuzzycontroller import *
from disconnection import *
from CPU_MeM_Priority_Kill import *

r=robjects.r
print r
print "abc"
#if __name__=='__main__': 
robjects.r('''library("TTR",lib.loc="/home/R_Packet")''')
robjects.r('''library("forecast",lib.loc="/home/R_Packet")''')
robjects.r('''library("tsDyn",lib.loc="/home/R_Packet")''')
#from forecast_gui import *

ip='3.0.0.1' #remote access router which ip is 3.0.0.1 for dynamically analyzing             
ip2='1.0.0.1'#attack packets and redirecting illegal flow from router to protected VM before forwarding packets to host 
user='root'  # router username password
passwd='000000'
#os.mkfifo("filename.fifo")
#fifo = open("filename.fifo", 'w')
class TimeoutException(Exception): 
    pass 
class Forecast():
    
    CPUState='Normal'
    
    MemState='Normal'
    
    PacketState='Normal'
   
    ForecastAttack="Normal"
    def __init__(self,log):          
        self.log=log 
	
	#self.log.writeText("TEST",'RED')
            #self.udpbest=""
            #self.tcpbest="" 
        
        
    def setLog(self, log):
        self.log = log

    def ProcessLog(self,attack):
	#print "Working"
	#self.log=log
	self.attack=attack
	#self.log=log
        newtime=0
        #UDPString='{UDP}'
        #PODString='POD'
        #ICMPString='ICMP'
        UDPNumber=0
        ICMPNumber=0
        PODNumber=0
	TCPNumber=0
        UDPTotal=[]
        ICMPTotal=[]
        PODTotal=[]
	TCPTotal=[]
        preLine=0
	preLine2=0
	starttime=time.clock()
        while (newtime<10000):
	    
	    self.CPUState='Normal'
    
    	    self.MemState='Normal'
    
    	    self.PacketState='Normal'
   
    	    self.ForecastAttack="Normal"
	    self.log.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLACK') 
	    #self.log.writeText("Begin",'RED')
            if(os.path.isfile('/var/log/snort_inline/snort_inline-fast')==False):    
                nofile="No Snort_Inline Log Files"
		print nofile
	        self.log.writeText(nofile,'RED')
                break
            else:
		print "ProcessLog else works"
                
                #print starttime
                f1=open('/var/log/snort_inline/snort_inline-fast','r')
                
                lines=f1.readlines()#lines is list; type(lines[0]) is str
                
                number=len(lines)
                #print "Number of File is %d\n"%number
                #print number
                data=lines[preLine:number]
                for logdata in data:
                    if(logdata.find('UDP')>=0):
                        UDPNumber=UDPNumber+1
                        #print logdata
                        #print "UDP if\n"
                    elif(logdata.find('ICMP')>=0):
                        #print logdata
                        ICMPNumber=ICMPNumber+1
                        #print "ICMP if \n"
                    elif(logdata.find('POD')>=0):
                        PODNumber=PODNumber+1
                preLine=number
                #print preLine
                #print "UDPNumber is %d"%UDPNumber
                UDPTotal.append(UDPNumber)
              
                ICMPTotal.append(ICMPNumber)
                PODTotal.append(PODNumber)
                f1.close()
                UDPString=str(UDPNumber)
                #print UDPString
                ICMPString=str(ICMPNumber)
                PODString=str(PODNumber)
                UDPFile=open('/home/forecast/UDPTotal.txt','a+')
                #UDPFile.write(UDPString+'\n')
                UDPFile.close()
                ICMPFile=open('/home/forecast/ICMPTotal.txt','a+')
                #ICMPFile.write(ICMPString+'\n')
                ICMPFile.close()
                PODFile=open('/home/forecast/PODTotal.txt','a+')
                #PODFile.write(PODString+'\n')
                PODFile.close()
                #self.predict(self.attack)
                
                
                #print endtime
               
                #newtime=newtime+(endtime-starttime)+10 
	#==============TCP Log File=========================
	    if(os.path.isfile('/home/log/custom.log')==False):    
                nofile="No TCP Log Files"
		print nofile
	        self.log.writeText(nofile,'RED')
                break
            else:
		print "Process TCPLog else works"
                #starttime=time.clock()
                #print starttime
                f1=open('/home/log/custom.log','r')
                
                lines=f1.readlines()#lines is list; type(lines[0]) is str
                
                number=len(lines)
                #print "Number of File is %d\n"%number
                #print number
                data=lines[preLine2:number]
                for logdata in data:
                    if(logdata.find('PROTO=TCP')>=0):
                        TCPNumber=TCPNumber+1
                     
                preLine2=number
                #print preLine
                #print "UDPNumber is %d"%UDPNumber
                TCPTotal.append(TCPNumber)            
               
                f1.close()
                TCPString=str(TCPNumber)
                #print UDPString
                
                TCPFile=open('/home/forecast/TCPTotal.txt','a+')
                TCPFile.write(TCPString+'\n')
                TCPFile.close()
                
            self.predict(self.attack)
            time.sleep(10)
            endtime=time.clock()
                #print endtime
               
            newtime=newtime+(endtime-starttime)+10 
   
    def predict(self,newattack):
        print "predict works\n"
    	
    	
        newtime=0
        UDPString='UDP'
        PODString='POD'
        ICMPString='ICMP'
	TCPString='TCP'
        UDPPredict=[]
	TCPPredict=[]
        SetarList=[]
        realdata=[]
        Rdata=[]
        preLine=0
        OriginalData=[]
        ProcessedData=[]
        ArimaList=[]
        number=0
        #while (newtime<5):
        
        fileList=['UDP','ICMP','POD','TCP']
        for i in range (0,len(fileList)):
            attack=fileList[i]
            fileName='/home/forecast/'+attack+'Total.txt'
            print fileName
            if(os.path.isfile(fileName)==False):    
                nofile="No %s Dropped Packets"%attack
                print nofile
                self.log.writeText(nofile,'RED')
                #sys.exit(1)
                break
            else:
                f1=open(fileName,'r')
                lines=f1.readlines()#lines is list; type(lines[0]) is str
                number=len(lines)
                f1.close()
                #print number
                Rdata=lines[0:number]
            
                UDPPredict=lines[0:number]
		if(number>2):
                	print "Last 2 Sec: "
			print "my name is "
			print UDPPredict[-4:-1]
			print "whatever"
                #if(len(UDPPredict)>=10):
                Equal=0
                for i in range (1, len(UDPPredict)):
                            Delta=float(UDPPredict[i])-float(UDPPredict[i-1])
                            if(Delta==0):
                                Equal+=1
                            else:
                                Equal=0
                #print "Equal is: %d"%Equal
                if(Equal>=(len(UDPPredict)-2)):
                            forecastfileName='/home/forecast/'+attack+'forecast.txt'
                            forecastFile=open(forecastfileName,'w')
                            f="Same as Previous Forecast\n n+1  %s"%UDPPredict[len(UDPPredict)-1]
                            forecastFile.write(f)
                            forecastFile.close()
                            #ArimaList.append(UDPPredict[len(UDPPredict)-1])
                            #del UDPPredict[0]

                else:
                            vector=robjects.FloatVector(UDPPredict)
                        
                            newdataSMA15=r['SMA'](vector, n=1)
                            
                            predfit=r['auto.arima'](newdataSMA15)
                    
                            f=r['forecast.Arima'](predfit,level=r['c'](99.5))
                            print "yadfjkfjalfjd;ajldkfja;dfdkjfak;fjdkfjak;fjdklafjl;"
                            r['print'](f)
			    print "jo bhi hoga dekhebbge"
			    #print f
			    
			    #print >> fifo, f
    			    
                            forecastfileName='/home/forecast/'+attack+'forecast.txt'
                            forecastFile=open(forecastfileName,'w')
                            forecastFile.write(str(f))
                            forecastFile.close()
			    FileName='/home/forecast/'+attack+'forecastall.txt'
			    WriteFile=open(FileName,'a+')
			    
                            ReadFile=open(forecastfileName,'r')
                            AttackTotal=ReadFile.readlines()
			    TotalData=AttackTotal[1].split()
			    WriteFile.write(TotalData[1]+'\n')
                            forecastFile.close()
			    ReadFile.close()
			    WriteFile.close()
"""
        #=========Predict all paramters and known attacks============== 
        if(cmp(newattack,'All')==0):
            for i in range (0,len(fileList)):
                attack=fileList[i]
                #print attack
                fileName='/home/forecast/'+attack+'Total.txt'
                forecastfileName='/home/forecast/'+attack+'forecast.txt'
                if(os.path.isfile(forecastfileName)==False):    
                    print "No %s Forecast file"%attack #ye print ho raha hai
                    
                    #sys.exit(1)
                    noattack="No %s Attack in the future"%attack
                    self.log.writeText(noattack,'BLUE')
                    continue
                else:
                    f1=open(fileName,'r')
                    lines=f1.readlines()#lines is list; type(lines[0]) is str
                    number=len(lines)
                    f1.close()
                    UDPPredict=lines[0:number]
                    forecastRead=open(forecastfileName,'r')
                    forecastResult=forecastRead.readlines()
                    forecastRead.close()
                    NextDataAll=forecastResult[1]
                    NextData=NextDataAll.split()
                    PredictData=NextData[1]
                    #------send signal to host that will forecast the-------------------- 
        	    #------CPU, Mem, Packet, Host SQL Injection valuse-------------------
                   
                    if(float(PredictData)-float(UDPPredict[-2:-1][0])>0):
                        result="The forecaster estimates the %s flood attack will compromise the host in next several seconds."%attack
                        self.log.writeText(result,'RED')
			self.ForecastAttack=attack #---for prevention system to choose how to prevent the system
                    else:
                        result="The forecaster estimitate the %s attack won't be seen in the host"%attack
                        self.log.writeText(result,'BLUE')
			self.ForecastAttack='Normal'#---for prevention system to choose how to prevent the system
           
	    thread.start_new_thread(self.Send,('All',))
            thread.start_new_thread(self.Receive,('All',))#Receive ave. forecast CPU, Mem... from the host
	    
	    
	#==========Individual Paramters to be forecasted, e.g. CPU, Mem, UDP attack...======    
        elif(cmp(newattack,'UDP')==0 or cmp(newattack,'ICMP')==0 or cmp(newattack,'POD')==0 or cmp(newattack,'TCP_SYN')==0):
	    print "Predicted Parameter is", newattack
            #attack=fileList[i]
            #print attack
            fileName='/home/forecast/'+newattack+'Total.txt'
            forecastfileName='/home/forecast/'+newattack+'forecast.txt'
            if(os.path.isfile(forecastfileName)==False):    
                print "No %s Forecast file"%newattack
                
                #sys.exit(1)
                noattack="No %s Attack in the future"%newattack
                self.log.writeText(noattack,'BLUE')
                
            else:
                f1=open(fileName,'r')
                lines=f1.readlines()#lines is list; type(lines[0]) is str
                number=len(lines)
                f1.close()
                UDPPredict=lines[0:number]
                forecastRead=open(forecastfileName,'r')
                forecastResult=forecastRead.readlines()
                forecastRead.close()
                NextDataAll=forecastResult[1]
                NextData=NextDataAll.split()
                PredictData=NextData[1]
                	
                if(float(PredictData)-float(UDPPredict[-2:-1][0])>0):
                    result="The forecaster estimates the %s flood attack will compromise the host in next several seconds."%newattack
                    self.log.writeText(result,'RED')
		    self.ForecastAttack=newattack
                else:
                    result="The forecaster estimitate the %s attack won't be seen in the host"%newattack
                    self.log.writeText(result,'BLUE')
		    self.ForecastAttack='Normal'
        #========CPU Utimization, Host SQL Injection,Mem, PacketRate==== 
	else:
	    thread.start_new_thread(self.Send,(newattack,))
            thread.start_new_thread(self.Receive,(newattack,))#Receive ave. forecast CPU, Mem... from the host
	print "Parameters are change to ",self.ForecastAttack,self.CPUState,self.MemState,self.PacketState
	
	#================Prevent Known Attack UDP, ICMP, POD, TCP_SYN=========
	if(cmp(self.ForecastAttack,'UDP')==0 or cmp(newattack,'ICMP')==0 or cmp(newattack,'POD')==0 ):
	      	GlobeFun=Globe(self.log)
		GlobeFun.UDP()
		logstring="Prevention Method to prevent %s attack is IPS.",ForecastAttack
	    	print logstring
		self.log.writeText(logstring,'YELLOW')

    #---------def unknownfun(): -------------------
    def ssh_cmd(self,ip, user, passwd, cmd): #ssh router for redirect new attacks to protected VM 
        ssh = pexpect.spawn('ssh %s@%s "%s"' % (user, ip, cmd))  # connect to router
        r = ''
        time=400
        try:
            i = ssh.expect(['password: ', 'continue connecting (yes/no)?'],timeout=time)    
            if i == 0 :
                ssh.sendline(passwd)         
            elif i == 1:
                ssh.sendline('yes')
		
        except pexpect.EOF:
            ssh.close()
            print "EOF"
        except pexpect.TIMEOUT:
            print "timeout"
            
            ssh.close()
        else:
            r = ssh.read()
            ssh.expect(pexpect.EOF)
            ssh.close()
	    print "SSH Finish\n"
            return r
   #----------Unknown check Payload-------------
    def unknown(self):
	
        if(os.path.isfile('/home/file/capunknown.txt')==True):
            os.system("rm /home/file/capunknown.txt ")
  	if(os.path.isfile('/home/file/capunknowncontent.txt')==True): 
            os.system("rm /home/file/capunknowncontent.txt ")       
        
        hostnew=""    
        point=0 
        point1=0    
        ipdest="-> 1.0.0.2"
        su="UDP Source port:"
        su1="TCP"
        su2="ICMP"
                
        thread.start_new_thread(self.communication_send,())
        thread.start_new_thread(self.communication_receive,())
        
        time.sleep(10)
        fip=open('/home/file/capunknown.txt','r')
        lines=fip.readlines();
        number=len(lines)
        l_list = lines[0:number-1] 
        string=[]
        print "dynamic check attack type"
        for l2 in l_list:
            if(l2.find(su)>=0 and l2.find(ipdest)>=0): #check if the DoS attack packets' are UPD protocol? Yes define as UDP Flood
                if(point==0):
                    con1= "The attack is UDP flood\n"
                    vmnew=con1
                    print con1                     #print on GUI
                    self.log.writeText(con1,'BLUE')
                    tmp=l2.split(' ')
                    leng=len(tmp)                   #analyze destination port
                    for i in range (0,leng):      
                        if(cmp(tmp[i],'')!=0):
                            string.append(tmp[i])        
                    src=string[1] #src
                    dp=string[10]
                    ds=dp[0:(len(dp)-2)]
                    print ds                       #destination    
                    if (cmp(ds,"synapsis-edg")==0):  #example if attack comes from UDP 5008, change the name to number
                        dstport=5008    
                    if (cmp(ds,"wsm-server-ss")==0):
                        dstport=5007  
                    if (cmp(ds,"wsm-serve")==0):
                        dstport=5006
                    con2= "The attacked port is: %d\n"%dstport # save to print on GUI when click 'Click Me' button
                    vmnew=vmnew+'\n'+con2 
                    fip.close()
                    self.log.writeText(con2,'BLUE')
        #------------read packet content-----------
                    fcontent=open('/home/file/capunknowncontent.txt','r')
                    fsnort=open('/etc/snort_inline/drop-rules/my.rules','a')
                    uc=fcontent.readline()
                    udpcontent=uc[(len(uc)-19):(len(uc)-1)]
                    nc=udpcontent
                    nc1=binascii.unhexlify(nc)  #change HEX to string
                    newcontent='"'+nc1+'"'
                    cont3= "The content in the UDP packet is (last nine characters): %s\n"%newcontent
                    vmnew=vmnew+'\n'+cont3
                    print cont3 #content
                    self.log.writeText(cont3,'BLUE')
                    #---------------Router Redirect new attack----------------
                    cmd="iptables -t nat -A PREROUTING -d 1.0.0.2 -p udp --dport %d -j DNAT --to 1.0.0.9:%d"%(dstport,dstport) # mirroting, change packet from router-> host to router->protect VM->host
                    cmd3="iptables -A FORWARD -d 1.0.0.2 -p udp --dport %d -j ACCEPT"%dstport
                    cmd4="iptables -A FORWARD -d 1.0.0.9 -p udp --dport %d -j ACCEPT"%dstport     
                    con4="UDP flood attack is redirected to the protected VM from the router\n"
                    routernew=con4  #save message for printing on Router Panel(GUI)
                    #--------------default method to protect against UDP zero day attack is to use IPS------------------
                    fsnort.write('drop udp %s any -> 1.0.0.2 %d (msg:"drop more udp";content:%s;sid:100;)'%(src,dstport,newcontent)) #dynamically add new rules in Snort_inline my.rules file for filtering attacks.
                    fsnort.write('\n')
                    fcontent.close()
                    fsnort.close()  
                    #thread.start_new_thread(self.ssh_cmd,(ip, user, passwd, cmd))
		    #thread.start_new_thread(self.ssh_cmd,(ip, user, passwd, cmd3))
		    #thread.start_new_thread(self.ssh_cmd,(ip, user, passwd, cmd4))
	            self.ssh_cmd(ip, user, passwd, cmd)
                    self.ssh_cmd(ip, user, passwd, cmd3)
                    self.ssh_cmd(ip, user, passwd, cmd4)
                    #self.router.hlable=wx.StaticText(self.router,-1,label=con4,pos=(200,80))
                    #self.router.hlabel.SetLabel(con4)
                    #self.router.hlabel.SetForegroundColour('Blue')
                    self.log.writeText(con4,'BLACK')
                    #----------------Set Iptables for the VM mirroring-------------
		    print "TEST ATTACK\n"
                    cmd1="iptables -t nat -A PREROUTING -d 1.0.0.9 -p udp --dport %d -j DNAT --to 1.0.0.2:%d"%(dstport,dstport)
                    cmd2="iptables -A FORWARD -d 1.0.0.2 -p udp --dport %d -j ACCEPT"%dstport
                    cmd5='iptables -I FORWARD -d 1.0.0.2 -p udp --dport %d -j QUEUE'%dstport
                    cont5= "The Front VM forwards the legal packets (IPS) to the attacked Host\n"
                    vmnew=vmnew+'\n'+cont5
                    print cont5
                    self.log.writeText(cont5,'BLUE')
                    os.system(cmd1) 
                    os.system(cmd2)
                    os.system(cmd5)
                    con6="Write new rules to IPS (Snort_Inline) to drop the illegal UDP packets\n"
                    vmnew=vmnew+'\n'+con6
                    print con6
                    self.log.writeText(con6,'BLUE')
                        
                    os.system("killall -9 snort_inline") 
                    os.system("snort_inline -c /etc/snort_inline/snort_inline.conf -Q -N -l /var/log/snort_inline/ \-t /var/log/snort_inline/ -v -D")
                    print "unknown snort_starts"
                    point=point+1
                    con7= "Host is protected against UDP flood\n"
                    hostnew=con7
                    print hostnew
                    frouternew=open('/home/Write/routerstring.txt','a') #add message for Router Panel
                    frouternew.write(routernew)
                    frouternew.close()
                    self.log.writeText(con7,'GREEN')
#---------------------------TCP SYN----------------------------------   
            elif(l2.find(su1)>=0 and l2.find(ipdest)>=0):     #If it is TCP SYN attack 
                if(point==0):
                    con1= "The attack is TCP SYN Attack\n"
                    vmnew=con1
                    print con1
                    self.log.writeText(con1,'BLUE')
                    tmp=l2.split(' ')
                    leng=len(tmp)
                    for i in range (0,leng):
                        if(cmp(tmp[i],'')!=0):
                            string.append(tmp[i])        
                    src=string[1] #analyze NO.
                    ds=string[7]         
		    if (cmp(ds,"telnet")==0):  
			dstport='23' 
                    	con2= "The attacked TCP Port is: %s\n"%dstport   
                    	vmnew=vmnew+'\n'+con2
                    	print con2
                    elif (cmp(ds,"netbios-ssn")==0): #example if it is TCP 139
                        dstport='139' 
                    	con2= "The attacked TCP Port is: %s\n"%dstport   
                    	vmnew=vmnew+'\n'+con2
                    	print con2
		    elif (cmp(ds,"http")==0):  
			dstport='80' 
                    	con2= "The attacked TCP Port is: %s\n"%dstport   
                    	vmnew=vmnew+'\n'+con2
                    	print con2
		    else:
			con2=ds+'\n This is not DoS attack.'
			vmnew=vmnew+'\n'+con2
			
                    	print con2

                    fip.close()
                    self.log.writeText(con2,'BLUE')
                    #----------Mirroring--------------
                    cmd="iptables -t nat -A PREROUTING -d 1.0.0.2 -p tcp --dport %s -j DNAT --to 1.0.0.9:%s"%(dstport,dstport)
                    #cmd3="iptables -A FORWARD -d 1.0.0.2 -p tcp --dport %s -j ACCEPT"%d  stport
                    #cmd4="iptables -A FORWARD -d 1.0.0.9 -p tcp --dport %s -j ACCEPT"%dstport     
                    
                    
                    self.ssh_cmd(ip, user, passwd, cmd)
		    con3= "TCP packets are redirected to the protected VM from the router\n."
                    routernew=con3
                    print con3
                    #self.ssh_cmd(ip, user, passwd, cmd3)
		    #thread.start_new_thread(self.ssh_cmd,(ip, user, passwd, cmd))
		    #thread.start_new_thread(self.ssh_cmd,(ip, user, passwd, cmd3))

                    #self.ssh_cmd(ip, user, passwd, cmd4)
                    #self.router.hlable=wx.StaticText(self.router,-1,label=con3,pos=(200,80)
                    #self.router.hlabel.SetLabel(con3)
                    #self.router.hlabel.SetForegroundColour('Blue')
                    self.log.writeText(con3,'BLACK')
                    #------------VM commands for mirroring------------
                    cmd1="iptables -t nat -A PREROUTING -d 1.0.0.9 -p udp --dport %s -j DNAT --to 1.0.0.2:%s"%(dstport,dstport)
                    #cmd2="iptables -A FORWARD -d 1.0.0.2 -p tcp --dport %s -j ACCEPT"%dstport 
                    #cmd3='iptables -I FORWARD -d 1.0.0.2 -p udp --dport %d -j QUEUE'%dstport    
                    con4= "Drop the TCP SYN Attack packtes\n"
                    vmnew=vmnew+'\n'+con4
                    print con4
                    self.log.writeText(con4,'BLUE')
                    os.system(cmd1)
                    #os.system(cmd2) 
                    os.system('iptables -A FORWARD -p tcp -d 1.0.0.2 --dport %s -j DROP'%dstport)             
		    os.system('iptables -A INPUT -p tcp --dport %s -j LOG --log-level 5 --log-prefix "IPTABLES"'%dstport)    
		    os.system('iptables -A OUTPUT -p tcp --dport %s -j LOG --log-level 5 --log-prefix "IPTABLES"'%dstport) 
		    os.system('iptables -A FORWARD -p tcp --dport %s -j LOG --log-level 5 --log-prefix "IPTABLES"'%dstport)     
                    point=point+1
                    con5="Host is protected against TCP SYN Attack\n"
                    hostnew=hostnew+'\n'+con5
                    print hostnew
                    self.log.writeText(con5,'GREEN')
                    frouternew=open('/home/Write/routerstring.txt','a')
                    frouternew.write(routernew)
                    frouternew.close()
                    #self.log.writeText(con5,'GREEN')
                    #----------------ICMP Protocol Attack --------------------------------------------------
            elif(l2.find(su2)>=0 and l2.find(ipdest)>=0):
                if(point==0):     
                    con1= "The unknown attack is ICMP Protocal flood"
                    vmnew=vmnew+'\n'+con1
                    print con1    
                    self.log.writeText(con1,'BLUE') 
                    fcontent=open('/home/file/capunknowncontent.txt','r')
                    fsnort=open('/etc/snort_inline/drop-rules/my.rules','a')
                    uc=fcontent.readline()
                    udpcontent=uc[(len(uc)-18):(len(uc)-10)]
                    nc=udpcontent
                    nc1=binascii.unhexlify(nc) #change HEX message to String which is the content in attack packets 
                    newcontent='"'+str(nc1)+'"'        
                    if (cmp(nc,"")==0): #ICMP Flood no message inside
                        con2= "The Attack is ICMP flood attack, the Snort_Inline is running in the background"
                        vmnew=vmnew+'\n'+con2
                        print con1
                        self.log.writeText(con2,'BLUE')
                        os.system("killall -9 snort_inline")
                        os.system("snort_inline -c /etc/snort_inline/snort_inline.conf -Q -N -l /var/log/snort_inline/ \-t /var/log/snort_inline/ -v -D")        
                    else: #POD has content inside the packets, check last 10 characters of the long message and add new rules in my.rules file
                        con3="The content in the ICMP packet includes (9 characters): %s\n"%newcontent    
                        vmnew=vmnew+'\n'+con3
                        print con3
                        self.log.writeText(con3,'BLUE')
                        con4= "Add a new ICMP rule in IPS\n"
                        vmnew=vmnew+'\n'+con4
                        print con4
                        self.log.writeText(con4,'BLUE')
                        fsnort.write('drop icmp any any -> 1.0.0.2 any (msg:"drop icmp dynamic";content:%s;sid:1000;)'%newcontent)#new rule
                        fsnort.write('\n')
                        fcontent.close()
                        fsnort.close()
                        con5="Run IPS in background"
                        vmnew=vmnew+'\n'+con5
                        print con5
                        self.log.writeText(con5,'BLUE')
                        os.system('iptables -I FORWARD -p icmp -d 1.0.0.2 -j QUEUE')  #set iptables
                        os.system("killall -9 snort_inline")
                        os.system("snort_inline -c /etc/snort_inline/snort_inline.conf -Q -N -l /var/log/snort_inline/ \-t /var/log/snort_inline/ -v -D")#run snort_inline 
                        point=point+1
                        con6= "Host is protected against Ping of Death Attack Attack"
                        hostnew=hostnew+'\n'+con6
                        print hostnew 
                        self.log.writeText(con6,'GREEN')               
                    point=point+1 
                    fvmnew=open('/home/Write/vmstring.txt','a')
                    fvmnew.write(vmnew)
                    fvmnew.close()
                    fhostnew=open('/home/Write/hoststring.txt','a')
                   
                    fhostnew.write(hostnew)
                    fhostnew.close()

    #------------------Network Disconnection-----------
    def disconnection(self):
        print "The host is disconnect to network \n"
        os.system("python disconnection.py") # run disconnection script
        Disconnect()
    #------------------Unknown Send Command-------------
    def communication_send(self):
        s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.sendto('send',('1.0.0.2',295))
        s.close()
    #--------------------------Unknown Communication Receive----------
    def communication_receive(self):
        
            
            s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            s.bind(('',244)) #this script run on 1.0.0.9 which is the protected VM
    
            packet_data,addr = s.recvfrom(102400000)
           
	    s.close()
	    file_packet_write=open('/home/file/data.txt','w')
	    file_packet_write.write(packet_data)
	    file_packet_write.close()
	    file_packet=open('/home/file/data.txt','r')
            data=file_packet.readlines()
	    file_packet.close()
            number=len(data)
	    line=data[0:number]
	    new=""
            for i in line:
	    	new=new+i
	    string_new=new.split('$$$$')
            
	    packetinfo=string_new[0]
	    
	    packetdata=string_new[1]
	    
	    #-------split into 2 files-----------
	    unknown=open('/home/file/capunknown.txt','w')
	    unknown.write(packetinfo)

	    unknowndata=open('/home/file/capunknowncontent.txt','w')
	    if(cmp(unknowndata,"")==0):
		unknowndata.write("")
	    else:
		unknowndata.write(packetdata)

	    unknown.close()
	    unknowndata.close()
   #=======Sending ALL, SQL, CPU, Mem, Packet for Host to forecast and send back===========
    def Send(self,command):
	print "Sending"
    	client = socket.socket (socket.AF_INET,socket.SOCK_DGRAM)  
	client.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1) 
	client.connect(("1.0.0.2",3000))     
	client.send(command)
        #command="All"
        #client.send(command,("1.0.0.2",300))# let the host estimate values of future state.
	client.close()
   #======Receving Forecasting Data of CPU, Mem, PacketRate, SQL Injection Attacks from the Host===
    def Receive(self,command):
	
        print"Receiveing"
        s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('',256)) #this script run on 1.0.0.9 which is the protected VM
    
        data,addr = s.recvfrom(1024)
        if not data:
               print 'The responses from the Host Forecaster has exited!'
               return 0
            
        s.close()
       
        returnlist=[]
	print "data is ",data
	#========All Attacks and Parameters=====
        if(cmp(command,'All')==0):
		returnlist=self.SplitReceivedData(data)
	#========Estimation of CPU Only============
	if(cmp(command,'CPU')==0):
		if(float(float(data))<44): #----CPU IDle---
			self.CPUState='Abnormal' #---for prevention system to choose how to prevent the system
                    	Cabnormal="The forecaster estimitate the CPU Utilization is higher than the threashold. The high utilization of CPU may caused by known or unknown attacks. The Ave.Value is %s"%data
                        self.log.writeText(Cabnormal,'Red')
		else:
			Cabnormal="The forecaster estimitate the CPU Utilization is less than the threashold.The Ave.Value is %s"%data
                        self.log.writeText(Cabnormal,'Blue')
	#========Estimation of Mem Only============
	if(cmp(command,'Mem')==0):
		if(float(float(data))<322468.8): #----CPU IDle---test MEM 430000
			self.MemState='Abnormal' #---for prevention system to choose how to prevent the system
                    	Cabnormal="The forecaster estimitate the Mem Utilization is higher than the threashold. The high utilization of Mem may caused by known or unknown attacks. The Ave.Value is %s"%data
                        self.log.writeText(Cabnormal,'Red')
		else:
			Cabnormal="The forecaster estimitate the Mem Utilization is less than the threashold.The Ave.Value is %s"%data
                        self.log.writeText(Cabnormal,'Blue')
	#========Estimation of packet rate Only============
	if(cmp(command,'Packet')==0):
		if(float(float(data))>368): #----CPU IDle---
			self.PacketState='Abnormal' #---for prevention system to choose how to prevent the system
                    	Cabnormal="The forecaster estimitate the Packet Rate is higher than the threashold. The high Packet Rate may caused by known or unknown attacks. The Ave.Value is %s"%data
                        self.log.writeText(Cabnormal,'Red')
		else:
			Cabnormal="The forecaster estimitate the Packet Rate is less than the threashold.The Ave.Value is %s"%data
                        self.log.writeText(Cabnormal,'Blue')
	#========Estimation of Host SQL Only============
	if(cmp(command,'SQL')==0):
		if(float(float(data))>0): #----CPU IDle---
			self.ForecastAttack='SQL' #---for prevention system to choose how to prevent the system
                    	Cabnormal="The forecaster estimitate the SQL Injection Attack to the host will occur.The Ave.of the increasing number of SQL Injection Attack in the future 10 seconds is %s"%data
                        self.log.writeText(Cabnormal,'Red')
		else:
			Cabnormal="The forecaster estimitate the SQL Injection Attack won't occure."
                        self.log.writeText(Cabnormal,'Blue')
			self.ForecastAttack='Normal'
	print returnlist[0],returnlist[1],returnlist[2]
	self.Prevention(self.ForecastAttack,self.CPUState,self.MemState,self.PacketState,command)
	time.sleep(10)
#===========Split Data of CPU, MEM, PAcket, SQL when command is 'ALL'============
    def SplitReceivedData(self,data):
	CPU=data.split(',')[0]
	Mem=data.split(',')[1]
   	Packet=data.split(',')[2]
        SQL=data.split(',')[3]
 	SQL_Difference=data.split(',')[4]
	self.CPUState='Normal'
	self.MemState='Normal'
	self.PacketState='Normal'
	returnlist=[]
	if(float(CPU)<44): #----CPU IDle---
			self.CPUState='Abnormal' #---for prevention system to choose how to prevent the system
                    	Cabnormal="The forecaster estimitate the CPU Utilization is higher than the threashold. The high utilization of CPU may caused by known or unknown attacks.The Ave.Value is %s"%CPU
                        self.log.writeText(Cabnormal,'Red')
	if(float(Mem)<322468.8):#--Mem Available---
			self.MemState='Abnormal' #---for prevention system to choose how to prevent the system
                    	Cabnormal="The forecaster estimitate the Mem Utilization is higher than the threashold. The high utilization of Mem may caused by known or unknown attacks.The Ave.Value is %s"%Mem
                        self.log.writeText(Cabnormal,'Red')
	if(float(Packet)>368):#--Packet Received 10 times of normal--- #normal 1628
			self.PacketState='Abnormal' #---for prevention system to choose how to prevent the system
                    	Cabnormal="The forecaster estimitate the packet Rate is higher than the threashold. The high Rate of Packet may caused by known or unknown attacks.The Ave.Value is %s"%Packet
                        self.log.writeText(Cabnormal,'Red')
	if(float(SQL_Difference)>0):#--Packet Received 10 times of normal---
			self.ForecastAttack='SQL' #---for prevention system to choose how to prevent the system
                    	Cabnormal="The forecaster estimitate the SQL Injection Attack to the host will occur.The Ave.of the increasing number of SQL Injection Attack in the future 10 seconds is %s"%SQL_Difference
                        self.log.writeText(Cabnormal,'Red')
	else:
			#CPUState='normal'#---for prevention system to choose how to prevent the system
			#MemState='normal'
			#PacketState='normal'
			Cabnormal= "The forecaster estimitate the UDP,TCP,ICMP, POD and Host SQL Attack will not occur, the Estimated value of Host's CPU,Mem,Packet Rate will be normal."
                        self.log.writeText(Cabnormal,'BLUE')
	returnlist.append(self.CPUState)
	returnlist.append(self.MemState)
	returnlist.append(self.PacketState)
        return returnlist
    def Prevention(self,ForecastAttack,CPUState,MemState,PacketState,newattack):
	self.ForecastAttack=ForecastAttack
	self.CPUState=CPUState
	self.MemState=MemState
	self.PacketState=PacketState
	#=======Prevention===================
	
	if (cmp(self.ForecastAttack,'SQL')==0 ):
		print "SQL Attack Abnormal"
		newlist={}
		Decision=Calculation()
		#newlist=Decision.MAC()
		newlist=Decision.FuzzyControl()
		print 'SQL Method:'
		method=newlist['SQL']
		print method
		if(method=='Mod'):
			logstring="The Mod_Security module of Apache Server is running to block SQL Injection Attacks to the Host."
			print logstring
			self.log.writeText(logstring,'YELLOW')
		elif(method=='Filter'):
			self.unknown()
	elif(cmp(self.ForecastAttack,'Normal')==0 and cmp(self.CPUState,'Abnormal')==0 and cmp(self.PacketState,'Normal')==0):
		#==========Base on Controller Protection Ranking===================
		print "CPU is abnormal"
		newlist={}
		Decision=Calculation()
		#newlist=Decision.MAC()
		newlist=Decision.FuzzyControl()
		print 'TCP Method:'
		method=newlist['TCP_SYN']
		print method
		#if(method=='Disconnection'):
		
		#========Self Defined KillPriority()===================
		KillPriority()
		logstring="The CPU Utilization of the host is abnormally higher. The priority of the Process which cost the most CPU utilization is adjusted."
		print logstring
		self.log.writeText(logstring,'YELLOW')
	elif(cmp(self.ForecastAttack,'Normal')==0 and cmp(self.MemState,'Abnormal')==0 and cmp(self.PacketState,'Normal')==0):
		#==========Base on Controller Protection Ranking===================
		print "Mem is abnormal"
		newlist={}
		Decision=Calculation()
		#newlist=Decision.MAC()
		newlist=Decision.FuzzyControl()
		print 'TCP Method:'
		method=newlist['TCP_SYN']
		print method
		
		#========Self Defined KillPriority()===================
		
		#KillPriority()
		logstring="The Mem Utilization of the host is abnormally higher. The Process which cost the most Mem utilization is killed."
		print logstring
		self.log.writeText(logstring,'YELLOW')
	elif(cmp(self.ForecastAttack,'Normal')==0 and cmp(self.PacketState,'Abnormal')==0):
		#==========Base on Controller Protection Ranking===================
		print "Packet is abnormal"
		newlist={}
		Decision=Calculation()
		#newlist=Decision.MAC()
		newlist=Decision.FuzzyControl()
		print 'TCP Method:'
		method=newlist['TCP_SYN']
		print method
		if(method=='Disconnection'):
			#logstring="The Mod_Security module of Apache Server is running to block SQL Injection Attacks to the Host."
			logstring="TCP Disconnection is implementing"
			print logstring
			self.disconnection()
			self.log.writeText(logstring,'YELLOW')
			
		elif(method=='Filter'):
			self.unknown()

		#========Self Defined KillPriority()===================
		#self.unknown()
		logstring="Unknown DoS attacks or Congestion is occured.The Dynamic Module is running to check payload of the incoming packets."
		print logstring
		self.log.writeText(logstring,'YELLOW')"""
	
