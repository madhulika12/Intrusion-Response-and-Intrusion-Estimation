from globe import *
from processdata import *
from preprocessing import *
from figure import *
#from main import *
#global routernew

class ButtonFunction():
    def __init__(self,log):
        self.log=log 
        self.working=0
    #def setLog(self, log)
        #self.log = log   
    def setLog(self, log):
        self.log = log
    #--------------IPS Function----------------------------
    def IPSfun(self): #function for IPS
#        if not  self.working:
#            #self.status.SetLabel('Starting Computation')
#            self.working = 1
#            self.need_abort = 0
            #
            #for i in range(0,1000): #If press IPS button, the method to protect the host is by IPS method 
                GlobeFun=Globe(self.log)
                icmp=0
                udp=0
                pod=0
                tcp=0
                normal=0
                List=[] #sort largest probability
                if(os.path.isfile('/home/Write/vmstring.txt')==True): #remove message for  previous loop which shown on panel 
                    os.system("rm /home/Write/vmstring.txt ")
            
                if(os.path.isfile('/home/Write/hoststring.txt')==True):
                    os.system("rm /home/Write/hoststring.txt ")
            
                if(os.path.isfile('/home/Write/routerstring.txt')==True):
                    os.system("rm /home/Write/routerstring.txt ")    
                    
                print "Collect current measurements of the system\n"
                self.log.Clear()
                self.log.writeText('Collect current measurements of the system','BLUE')
                #return
                #self.log.Clear()
                os.system("sar -r -n DEV -b -u 2 5 > /home/file/sar.txt")  #check current features of the system, CPU, Memory, Packet rate etc.
                #os.system("python /home/file/processdata.py") #preprocess raw data
                PData=ProcessData()
                #os.system("python /home/file/test_process2.py")#preprocess raw data
                PreProcess=Preprocessing()
                #os.system("python /home/file/figure.py") # draw figures of current system feautes
                Figure=graph()
                os.system("java -cp /home/weka-3-6-6/weka.jar weka.classifiers.bayes.NaiveBayes -p 11 -l /home/file/training.model -T /home/file/test.arff > /home/file/dump.out")
                    #---IDS check the suspicious flow is attack or not, if it is attack ,which kind of attack it is
                f1=open('/home/file/dump.out','r') #WEKA predict file
                wr=open('/home/file/new','w')#check latest 5 seconds' features of system
                
                #--------calculate the largest probability of the suspicious flow type--------------------
                lines = f1.readlines()
                f1.close()
                
                number=len(lines)
                l_list = lines[5:number-1] 
                for li in l_list:    
                    wr.write(li)
                wr.close()
                f1.close()
                f2=open('/home/file/new','r')
                lines2 = f2.readlines()
                number2=len(lines2)    
                l_list2=lines2[0:number2]
                for li2 in l_list2:
                    splitdata=li2.split('       ')
                    predict=splitdata[1]        
                    typef=predict.split(':')        
                    pretype=typef[2]        
                    if (cmp(pretype,'ICMP')==0):
                        icmp=icmp+1
                    elif(cmp(pretype,'UDP')==0):
                        udp=udp+1
                    elif (cmp(pretype,'TCP_SYN')==0):
                        tcp=tcp+1
                    elif (cmp(pretype,'POD')==0):
                        pod=pod+1
                    elif (cmp(pretype,'Normal')==0):
                        normal=normal+1
                pre_icmp=icmp/number2    
                pre_udp=udp/number2
                pre_tcp=tcp/number2
                pre_pod=pod/number2
                pre_normal=normal/number2    
                List={'ICMP':pre_icmp,'UDP':pre_udp,'TCPSYN':pre_tcp,'POD':pre_pod,'Normal':pre_normal} #list check largest probability    
                sort=sorted(List.items(), key=lambda d: d[1])
                large=sort[len(sort)-1]  #predicted attack     
                preattack=large[0]
                preattack2=sort[2]    
                preattack3=sort[1]    
                preattack4=sort[0]
                print "IDS module is running and the flow is defined as: %s\n"% preattack
                connection1="The suspicious flow is defined as %s "%preattack
                if(cmp(preattack,'Normal')!=0):
                    
                    #VmPanel=Vmpanel()
                    VmPanel.icon = wx.StaticBitmap(self, bitmap=wx.Bitmap('connect.png'),pos=(250,120))
                    wx.CallAfter(VmPanel)
                #elif
                #    VmPanel.icon = wx.StaticBitmap(self, bitmap=wx.Bitmap('connect.png'),pos=(250,120))
                self.log.writeText(connection1,'BLUE')
                previous=""
                
                #----host state----
                hostabnormal=GlobeFun.receive() # call receive function to get the state of the host, is it under attack or not.
                #connection2="The anomaly-based IDS on Host \n detected the victim host \n(Before Protected Method implemented) is \n: %s\n"%hostabnormal
                connection2="The anomaly-based IDS on Host detected the victim host(Before Protected Method implemented) is: %s\n"%hostabnormal
                print connection2
                self.log.writeText(connection2,'GREEN')
                hostconnection=connection2 
            
                #------------------Implement IPS for Attacks---------------------
                if(cmp(preattack,'UDP')==0 or cmp(preattack,'TCPSYN')==0 or cmp(preattack,'ICMP')==0 or cmp(preattack,'POD')==0): 
              
                    connection3="The controller decides to run IPS to protect against Attack\n" 
                    self.log.writeText(connection3,'BLUE')       
                    connection1=connection1+'\n'+connection3        
                    GlobeFun.UDP() #run snort_inline        
                    connection4="IPS is running in the background\n"    
                    self.log.writeText(connection4,'BLUE')    
                    connection1=connection1+'\n'+connection4
                    if (cmp(previous,'Network Disconnection')==0 ): #Remind System Administrator, if last loop implemented method is 'Network Disconnection adapter' or 'shutdown host',
                                                                         # Please make sure the host is connected to network properly
            
                        Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                        self.log.writeText(Connectionsp,'RED')
                        connection1=connection1+'\n'+Connectionsp
                    
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                        self.log.writeText(Connectionsp,'RED')
                        connection1=connection1+'\n'+Connectionsp
                        
                if (cmp(preattack,'Normal')==0):    #No attack
                    Connectionx="No attack,the controller does not need to work\n"  
                    self.log.writeText(Connectionx,'BLUE')          
                    connection1=connection1+'\n'+Connectionx
                    print "Normal connection1,%s " %connection1
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                        self.log.writeText(Connectionsp,'RED')
                        connection1=connection1+'\n'+Connectionsp        
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                        self.log.writeText(Connectionsp,'RED')
                        connection1=connection1+'\n'+Connectionsp
            
                #---------write--------  # Print out on GUI Panel 
                fvm=open('/home/Write/vmstring.txt','w')
                #print "write connection1 %s" %connection1
                fvm.write(connection1)
                fvm.close()
                fhost=open('/home/Write/hoststring.txt','w')
                fhost.write(hostconnection)
                fhost.close()
                #-------------------------receive state from host-------------------------------
            
                host2=GlobeFun.receive()      
                connection14="The anomaly-based IDS on Host detected the victim host (after protected method) is: %s\n"%host2
                self.log.writeText(connection14,'GREEN')
                print connection14
                hostnew=""
                connectnew=""
                hostnew=hostnew+'\n'+connection14
                fvm3=open('/home/Write/vmstring.txt','a')    
                #-- Dynamic module run unknow() function if the previous method cannot protect the host (novel attack) or the host is under heavy load (cannot communicate with host) --------------------
                if(((cmp(hostabnormal,'abnormal')==0) and (cmp(host2,'abnormal')==0))or ((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'abnormal')==0))):
                    connection15= "The attack is not in our database or it is misclassified,the wireshark is running to analyze attack packets\n"
                    self.log.writeText(connection14,'RED')
                    connectnew=connectnew+'\n'+connection15
                    fvm3.write(connectnew)
                    fvm3.close()            
                    GlobeFun.unknown()
            
                    
                    if(((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'Timeout')==0)) or ((cmp(hostabnormal,'abnormal')==0) and (cmp(host2,'Timeout')==0))):
                        if (cmp(previous,'Network Disconnection')==0 ):  # 'Timeout' state of host means heavy load or the host is not in the network (disabled network adapter or shut down),check whether the
                                                                              # host is under heavy load or needed to be connected to network or not.
                
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            self.log.writeText(Connectionsp,'RED')
                            fvm3.write(Connectionsp)
                            fvm3.close()            
                            
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."      
                            self.log.writeText(Connectionsp,'RED')      
                            fvm3.write(connectnew)
                            fvm3.close()
                
                        else:            
                            connection18="Heavy Load of Unknown attack\n"
                            self.log.writeText(Connectionsp,'BLUE')
                            connectnew=connectnew+'\n'+connection18            
                            fvm3.write(connectnew)
                            fvm3.close()        
                            GlobeFun.unknown()
                        
                    
                print "--------------------------------"    
                fhost3=open('/home/Write/hoststring.txt','a')
                fhost3.write(hostnew)
                fhost3.close()
                wx.Yield()
#                if self.need_abort:
#                    self.status.SetLabel('Computation aborted')
#                    break
#                else:              
#                    self.status.SetLabel('Computation Completed')           
#                    self.working = 0
#----------------------Port Disablement----------------
    def Disablefun(self):
        #=======================================================================
        # if not self.working:
        #    self.status.SetLabel('Starting Computation')
        #    self.working = 1
        #    self.need_abort = 0
        #=======================================================================
            
            #for i in range(0,1):    #will change to 10000+ to run in background,here "1 loop" for checking whether it works or not
                GlobeFun=Globe(self.log)
                if(os.path.isfile('/home/Write/vmstring.txt')==True):
                    os.system("rm /home/Write/vmstring.txt ")
                if(os.path.isfile('/home/Write/hoststring.txt')==True):
                    os.system("rm /home/Write/hoststring.txt ")
                if(os.path.isfile('/home/Write/routerstring.txt')==True):
                    os.system("rm /home/Write/routerstring.txt ")
                #i=i+1        
                print "Collect current measurements of the system\n"
                self.log.Clear()
                self.log.writeText('Collect current measurements of the system','BLUE')
#                os.system("sar -r -n DEV -b -u 2 5 > sar.txt")
#                os.system("python /home/file/processdata.py")
#                os.system("python /home/file/test_process2.py")
#                os.system("python /home/file/figure.py")
                os.system("sar -r -n DEV -b -u 2 5 > /home/file/sar.txt")  #check current features of the system, CPU, Memory, Packet rate etc.
                #os.system("python /home/file/processdata.py") #preprocess raw data
                PData=ProcessData()
                #os.system("python /home/file/test_process2.py")#preprocess raw data
                PreProcess=Preprocessing()
                #os.system("python /home/file/figure.py") # draw figures of current system feautes
                Figure=graph()
                os.system("java -cp /home/weka-3-6-6/weka.jar weka.classifiers.bayes.NaiveBayes -p 11 -l /home/file/training.model -T /home/file/test.arff > /home/file/dump.out")
                
                f1=open('/home/file/dump.out','r')
                wr=open('/home/file/new','w')
                
                lines = f1.readlines()
                f1.close()
                icmp=0
                udp=0
                pod=0
                tcp=0
                normal=0
                List=[] #sort largest probability
                number=len(lines)
                l_list = lines[5:number-1] 
                for li in l_list:    
                    wr.write(li)
                wr.close()
                f1.close()
                f2=open('/home/file/new','r')
                lines2 = f2.readlines()
                number2=len(lines2)    
                l_list2=lines2[0:number2]
                for li2 in l_list2:
                    splitdata=li2.split('       ')
                    predict=splitdata[1]        
                    typef=predict.split(':')        
                    pretype=typef[2]        
                    if (cmp(pretype,'ICMP')==0):
                        icmp=icmp+1
                    elif(cmp(pretype,'UDP')==0):
                        udp=udp+1
                    elif (cmp(pretype,'TCP_SYN')==0):
                        tcp=tcp+1
                    elif (cmp(pretype,'POD')==0):
                        pod=pod+1
                    elif (cmp(pretype,'Normal')==0):
                        normal=normal+1
                
                pre_icmp=icmp/number2    
                pre_udp=udp/number2
                pre_tcp=tcp/number2
                pre_pod=pod/number2
                pre_normal=normal/number2
                List={'ICMP':pre_icmp,'UDP':pre_udp,'TCPSYN':pre_tcp,'POD':pre_pod,'Normal':pre_normal}    
                sort=sorted(List.items(), key=lambda d: d[1])    
                large=sort[len(sort)-1]    #the largest probability is "... Attack"
                preattack=large[0]
                preattack2=sort[2]    
                preattack3=sort[1]    
                preattack4=sort[0]
                
                print "IDS module is running and the flow is defined as: %s\n"% preattack
                
                connection1="The suspicious flow is defined as %s "%preattack
                self.log.writeText(connection1,'BLUE')
                previous=""
                hostabnormal=GlobeFun.receive()
                connection2="The anomaly-based IDS on Host detected the victim host (Before Protected Method implemented) is: %s\n"%hostabnormal    
                hostconnection=connection2 
                self.log.writeText(connection2,'GREEN')
                print connection2
                #-------------------UDP Port Disablement--------------
                if(cmp(preattack,'UDP')==0):
                    connection5="The controller decides to drop the UDP packet to protect against UDP Flood Attack as IPS does not work fine\n"
                    connection1=connection1+'\n'+connection5
                    self.log.writeText(connection5,'BLUE')   
                    print connection5
                    connection6="The UDP packets pass through port 5009 are considered as UDP Flood which is dropped\n"
                    self.log.writeText(connection6,'BLUE')   
                    GlobeFun.UDP2() #UDP Port Disablement
                    connection1=connection1+'\n'+connection6
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                    
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                #----------------TCP Disable-----------
                if(cmp(preattack,'TCPSYN')==0):
                    connection5="The controller decides to Port Disablement to protect against TCPSYN Flood Attack \n"
                    connection1=connection1+'\n'+connection5
                    self.log.writeText(connection5,'BLUE')   
                    print connection5
                    connection6="The TCPSYN packets pass through port 135 are considered as TCPSYN Flood which is dropped\n"
                    self.log.writeText(connection5,'BLUE')   
                    GlobeFun.TCP2() #TCP Port Disablement
                    connection1=connection1+'\n'+connection6
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                     
                 
                #-------------------ICMP POD-------------
                if(cmp(preattack,'ICMP')==0 or cmp(preattack,'POD')==0 ):
                    connection5="The controller decides to Port Disablement,\n but ICMP Protocol packets has no port,\n drop the ICMP packets instead\n"
                    connection1=connection1+'\n'+connection5
                    self.log.writeText(connection5,'BLUE')
                    print connection5
                    GlobeFun.POD2() #disable all icmp packets
                    connection6="ICMP Packets to the host are dropped\n"   
                    self.log.writeText(connection6,'BLUE')     
                    connection1=connection1+'\n'+connection6
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                if (cmp(preattack,'Normal')==0):    
                        Connectionx="No attack,the controller does not need to work\n"    
                        self.log.writeText(Connectionx,'BLUE')        
                        connection1=connection1+'\n'+Connectionx
                        print "Normal connection1,%s " %connection1
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                fvm=open('/home/Write/vmstring.txt','w')    
                fvm.write(connection1)
                fvm.close()
                fhost=open('/home/Write/hoststring.txt','w')
                fhost.write(hostconnection)
                fhost.close()
                #-------------------------receive state from host-------------------------------
                host2=GlobeFun.receive()      
                connection14="The anomaly-based IDS on Host detected the victim host (after protected method) is: %s\n"%host2
                print connection14    
                self.log.writeText(connection14,'GREEN')
                hostnew=""
                connectnew=""
                hostnew=hostnew+'\n'+connection14
                fvm3=open('/home/Write/vmstring.txt','a')    
                if(((cmp(hostabnormal,'abnormal')==0) and (cmp(host2,'abnormal')==0))or ((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'abnormal')==0))):
                    connection15= "The attack is not in our database or it is misclassified,the wireshark is running to analyze attack packets\n"
                    self.log.writeText(connection15,'BLUE')
                    connectnew=connectnew+'\n'+connection15
                    fvm3.write(connectnew) #message print on VM panel
                    fvm3.close()    
                    GlobeFun.unknown()        
                
                if(((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'Timeout')==0)) or ((cmp(hostabnormal,'abnormal')==0) and (cmp(host2,'Timeout')==0))):
                    if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            fvm3.write(Connectionsp)#message print on VM panel
                            fvm3.close()    
                            self.log.writeText(Connectionsp,'RED')
                    elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."            
                            fvm3.write(connectnew)
                            fvm3.close()
                            self.log.writeText(Connectionsp,'RED')
                    else:
                            connection18="Heavy Load of Unknown attack\n"
                            self.log.writeText(connection18,'BLUE')
                            connectnew=connectnew+'\n'+connection18
                            print connectnew
                            fvm3.write(connectnew)
                            fvm3.close()        
                            GlobeFun.unknown()            
                 
                print "--------------------------------"        
                fhost3=open('/home/Write/hoststring.txt','a')
                fhost3.write(hostnew)
                fhost3.close()
                wx.Yield()
#                if self.need_abort:
#                    self.status.SetLabel('Computation aborted')
#                    break
#                else:                
#                    self.status.SetLabel('Computation Completed')           
#                    self.working = 0
        
    #--------------------------------------NetworkFun---------------------
    def Networkfun(self):
        #=======================================================================
        # if not self.working:
        #    self.status.SetLabel('Starting Computation')
        #    self.working = 1
        #    self.need_abort = 0
        #=======================================================================
                GlobeFun=Globe(self.log)
                
                if(os.path.isfile('/home/Write/vmstring.txt')==True):
                    os.system("rm /home/Write/vmstring.txt ")
            
                if(os.path.isfile('/home/Write/hoststring.txt')==True):
                    os.system("rm /home/Write/hoststring.txt ")
                if(os.path.isfile('/home/Write/routerstring.txt')==True):
                    os.system("rm /home/Write/routerstring.txt ")
                #i=i+1        
                print "Collect current measurements of the system\n"
                self.log.Clear()
                self.log.writeText('Collect current measurements of the system','BLUE')
#                os.system("sar -r -n DEV -b -u 2 5 > /home/file/sar.txt")
#                os.system("python /home/file/processdata.py")
#                os.system("python /home/file/test_process2.py")
#                os.system("python /home/file/figure.py")
                os.system("sar -r -n DEV -b -u 2 5 > /home/file/sar.txt")  #check current features of the system, CPU, Memory, Packet rate etc.
                #os.system("python /home/file/processdata.py") #preprocess raw data
                PData=ProcessData()
                #os.system("python /home/file/test_process2.py")#preprocess raw data
                PreProcess=Preprocessing()
                #os.system("python /home/file/figure.py") # draw figures of current system feautes
                Figure=graph()
                os.system("sar -r -n DEV -b -u 2 5 > /home/file/sar.txt")  #check current features of the system, CPU, Memory, Packet rate etc.
                #os.system("python /home/file/processdata.py") #preprocess raw data
                PData=ProcessData()
                #os.system("python /home/file/test_process2.py")#preprocess raw data
                PreProcess=Preprocessing()
                #os.system("python /home/file/figure.py") # draw figures of current system feautes
                Figure=graph()
                os.system("java -cp /home/weka-3-6-6/weka.jar weka.classifiers.bayes.NaiveBayes -p 11 -l /home/file/training.model -T /home/file/test.arff > /home/file/dump.out")
                f1=open('/home/file/dump.out','r')
                wr=open('/home/file/new','w')
                lines = f1.readlines()
                f1.close()
                icmp=0
                udp=0
                pod=0
                tcp=0
                normal=0
                List=[] #sort largest probability
                number=len(lines)
                l_list = lines[5:number-1] 
                for li in l_list:
                    wr.write(li)
                wr.close()
                f1.close()
                f2=open('/home/file/new','r')
                lines2 = f2.readlines()
                number2=len(lines2)    
                l_list2=lines2[0:number2]
                for li2 in l_list2:
                    splitdata=li2.split('       ')
                    predict=splitdata[1]        
                    typef=predict.split(':')        
                    pretype=typef[2]        
                    if (cmp(pretype,'ICMP')==0):
                        icmp=icmp+1
                    elif(cmp(pretype,'UDP')==0):
                        udp=udp+1
                    elif (cmp(pretype,'TCP_SYN')==0):
                        tcp=tcp+1
                    elif (cmp(pretype,'POD')==0):
                        pod=pod+1
                    elif (cmp(pretype,'Normal')==0):
                        normal=normal+1
                pre_icmp=icmp/number2    
                pre_udp=udp/number2
                pre_tcp=tcp/number2
                pre_pod=pod/number2
                pre_normal=normal/number2
                List={'ICMP':pre_icmp,'UDP':pre_udp,'TCPSYN':pre_tcp,'POD':pre_pod,'Normal':pre_normal}    
                sort=sorted(List.items(), key=lambda d: d[1])
                large=sort[len(sort)-1]    
                preattack=large[0]
                preattack2=sort[2]    
                preattack3=sort[1]    
                preattack4=sort[0]    
                print "IDS module is running and the flow is defined as: %s\n"% preattack
                connection1="The suspicious flow is defined as %s "%preattack
                self.log.writeText(connection1,'BLUE')
                previous=""
                hostabnormal=GlobeFun.receive()
                connection2="The anomaly-based IDS on Host detected the victim host (Before Protected Method implemented) is: %s\n"%hostabnormal
                hostconnection=connection2 
                self.log.writeText(connection2,'GREEN')
                print connection2
                #----------------Attack disable Host's Network Adapter--------------    
                if(cmp(preattack,'UDP')==0 or cmp(preattack,'TCPSYN')==0 or cmp(preattack,'ICMP')==0 or cmp(preattack,'POD')==0):
                    connection7= "The Controller decides to disconnet Network to protect against the attack to Host\n"
                    print connection7      
                    self.log.writeText(connection7,'BLUE')  
                    connection1=connection1+'\n'+connection7        
                    GlobeFun.disconnection()
                    connection8="Host network is disabeled.\n"
                    self.log.writeText(connection8,'BLUE')
                    hostconnection = hostconnection+connection8
                    print hostconnection
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                        connection1=connection1+'\n'+Connectionsp    
                        self.log.writeText(Connectionsp,'RED')    
                    elif(cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                    previous="Network Disconnection"
                    
                if (cmp(preattack,'Normal')==0):    
                    Connectionx="No attack,the controller does not need to work\n"            
                    connection1=connection1+'\n'+Connectionx
                    self.log.writeText(Connectionx,'BLUE')
                    print "Normal connection1,%s " %connection1
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                        connection1=connection1+'\n'+Connectionsp       
                        self.log.writeText(Connectionsp,'RED') 
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                
                #-----------------Write------------------
                fvm=open('/home/Write/vmstring.txt','w')    
                fvm.write(connection1)
                fvm.close()
                fhost=open('/home/Write/hoststring.txt','w')
                fhost.write(hostconnection)
                fhost.close()
            
            #-------------------------receive state from host-------------------------------
            
                host2=GlobeFun.receive()      
                connection14="The anomaly-based IDS on Host detected the victim host (after protected method) is: %s\n"%host2
                self.log.writeText(connection14,'GREEN')
                print connection14
                hostnew=""
                connectnew=""
                hostnew=hostnew+'\n'+connection14
                fvm3=open('/home/Write/vmstring.txt','a')    # add more print out message
                if(((cmp(hostabnormal,'abnormal')==0) and (cmp(host2,'abnormal')==0))or ((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'abnormal')==0))):
                    connection15= "The attack is not in our database or it is misclassified,the wireshark is running to analyze attack packets\n"
                    connectnew=connectnew+'\n'+connection15
                    self.log.writeText(connection15,'BLUE')
                    fvm3.write(connectnew)
                    fvm3.close()            
                    GlobeFun.unknown()    
            
                    if(((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'Timeout')==0)) or ((cmp(hostabnormal,'abnormal')==0) and (cmp(host2,'Timeout')==0))):
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            fvm3.write(Connectionsp)
                            fvm3.close()
                            self.log.writeText(Connectionsp,'RED')
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."            
                            fvm3.write(connectnew)
                            fvm3.close()
                            self.log.writeText(Connectionsp,'RED')
                        else:
                            connection18="Heavy Load of Unknown attack\n"
                            connectnew=connectnew+'\n'+connection18
                            self.log.writeText(connection18,'BLUE')
                            print connectnew
                            fvm3.write(connectnew) #write to file later print on VM panel
                            fvm3.close()
                                
                    
                print "--------------------------------"
                #time.sleep(10)    
                fhost3=open('/home/Write/hoststring.txt','a')
                fhost3.write(hostnew)#Print on Host Panel
                fhost3.close()
                wx.Yield()
#                if self.need_abort:
#                    self.status.SetLabel('Computation aborted')
#                    break
#                else:             
#                    self.status.SetLabel('Computation Completed')           
#                    self.working = 0
#-------------------------let legal user access host's resources if under attack---------------------------------
    def flowfun(self):
        #=======================================================================
        # if not self.working:
        #    self.status.SetLabel('Starting Computation')
        #    self.working = 1
        #    self.need_abort = 0
        #=======================================================================
           
            #for i in range(0,1):    
                GlobeFun=Globe(self.log)
                if(os.path.isfile('/home/Write/vmstring.txt')==True):
                    os.system("rm /home/Write/vmstring.txt ")
                if(os.path.isfile('/home/Write/hoststring.txt')==True):
                    os.system("rm /home/Write/hoststring.txt ")
                if(os.path.isfile('/home/Write/routerstring.txt')==True):
                    os.system("rm /home/Write/routerstring.txt ")
                #i=i+1        
                print "Collect current measurements of the system\n"
                self.log.Clear()
                self.log.writeText('Collect current measurements of the system','BLUE')
#                os.system("sar -r -n DEV -b -u 2 5 > /home/file/sar.txt")
#                os.system("python /home/file/processdata.py")
#                os.system("python /home/file/test_process2.py")
#                os.system("python /home/file/figure.py")
                os.system("sar -r -n DEV -b -u 2 5 > /home/file/sar.txt")  #check current features of the system, CPU, Memory, Packet rate etc.
                #os.system("python /home/file/processdata.py") #preprocess raw data
                PData=ProcessData()
                #os.system("python /home/file/test_process2.py")#preprocess raw data
                PreProcess=Preprocessing()
                #os.system("python /home/file/figure.py") # draw figures of current system feautes
                Figure=graph()
                os.system("java -cp /home/weka-3-6-6/weka.jar weka.classifiers.bayes.NaiveBayes -p 11 -l /home/file/training.model -T /home/file/test.arff > /home/file/dump.out")
                f1=open('/home/file/dump.out','r')
                wr=open('/home/file/new','w')
                lines = f1.readlines()
                f1.close()
                icmp=0
                udp=0
                pod=0
                tcp=0
                normal=0
                List=[] #sort largest probability
                number=len(lines)
                l_list = lines[5:number-1] 
                for li in l_list:    
                    wr.write(li)
                wr.close()
                f1.close()
            
                f2=open('/home/file/new','r')
                lines2 = f2.readlines()
                number2=len(lines2)    
                l_list2=lines2[0:number2]
                for li2 in l_list2:
                    splitdata=li2.split('       ')
                    predict=splitdata[1]        
                    typef=predict.split(':')        
                    pretype=typef[2]        
                    if (cmp(pretype,'ICMP')==0):
                        icmp=icmp+1
                    elif(cmp(pretype,'UDP')==0):
                        udp=udp+1
                    elif (cmp(pretype,'TCP_SYN')==0):
                        tcp=tcp+1
                    elif (cmp(pretype,'POD')==0):
                        pod=pod+1
                    elif (cmp(pretype,'Normal')==0):
                        normal=normal+1
            
                pre_icmp=icmp/number2    
                pre_udp=udp/number2
                pre_tcp=tcp/number2
                pre_pod=pod/number2
                pre_normal=normal/number2
                List={'ICMP':pre_icmp,'UDP':pre_udp,'TCPSYN':pre_tcp,'POD':pre_pod,'Normal':pre_normal}    
                sort=sorted(List.items(), key=lambda d: d[1])    
                large=sort[len(sort)-1]    
                preattack=large[0]
                preattack2=sort[2]    
                preattack3=sort[1]    
                preattack4=sort[0]
                
                print "IDS module is running and the flow is defined as: %s\n"% preattack
                connection1="The suspicious flow is defined as %s "%preattack
                self.log.writeText(connection1,'BLUE')
                previous=""
                hostabnormal=GlobeFun.receive()
                connection2="The anomaly-based IDS on Host detected the victim host (Before Protected Method implemented) is: %s\n"%hostabnormal
                hostconnection=connection2 
                self.log.writeText(connection2,'GREEN')
                print connection2
                #---------------UDP,TCP, ICMP,pod------------
                if(cmp(preattack,'UDP')==0 or cmp(preattack,'TCPSYN')==0 or cmp(preattack,'ICMP')==0 or cmp(preattack,'POD')==0):
                    connection10="Only legal users can access resources"
                    connection1=connection1+'\n'+connection10
                    GlobeFun.Legalflow() #run legal function
                    connection11="Registered user can access confidential data"
                    hostconnection = hostconnection+connection11
                    print hostconnection
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                        
                if (cmp(preattack,'Normal')==0):    
                    Connectionx="No attack,the controller does not need to work\n"   
                    self.log.writeText(connection1,'BLUE')         
                    connection1=connection1+'\n'+Connectionx
                    print "Normal connection1,%s " %connection1
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                        
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                
                
                #------------write-------------
                fvm=open('/home/Write/vmstring.txt','w')
                #print "write connection1 %s" %connection1
                fvm.write(connection1)
                fvm.close()
                fhost=open('/home/Write/hoststring.txt','w')
                fhost.write(hostconnection)
                fhost.close()
            
            #-------------------------receive state from host-------------------------------
            
                host2=GlobeFun.receive()      
                connection14="The anomaly-based IDS on Host detected the victim host (after protected method) is: %s\n"%host2
                print connection14
                self.log.writeText(connection14,'GREEN')
                hostnew=""
                connectnew=""
                hostnew=hostnew+'\n'+connection14
                fvm3=open('/home/Write/vmstring.txt','a')
                
                if(((cmp(hostabnormal,'abnormal')==0) and (cmp(host2,'abnormal')==0))or ((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'abnormal')==0))):
                    connection15= "The attack is not in our database or it is misclassified,the wireshark is running to analyze attack packets\n"
                    connectnew=connectnew+'\n'+connection15
                    self.log.writeText(connection15,'BLUE')
                    fvm3.write(connectnew)
                    fvm3.close()            
                    GlobeFun.unknown()
                
                    
                    if(((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'Timeout')==0)) or ((cmp(hostabnormal,'abnormal')==0) and (cmp(host2,'Timeout')==0))):
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            fvm3.write(Connectionsp)
                            fvm3.close()         
                            self.log.writeText(Connectionsp,'RED')   
                            
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."            
                            fvm3.write(connectnew)
                            fvm3.close()
                            self.log.writeText(Connectionsp,'RED')
                
                        else:            
                            connection18="Heavy Load of Unknown attack\n"
                            connectnew=connectnew+'\n'+connection18
                            self.log.writeText(connection18,'BLUE')
                            print connectnew
                            fvm3.write(connectnew)
                            fvm3.close()        
                            GlobeFun.unknown()            
                    
                print "--------------------------------"
                fhost3=open('/home/Write/hoststring.txt','a')
                fhost3.write(hostnew)
                fhost3.close()
                wx.Yield()
#                if self.need_abort:
#                    self.status.SetLabel('Computation aborted')
#                    break
#                else:
#                       
#                    self.status.SetLabel('Computation Completed')       
#                    self.working = 0
#----------------------------Firewallfun-----------------------------
    def Firewallfun(self):
        #=======================================================================
        # if not self.working:
        #    self.status.SetLabel('Starting Computation')
        #    self.working = 1
        #    self.need_abort = 0
        #=======================================================================
            
            #for i in range(0,1):    
                GlobeFun=Globe(self.log)
                if(os.path.isfile('/home/Write/vmstring.txt')==True):
                    os.system("rm /home/Write/vmstring.txt ")
            
                if(os.path.isfile('/home/Write/hoststring.txt')==True):
                    os.system("rm /home/Write/hoststring.txt ")
            
            
                if(os.path.isfile('/home/Write/routerstring.txt')==True):
                    os.system("rm /home/Write/routerstring.txt ")
                #i=i+1
                print "Collect current measurements of the system\n"
                self.log.Clear()
                self.log.writeText('Collect current measurements of the system','BLUE')
#                os.system("sar -r -n DEV -b -u 2 5 > /home/file/sar.txt")
#                os.system("python /home/file/processdata.py")
#                os.system("python /home/file/test_process2.py")
#                os.system("python /home/file/figure.py")
                os.system("sar -r -n DEV -b -u 2 5 > /home/file/sar.txt")  #check current features of the system, CPU, Memory, Packet rate etc.
                #os.system("python /home/file/processdata.py") #preprocess raw data
                PData=ProcessData()
                #os.system("python /home/file/test_process2.py")#preprocess raw data
                PreProcess=Preprocessing()
                #os.system("python /home/file/figure.py") # draw figures of current system feautes
                Figure=graph()
                os.system("java -cp /home/weka-3-6-6/weka.jar weka.classifiers.bayes.NaiveBayes -p 11 -l /home/file/training.model -T /home/file/test.arff > /home/file/dump.out")
            
                f1=open('/home/file/dump.out','r')
                wr=open('/home/file/new','w')
                lines = f1.readlines()
                f1.close()
                icmp=0
                udp=0
                pod=0
                tcp=0
                normal=0
                List=[] #sort largest probability
                number=len(lines)
                l_list = lines[5:number-1] 
                for li in l_list:    
                    wr.write(li)
                wr.close()
                f1.close()
            
                f2=open('/home/file/new','r')
                lines2 = f2.readlines()
                number2=len(lines2)
                
                l_list2=lines2[0:number2]
                for li2 in l_list2:
                    splitdata=li2.split('       ')
                    predict=splitdata[1]    
                    typef=predict.split(':')    
                    pretype=typef[2]        
                    if (cmp(pretype,'ICMP')==0):
                        icmp=icmp+1
                    elif(cmp(pretype,'UDP')==0):
                        udp=udp+1
                    elif (cmp(pretype,'TCP_SYN')==0):
                        tcp=tcp+1
                    elif (cmp(pretype,'POD')==0):
                        pod=pod+1
                    elif (cmp(pretype,'Normal')==0):
                        normal=normal+1
            
                pre_icmp=icmp/number2    
                pre_udp=udp/number2
                pre_tcp=tcp/number2
                pre_pod=pod/number2
                pre_normal=normal/number2
                List={'ICMP':pre_icmp,'UDP':pre_udp,'TCPSYN':pre_tcp,'POD':pre_pod,'Normal':pre_normal}    
                sort=sorted(List.items(), key=lambda d: d[1])    
                large=sort[len(sort)-1]
                preattack=large[0]
                preattack2=sort[2]    
                preattack3=sort[1]    
                preattack4=sort[0]
                
                print "IDS module is running and the flow is defined as: %s\n"% preattack
                connection1="The suspicious flow is defined as %s "%preattack
                self.log.writeText(connection1,'BLUE')
                previous=""
                #print 'check attack %s'% connection1
                hostabnormal=GlobeFun.receive()
                connection2="The anomaly-based IDS on Host detected the victim host(Before Protected Method implemented) is: %s\n"%hostabnormal
                hostconnection=connection2 
                self.log.writeText(connection2,'GREEN')
                print connection2
                #-----------------All Firewall------------------
                if(cmp(preattack,'UDP')==0 or cmp(preattack,'TCPSYN')==0 or cmp(preattack,'ICMP')==0 or cmp(preattack,'POD')==0):
                    connection9= "The OS default firewall is the best method which has already runned\n"
                    connection1=connection1+'\n'+connection9
                    self.log.writeText(connection9,'BLUE')
                    
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
            
                if (cmp(preattack,'Normal')==0):    
                    Connectionx="No attack,the controller does not need to work\n"        
                    connection1=connection1+'\n'+Connectionx
                    self.log.writeText(Connectionx,'BLUE')
                    print "Normal connection1,%s " %connection1
            
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                    
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                #------------write into file--------------
                fvm=open('/home/Write/vmstring.txt','w')    
                fvm.write(connection1)
                fvm.close()
                fhost=open('/home/Write/hoststring.txt','w')
                fhost.write(hostconnection)
                fhost.close()
            
            #-------------------------receive state from host-------------------------------
            
                host2=GlobeFun.receive()      
                connection14="The anomaly-based IDS on Host detected the victim host (after protected method) is: %s\n"%host2
                print connection14
                self.log.writeText(connection14,'GREEN')
                hostnew=""
                connectnew=""
                hostnew=hostnew+'\n'+connection14
                fvm3=open('/home/Write/vmstring.txt','a')
                
                if(((cmp(hostabnormal,'abnormal')==0) and (cmp(host2,'abnormal')==0))or ((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'abnormal')==0))):
                    connection15= "The attack is not in our database or it is misclassified,the wireshark is running to analyze attack packets\n"
                    connectnew=connectnew+'\n'+connection15
                    self.log.writeText(connection15,'BLUE')
                    fvm3.write(connectnew)
                    fvm3.close()            
                    GlobeFun.unknown()        
            
                    if(((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'Timeout')==0)) or ((cmp(hostabnormal,'abnormal')==0) and (cmp(host2,'Timeout')==0))):
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            fvm3.write(Connectionsp)
                            fvm3.close()  
                            self.log.writeText(Connectionsp,'RED')
                                                  
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."            
                            fvm3.write(connectnew)
                            fvm3.close()
                            self.log.writeText(Connectionsp,'RED')
                            
                        else:            
                            connection18="Heavy Load of Unknown attack\n"
                            self.log.writeText(connection18,'BLUE')
                            connectnew=connectnew+'\n'+connection18
                            print connectnew
                            fvm3.write(connectnew)
                            fvm3.close()        
                            GlobeFun.unknown()            
                        
                print "--------------------------------"
                #time.sleep(10)    
                fhost3=open('/home/Write/hoststring.txt','a')
                fhost3.write(hostnew)
                fhost3.close()
                wx.Yield()
#                if self.need_abort:
#                    self.status.SetLabel('Computation aborted')
#                    break
#                else:                
#                    self.status.SetLabel('Computation Completed')          
#                    self.working = 0
#---------------------------ShutDownfun-----------------------
    def ShutDownfun(self):
        #=======================================================================
        # if not self.working:
        #    self.status.SetLabel('Starting Computation')
        #    self.working = 1
        #    self.need_abort = 0
        #=======================================================================
            
            #for i in range(0,1):
                GlobeFun=Globe(self.log)
                if(os.path.isfile('/home/Write/vmstring.txt')==True):
                    os.system("rm /home/Write/vmstring.txt ")
            
                if(os.path.isfile('/home/Write/hoststring.txt')==True):
                    os.system("rm /home/Write/hoststring.txt ")
            
                if(os.path.isfile('/home/Write/routerstring.txt')==True):
                    os.system("rm /home/Write/routerstring.txt ")
                #i=i+1
                    
                print "Collect current measurements of the system\n"
                self.log.Clear()
                self.log.writeText('Collect current measurements of the system','BLUE')
#                os.system("sar -r -n DEV -b -u 2 5 > /home/file/sar.txt")
#                os.system("python /home/file/processdata.py")
#                os.system("python /home/file/test_process2.py")
#                os.system("python /home/file/figure.py")
                os.system("sar -r -n DEV -b -u 2 5 > /home/file/sar.txt")  #check current features of the system, CPU, Memory, Packet rate etc.
                #os.system("python /home/file/processdata.py") #preprocess raw data
                PData=ProcessData()
                #os.system("python /home/file/test_process2.py")#preprocess raw data
                PreProcess=Preprocessing()
                #os.system("python /home/file/figure.py") # draw figures of current system feautes
                Figure=graph()
                os.system("java -cp /home/weka-3-6-6/weka.jar weka.classifiers.bayes.NaiveBayes -p 11 -l /home/file/training.model -T /home/file/test.arff > /home/file/dump.out")
                f1=open('/home/file/dump.out','r')
                wr=open('/home/file/new','w')
                lines = f1.readlines()
                f1.close()
                icmp=0
                udp=0
                pod=0
                tcp=0
                normal=0
                List=[] #sort largest probability
                number=len(lines)
                l_list = lines[5:number-1] 
                for li in l_list:    
                    wr.write(li)
                wr.close()
                f1.close()
                f2=open('/home/file/new','r')
                lines2 = f2.readlines()
                number2=len(lines2)    
                l_list2=lines2[0:number2]
                for li2 in l_list2:
                    splitdata=li2.split('       ')
                    predict=splitdata[1]        
                    typef=predict.split(':')        
                    pretype=typef[2]        
                    if (cmp(pretype,'ICMP')==0):
                        icmp=icmp+1
                    elif(cmp(pretype,'UDP')==0):
                        udp=udp+1
                    elif (cmp(pretype,'TCP_SYN')==0):
                        tcp=tcp+1
                    elif (cmp(pretype,'POD')==0):
                        pod=pod+1
                    elif (cmp(pretype,'Normal')==0):
                        normal=normal+1
            
                pre_icmp=icmp/number2    
                pre_udp=udp/number2
                pre_tcp=tcp/number2
                pre_pod=pod/number2
                pre_normal=normal/number2
                List={'ICMP':pre_icmp,'UDP':pre_udp,'TCPSYN':pre_tcp,'POD':pre_pod,'Normal':pre_normal}    
                sort=sorted(List.items(), key=lambda d: d[1])    
                large=sort[len(sort)-1]    
                preattack=large[0]
                preattack2=sort[2]    
                preattack3=sort[1]    
                preattack4=sort[0]
                
                print "IDS module is running and the flow is defined as: %s\n"% preattack
                connection1="The suspicious flow is defined as %s "%preattack
                self.log.writeText(connection1,'BLUE')
                previous=""    
                hostabnormal=GlobeFun.receive()
                connection2="The anomaly-based IDS on Host detected the victim host (Before Protected Method implemented) is: %s\n"%hostabnormal
                hostconnection=connection2 
                self.log.writeText(connection2,'GREEN')
                print connection2
                #----------Shutdown all---------
                if(cmp(preattack,'UDP')==0 or cmp(preattack,'TCPSYN')==0 or cmp(preattack,'ICMP')==0 or cmp(preattack,'POD')==0):
                
                    connection12="Shut Down the Host is the best method."
                    
                    GlobeFun.Shutdown()
                    connection13="The host is shutted"
                    connection1=connection1+'\n'+connection12+'\n'+connection13
                    self.log.writeText(connection12,'BLUE')
                    self.log.writeText(connection13,'BLUE')
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                        connection1=connection1+'\n'+Connectionsp      
                        self.log.writeText(Connectionsp,'RED')  
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                    previous="Host Shutdown"
            
                if (cmp(preattack,'Normal')==0):    
                    Connectionx="No attack,the controller does not need to work\n"            
                    connection1=connection1+'\n'+Connectionx
                    self.log.writeText(Connectionx,'BLUE')
                    print "Normal connection1,%s " %connection1
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                    
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                #----------Write------------
                fvm=open('/home/Write/vmstring.txt','w')    
                fvm.write(connection1)
                fvm.close()
                fhost=open('/home/Write/hoststring.txt','w')
                fhost.write(hostconnection)
                fhost.close()
            #-------------------------receive state from host-------------------------------
            
                host2=GlobeFun.receive()      
                connection14="The anomaly-based IDS on Host detected the victim host (after protected method) is: %s\n"%host2
                print connection14
                self.log.writeText(connection14,'GREEN')
                hostnew=""
                connectnew=""
                hostnew=hostnew+'\n'+connection14
                fvm3=open('/home/Write/vmstring.txt','a')    
                if(((cmp(hostabnormal,'abnormal')==0) and (cmp(host2,'abnormal')==0))or ((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'abnormal')==0))):
                    connection15= "The attack is not in our database or it is misclassified,the wireshark is running to analyze attack packets\n"
                    connectnew=connectnew+'\n'+connection15
                    self.log.writeText(connection15,'BLUE')
                    fvm3.write(connectnew)
                    fvm3.close()            
                    GlobeFun.unknown()    
                    if(((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'Timeout')==0)) or ((cmp(hostabnormal,'abnormal')==0) and (cmp(host2,'Timeout')==0))):
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            fvm3.write(Connectionsp)
                            fvm3.close()            
                            self.log.writeText(Connectionsp,'RED')
                            
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            self.log.writeText(Connectionsp,'RED')
                            fvm3.write(connectnew)
                            fvm3.close()
                        else:            
                            connection18="Heavy Load of Unknown attack\n"
                            connectnew=connectnew+'\n'+connection18
                            print connectnew
                            fvm3.write(connectnew)
                            fvm3.close()        
                            GlobeFun.unknown()    
                    
                print "--------------------------------"        
                fhost3=open('/home/Write/hoststring.txt','a')
                fhost3.write(hostnew)
                fhost3.close()
                wx.Yield()
#                if self.need_abort:
#                    self.status.SetLabel('Computation aborted')
#                    break
#                else:                
#                    self.status.SetLabel('Computation Completed')
#                    self.working = 0
    
    
    #---------------------------Ranking button method based on ranking----------------------
    def OnStart(self):
        
#        if not self.working:
#            self.status.SetLabel('Starting Computation')
#            self.working = 1
#            self.need_abort = 0
           
            #for i in range(0,1): 
                GlobeFun=Globe(self.log)
                if(os.path.isfile('/home/Write/vmstring.txt')==True):
                    os.system("rm /home/Write/vmstring.txt ")
                if(os.path.isfile('/home/Write/hoststring.txt')==True):
                    os.system("rm /home/Write/hoststring.txt ")
                if(os.path.isfile('/home/Write/routerstring.txt')==True):
                    os.system("rm /home/Write/routerstring.txt ")
                #i=i+1        
                print "Collect current measurements of the system\n"
                self.log.Clear()
                self.log.writeText('Collect current measurements of the system','BLUE')
                os.system("sar -r -n DEV -b -u 2 5 > /home/file/sar.txt")
                #os.system("python /home/file/processdata.py")
                
                #os.system("python /home/file/test_process2.py")
                #os.system("python /home/file/figure.py")
                os.system("sar -r -n DEV -b -u 2 5 > /home/file/sar.txt")  #check current features of the system, CPU, Memory, Packet rate etc.
                #os.system("python /home/file/processdata.py") #preprocess raw data
                PData=ProcessData()
                #os.system("python /home/file/test_process2.py")#preprocess raw data
                PreProcess=Preprocessing()
                #os.system("python /home/file/figure.py") # draw figures of current system feautes
                Figure=graph()
                os.system("java -cp /home/weka-3-6-6/weka.jar weka.classifiers.bayes.NaiveBayes -p 11 -l /home/file/training.model -T /home/file/test.arff > /home/file/dump.out")
                f1=open('/home/file/dump.out','r')
                wr=open('/home/file/new','w')    
                lines = f1.readlines()
                f1.close()
                icmp=0
                udp=0
                pod=0
                tcp=0
                normal=0
                List=[] #sort largest probability
                number=len(lines)
                l_list = lines[5:number-1] 
                for li in l_list:    
                    wr.write(li)
                wr.close()
                f1.close()
                f2=open('/home/file/new','r')
                lines2 = f2.readlines()
                number2=len(lines2)    
                l_list2=lines2[0:number2]
                for li2 in l_list2:
                    splitdata=li2.split('       ')
                    predict=splitdata[1]        
                    typef=predict.split(':')        
                    pretype=typef[2]        
                    if (cmp(pretype,'ICMP')==0):
                        icmp=icmp+1
                    elif(cmp(pretype,'UDP')==0):
                        udp=udp+1
                    elif (cmp(pretype,'TCP_SYN')==0):
                        tcp=tcp+1
                    elif (cmp(pretype,'POD')==0):
                        pod=pod+1
                    elif (cmp(pretype,'Normal')==0):
                        normal=normal+1
                pre_icmp=icmp/number2
                pre_udp=udp/number2
                pre_tcp=tcp/number2
                pre_pod=pod/number2
                pre_normal=normal/number2
                List={'ICMP':pre_icmp,'UDP':pre_udp,'TCPSYN':pre_tcp,'POD':pre_pod,'Normal':pre_normal}    
                sort=sorted(List.items(), key=lambda d: d[1])
                large=sort[len(sort)-1]    
                preattack=large[0]
                preattack2=sort[2]    
                preattack3=sort[1]    
                preattack4=sort[0]
                print "IDS module is running and the flow is defined as: %s\n"% preattack
                connection1="The suspicious flow is defined as %s "%preattack
                self.log.writeText(connection1,'BLUE')
                previous=""    
                hostabnormal=GlobeFun.receive()
                connection2="The anomaly-based IDS on Host detected the victim host (Before Protected Method implemented) is: %s\n"%hostabnormal
                hostconnection=connection2  #hostconnection print on host panel    
                self.log.writeText(connection2,'GREEN')
                print connection2
		if(cmp(hostabnormal,'abnormal')==0):
			self.host.hlabel=wx.StaticText(self.host,-1,label=hostabnormal,pos=(20,80))
			self.host.hlabel.SetForegroundColour('Red')
			#print "ok"
		elif(cmp(hostabnormal,'abnormal')!=0):
			self.host.hlabel=wx.StaticText(self.host,-1,label=hostabnormal,pos=(20,80))
			self.host.hlabel.SetForegroundColour('Green')
                if (cmp(preattack,'UDP')==0):  # if the suspcious flow is UDP attack
		    self.vm.icon=wx.StaticText(self.vm, label=u'Current Flow on VM is Attack %s'%preattack,pos=(520,40))
                    
                    self.vm.icon.SetForegroundColour('Red')
                    udplist=GlobeFun.udprankfun()
                    udpbest=udplist[1]
                    if(cmp(udpbest,'IPS')==0):  # if the best method to solve UDP attack is IPS
                        connection3="The controller decides to run IPS to protect against UDP Flood Attack\n"        
                        connection1=connection1+'\n'+connection3       
                        self.log.writeText(connection3,'BLUE') 
                        print connection1
                        GlobeFun.UDP() #IPS        
                        connection4="IPS is running in the background\n"
                        self.log.writeText(connection4,'BLUE')
                        print connection4
                        connection1=connection1+'\n'+connection4
                        
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                    elif (cmp(udpbest,'Port Disablement')==0):#if 'Port Disablement' is the best method    
                        connection5="The controller decides to drop the UDP packet to protect against UDP Flood Attack as IPS does not work fine\n"
                        connection1=connection1+'\n'+connection5
                        self.log.writeText(connection5,'BLUE')
                        print connection5
                        connection6="The UDP packets pass through port 5009 are considered as UDP Flood which is dropped\n"
                        GlobeFun.UDP2()   #UDP disable certain port
                        self.log.writeText(connection6,'BLUE')
                        connection1=connection1+'\n'+connection6
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp     
                            self.log.writeText(Connectionsp,'RED')
                               
                    elif(cmp(udpbest,'Network Disconnection')==0): #if 'Network Disconnection ' is the best method
                            connection7= "The Controller decides to disconnet Network to protect against the attack to Host\n"
                            print connection7      
                            self.log.writeText(connection7,'BLUE')  
                            connection1=connection1+'\n'+connection7        
                            GlobeFun.disconnection() #call function
                            connection8="Host network is disabeled.\n"
                            self.log.writeText(connection8,'GREEN')
                            
                            hostconnection = hostconnection+connection8
                            print hostconnection        
                            if (cmp(previous,'Network Disconnection')==0 ):
                                Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                                connection1=connection1+'\n'+Connectionsp 
                                self.log.writeText(Connectionsp,'RED')
                                       
                            elif( cmp(previous,'Host Shutdown')==0  ):
                                Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
                            previous="Network Disconnection"
                    
                    elif (cmp(udpbest,'Firewall')==0): #if 'Firewall' is the best option
                            connection9= "The OS default firewall is the best method which has already runned\n"
                            self.log.writeText(connection9,'BLUE')
                            connection1=connection1+'\n'+connection9        
                            if (cmp(previous,'Network Disconnection')==0 ):
                                Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
                                
                    elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp   
                            self.log.writeText(Connectionsp,'RED')     
                    
                    elif(cmp(udpbest,'Legal Flow Filtering')==0):        #if only let legal user access attacks
                            connection10="Only legal users can access resources"
                            self.log.writeText(connection1,'GREEN')
                            connection1=connection1+'\n'+connection10
                            GlobeFun.Legalflow()
                            connection11="Registered user can access confidential data"
                            self.log.writeText(connection11,'BLUE')
                            hostconnection = hostconnection+'\n'+connection10+'\n'+connection11
                            print hostconnection    
                            if (cmp(previous,'Network Disconnection')==0 ):
                                Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
                            
                            elif( cmp(previous,'Host Shutdown')==0  ):
                                Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
            
            
                    elif (cmp(udpbest,'Host Shutdown')==0):        
                            connection12="Shut Down the Host is the best method."
                            self.log.writeText(connection12,'BLUE')
                            connection1=connection1+'\n'+connection12
                            GlobeFun.Shutdown()
                            connection13="The host is shutted"
                            hostconnection = hostconnection+'\n'+connection13
                            self.log.writeText(connection13,'GREEN')
                            if (cmp(previous,'Network Disconnection')==0 ):
                                Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
                            
                            elif( cmp(previous,'Host Shutdown')==0  ):
                                Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
                            previous="Host Shutdown"
            
            #---------------TCP SYN ATTACK protected method----------------
            
                if (cmp(preattack,'TCPSYN')==0):  # If the suspicious flow is TCP_SYN attack
		    self.vm.icon=wx.StaticText(self.vm, label=u'Current Flow on VM is Attack %s'%preattack,pos=(520,40))
                    
                    self.vm.icon.SetForegroundColour('Red')
                    tcplist=GlobeFun.tcprankfun()
                    tcpbest=tcplist[1]
                    if(cmp(tcpbest,'IPS')==0):
                            connection3="The controller decides to run IPS to protect against TCPSYN Flood Attack\n"        
                            connection1=connection1+'\n'+connection3          
                            self.log.writeText(connection3,'BLUE')
                            GlobeFun.UDP() #IPS        
                            connection4="IPS is running in the background\n"        
                            connection1=connection1+'\n'+connection4
                            self.log.writeText(connection4,'BLUE')
                    if (cmp(previous,'Network Disconnection')==0 ): #Network Disconnection.
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                    
                    elif( cmp(previous,'Host Shutdown')==0  ): #shutdown host
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                    elif (cmp(tcpbest,'Port Disablement')==0): # Port Disablement
                            connection5="The controller decides to Port Disablement to protect against TCPSYN Flood Attack \n"
                            connection1=connection1+'\n'+connection5
                            self.log.writeText(connection5,'BLUE')
                            connection6="The TCPSYN packets pass through port 135 are considered as TCPSYN Flood which is dropped\n"
                            self.log.writeText(connection6,'BLUE')
                            GlobeFun.TCP2()
                            connection1=connection1+'\n'+connection6
                            if (cmp(previous,'Network Disconnection')==0 ):
                                Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
                            
                            elif( cmp(previous,'Host Shutdown')==0  ):
                                Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
            
                    elif(cmp(tcpbest,'Network Disconnection')==0): #Network Disconnection
                                connection7= "The Controller decides to disconnet Network to protect against the attack to Host\n"
                                print connection7        
                                self.log.writeText(connection7,'BLUE')
                                connection1=connection1+'\n'+connection7        
                                GlobeFun.disconnection()
                                connection8="Host network is disabeled.\n"
                                self.log.writeText(connection8,'GREEN')
                                hostconnection = hostconnection+connection8
                                print hostconnection        
                        
                                if (cmp(previous,'Network Disconnection')==0 ):
                                    Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                                    connection1=connection1+'\n'+Connectionsp
                                    self.log.writeText(Connectionsp,'RED')
                            
                                elif( cmp(previous,'Host Shutdown')==0  ):
                                    Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                                    connection1=connection1+'\n'+Connectionsp
                                    self.log.writeText(Connectionsp,'RED')
                                previous="Network Disconnection"
                                
                    elif (cmp(tcpbest,'Firewall')==0): #firewall
                        connection9= "The OS default firewall is the best method which has already runned\n"
                        self.log.writeText(connection9,'BLUE')
                        connection1=connection1+'\n'+connection9        
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp   
                            self.log.writeText(Connectionsp,'RED')     
                    
                    elif(cmp(tcpbest,'Legal Flow Filtering')==0):        
                            connection10="Only legal users can access resources"
                            self.log.writeText(connection10,'BLUE')
                            connection1=connection1+'\n'+connection10
                            GlobeFun.Legalflow()#call function
                            connection11="Registered user can access confidential data"
                            hostconnection = hostconnection+connection11
                            self.log.writeText(connection11,'GREEN')
                            print hostconnection    
            
                            if (cmp(previous,'Network Disconnection')==0 ): #Network Disconnection
                                Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
                            
                            elif( cmp(previous,'Host Shutdown')==0  ):
                                Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
            
                    elif (cmp(tcpbest,'Host Shutdown')==0): #shutdown
                    
                            connection12="Shut Down the Host is the best method."
                            connection1=connection1+'\n'+connection12
                            self.log.writeText(connection12,'BLUE')
                            GlobeFun.Shutdown()
                            connection13="The host is shutted"
                            self.log.writeText(connection13,'GREEN')
                            if (cmp(previous,'Network Disconnection')==0 ):
                                Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                                connection1=connection1+'\n'+Connectionsp  
                                self.log.writeText(Connectionsp,'RED')
                                      
                            elif( cmp(previous,'Host Shutdown')==0  ):
                                Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
                            previous="Host Shutdown"
            
            #--------------------POD protected method--------------------------------
            
                if (cmp(preattack,'POD')==0):
		    self.vm.icon=wx.StaticText(self.vm, label=u'Current Flow on VM is Attack %s'%preattack,pos=(520,40))
                    
                    self.vm.icon.SetForegroundColour('Red')
                    podlist=GlobeFun.podrankfun()
                    podbest=podlist[1]
                    if(cmp(podbest,'IPS')==0):
                        connection3="The controller decides to run IPS to protect against POD Flood Attack\n"        
                        connection1=connection1+'\n'+connection3   
                        self.log.writeText(connection3,'BLUE')     
                        print connection1
                        GlobeFun.POD() #POD snort_inline        
                        connection4="IPS is running in the background\n"
                        self.log.writeText(connection4,'BLUE')
                        print connection4
                        connection1=connection1+'\n'+connection4
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                    
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                    elif (cmp(podbest,'Port Disablement')==0):        
                        connection5="The controller decides to Port Disablement,\n but ICMP Protocol packets has no port,\n drop the ICMP packets instead\n"
                        connection1=connection1+'\n'+connection5
                        self.log.writeText(connection5,'BLUE')
                        print connection5
                        GlobeFun.POD2()
                        connection6="ICMP Packets to the host are dropped\n"   
                        self.log.writeText(connection6,'BLUE')     
                        connection1=connection1+'\n'+connection6
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
            
                    elif(cmp(podbest,'Network Disconnection')==0):
                        connection7= "The Controller decides to disconnet Network to protect against the attack to Host\n"
                        print connection7        
                        self.log.writeText(connection7,'BLUE')
                        connection1=connection1+'\n'+connection7
                        GlobeFun.disconnection()
                        connection8="Host network is disabeled.\n"
                        self.log.writeText(connection8,'GREEN')
                        hostconnection = hostconnection+connection8
                        print hostconnection
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                    
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        previous="Network Disconnection"
                    elif (cmp(podbest,'Firewall')==0):
                        connection9= "The OS default firewall is the best method which has already runned\n"
                        self.log.writeText(connection9,'BLUE')
                        connection1=connection1+'\n'+connection9
                    
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                    
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp   
                            self.log.writeText(Connectionsp,'RED')     
                    
                    elif(cmp(podbest,'Legal Flow Filtering')==0):        
                        connection10="Only legal users can access resources"
                        self.log.writeText(connection10,'BLUE')
                        connection1=connection1+'\n'+connection10
                        GlobeFun.Legalflow()
                        connection11="Registered user can access confidential data"
                        hostconnection = hostconnection+connection10
                        print hostconnection        
                
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif(cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                
                    elif (cmp(podbest,'Host Shutdown')==0):        
                        connection12="Shut Down the Host is the best method."
                        self.log.writeText(connection12,'BLUE')
                        connection1=connection1+'\n'+connection12
                        GlobeFun.Shutdown()
                        connection13="The host is shutted"
                        self.log.writeText(connection13,'GREEN')
                        
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        previous="Host Shutdown"
                
            #----------------------Normal--------------
                    if (cmp(preattack,'Normal')==0):    
                        Connectionx="No attack,the controller does not need to work\n"            
                        connection1=connection1+'\n'+Connectionx
                        self.log.writeText(Connectionx,'BLUE')
                        print "Normal connection1,%s " %connection1
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
            
            #---------------------ICMP------------------------------------------------
                if (cmp(preattack,'ICMP')==0): #ICMP Attack
		    self.vm.icon=wx.StaticText(self.vm, label=u'Current Flow on VM is Attack %s'%preattack,pos=(520,40))
                    
                    self.vm.icon.SetForegroundColour('Red')
                    icmplist=GlobeFun.icmprankfun()
                    icmpbest=icmplist[1]
                    if(cmp(icmpbest,'IPS')==0):
                        connection3="The controller decides to run IPS to protect against ICMP Flood Attack\n"        
                        connection1=connection1+'\n'+connection3   
                        self.log.writeText(connection3,'BLUE')     
                        print connection1
                        GlobeFun.POD() #ICMP Protocol attack, same method as POD attack        
                        connection4="IPS is running in the background\n"
                        self.log.writeText(connection4,'BLUE')
                        print connection4
                        connection1=connection1+'\n'+connection4
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp     
                            self.log.writeText(Connectionsp,'RED')
                               
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                            
                    elif (cmp(icmpbest,'Port Disablement')==0):        
                        connection5="The controller decides to implement Port Disablement for ICMP Flood Attack,\n but ICMP Protocol packets has no port,\n drop the ICMP packets instead\n"
                        connection1=connection1+'\n'+connection5
                        self.log.writeText(connection5,'BLUE')
                        print connection5
                        GlobeFun.POD2()
                        connection6="ICMP Packets to the host are dropped\n"    
                        self.log.writeText(connection6,'BLUE')    
                        connection1=connection1+'\n'+connection6
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp     
                            self.log.writeText(Connectionsp,'RED')
                               
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                    
                    elif(cmp(icmpbest,'Network Disconnection')==0):
                        connection7= "The Controller decides to disconnet Network to protect against the attack to Host\n"
                        print connection7    
                        self.log.writeText(connection7,'BLUE')
                        connection1=connection1+'\n'+connection7
                        GlobeFun.disconnection()
                        connection8="Host network is disabeled.\n"
                        hostconnection = hostconnection+connection8
                        self.log.writeText(connection8,'GREEN')
                        print hostconnection
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                
                        previous="Network Disconnection"
                    elif (cmp(icmpbest,'Firewall')==0):
                        connection9= "The OS default firewall is the best method which has already runned\n"
                        self.log.writeText(connection9,'BLUE')
                        connection1=connection1+'\n'+connection9
                        
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp   
                            self.log.writeText(Connectionsp,'RED') 
                    
                    elif(cmp(icmpbest,'Legal Flow Filtering')==0):        
                        connection10="Only legal users can access resources"
                        connection1=connection1+'\n'+connection10
                        self.log.writeText(connection10,'BLUE')
                        GlobeFun.Legalflow()
                        connection11="Registered user can access confidential data"
                        self.log.writeText(connection11,'GREEN')
                        hostconnection = hostconnection+connection10
                        print hostconnection    
                
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                            
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp 
                            self.log.writeText(Connectionsp,'RED')
                            
                    elif (cmp(icmpbest,'Host Shutdown')==0):        
                        connection12="Shut Down the Host is the best method."
                        connection1=connection1+'\n'+connection12
                        self.log.writeText(connection12,'BLUE')
                        GlobeFun.Shutdown()
                        connection13="The host is shutted"
                        self.log.writeText(connection13,'GREEN')
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
            
                        previous="Host Shutdown"
                fvm=open('/home/Write/vmstring.txt','w')    
                fvm.write(connection1)
                fvm.close()
                fhost=open('/home/Write/hoststring.txt','w')
                fhost.write(hostconnection)
                fhost.close()
                
                
            #-------------------------receive state from host-------------------------------
            
                host2=GlobeFun.receive()  #attack or not
                connection14="The anomaly-based IDS on Host detected the victim host (after protected method) is: %s\n"%host2
                print connection14
                self.log.writeText(connection14,'GREEN')
		if(cmp(host2,'abnormal')==0):
			self.host.llabel=wx.StaticText(self.host,-1,label=host2,pos=(520,80))
			self.host.llabel.SetForegroundColour('Red')
		elif(cmp(host2,'abnormal')!=0):
			self.host.llabel=wx.StaticText(self.host,-1,label=host2,pos=(520,80))
			self.host.llabel.SetForegroundColour('Green')
                hostnew=""
                connectnew=""
                hostnew=hostnew+'\n'+connection14
                fvm3=open('/home/Write/vmstring.txt','a')    
                if(((cmp(hostabnormal,'abnormal')==0) and (cmp(host2,'abnormal')==0))or ((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'abnormal')==0))):
                    connection15= "The attack is not in our database or it is misclassified,the wireshark is running to analyze attack packets\n"
                    connectnew=connectnew+'\n'+connection15
                    self.log.writeText(connection15,'BLUE')
                    fvm3.write(connectnew)
                    fvm3.close()        
                    GlobeFun.unknown() #if protected method does not work, dynamic module runs to check for zero day attacks.
                    
            
                    if(((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'Timeout')==0)) or ((cmp(hostabnormal,'abnormal')==0) and (cmp(host2,'Timeout')==0))):
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="Last State the network of the host was disabled, please make sure the network is reconnected or protected methods cannot work "
                            fvm3.write(Connectionsp)
                            fvm3.close()       
                            self.log.writeText(Connectionsp,'RED')     
                            
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="Last State the host was shutted down, please make sure the host is turned on."            
                            fvm3.write(connectnew)
                            fvm3.close()
                            self.log.writeText(Connectionsp,'RED')
                        else:            
                            connection18="Heavy Load of Unknown attack\n"
                            self.log.writeText(connection18,'BLUE')
                            connectnew=connectnew+'\n'+connection18
                            print connectnew
                            fvm3.write(connectnew)
                            fvm3.close()        
                            GlobeFun.unknown()
                        
                        
                    
                print "--------------------------------"
                #time.sleep(10)    
                fhost3=open('/home/Write/hoststring.txt','a')
                fhost3.write(hostnew)
                fhost3.close()    
                wx.Yield()
#                if self.need_abort:
#                    self.status.SetLabel('Computation aborted')
#                    break
#                else:              
#                    self.status.SetLabel('Computation Completed')           
#                    self.working = 0
                

    
