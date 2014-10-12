from rpy2 import *
from rpy2 import robjects

if __name__=='__main__': 
 robjects.r('''library("TTR",lib.loc="/home/R_Packet")''')
 robjects.r('''library("forecast",lib.loc="/home/R_Packet")''')
 robjects.r('''library("tsDyn",lib.loc="/home/R_Packet")''')

from forecast_gui import *

class Forecast():

 def __init__(self,log):          
        self.log=log 

 def ProcessLog(self,attack):
	print "Working"
	self.attack=attack
	self.log=log
        newtime=0
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
                
                print starttime
                f1=open('/var/log/snort_inline/pressure','r')
                
                lines=f1.readlines()#lines is list; type(lines[0]) is str
                
                number=len(lines)
                #print "Number of File is %d\n"%number
                #print number
                data=lines[preLine:number]
                preLine=number
                #print preLine
                #print "UDPNumber is %d"%UDPNumber
               
                #self.predict(self.attack)
                
                
                #print endtime
               
                #newtime=newtime+(endtime-starttime)+10 
            #if(os.path.isfile('/home/log/custom.log')==False):    
                #nofile="No TCP Log Files"
		#print nofile
	        #self.log.writeText(nofile,'RED')
                #break
            #else:
		print "Process TCPLog else works"
                starttime=time.clock()
                #print starttime
                #f1=open('/home/log/custom.log','r')
                data=lines[preLine2:number]
                
                self.predict(self.attack)
                time.sleep(10)
                endtime=time.clock()
                #print endtime
               
            newtime=newtime+(endtime-starttime)+10 
   
 def predict(self,newattack):
        print "predict works\n"
      
        newtime=0
        SetarList=[]
        realdata=[]
        Rdata=[]
        preLine=0
        OriginalData=[]
        ProcessedData=[]
        ArimaList=[]
        number=0
        #while (newtime<5):
        
        
        Rdata=lines[0:number]
            
        UDPPredict=lines[0:number]
        if(number>2):
                print "Last 2 Sec: ",UDPPredict[-4:-1]
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
                            
                            f="Same as Previous Forecast\n n+1  %s"%UDPPredict[len(UDPPredict)-1]
                            

                else:
                            vector=robjects.FloatVector(UDPPredict)
                        
                            newdataSMA15=r['SMA'](vector, n=1)
                            
                            predfit=r['auto.arima'](newdataSMA15)
                    
                            f=r['forecast.Arima'](predfit,level=r['c'](99.5))
                    
                            r['print'](f)
                            
                            f1.write(str(f))
                            
			    
                #=========Predict all paramters and known attacks============== 
        if(cmp(newattack,'All')==0):
             for i in range (0,len(fileList)):
                attack=fileList[i]
                #print attack
                fileName='/home/forecast/'+attack+'Total.txt'
                forecastfileName='/home/forecast/'+attack+'forecast.txt'
                if(os.path.isfile(forecastfileName)==False):    
                    print "No %s Forecast file"%attack
                    
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
	    
