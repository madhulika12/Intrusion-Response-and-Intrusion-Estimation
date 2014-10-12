from figure import *

from processdata import *

from preprocessing import *

from disconnection import *

from shutdownhost import *

from legalflow import *

from globe import *

from Rightokbutton import *

from MRightokbutton import *

from ButtonFunction import *

from mcontroller import *

import wx
import wx.lib.colourdb
from multiprocessing import Process
from threading import *
import socket
import os,re,sys
import time
import binascii
import signal
import pexpect
from ReplicaHost import *
import datetime
from CPU_MeM_Priority_Kill import * #Protection Method for unknown attacks consume CPU and Mem.
from disconnection import *

from shutdownhost import *

from legalflow import *
#================================================================================
#======================= The main TFPG Frame and menu ===========================
#================================================================================   
 #Globe


tcp=0
udp=0
icmp=0
pod=0
normal=0
ID_START = wx.NewId() # use for "stop" button to terminate infinite loop in Protected method Buttons ("Ranking,IPS","Port Disablement"...)
ID_STOP = wx.NewId()
ID_IPS= wx.NewId()
ID_Disable= wx.NewId()
ID_Network= wx.NewId()
ID_Firewall= wx.NewId()
ID_flow= wx.NewId()
ID_shut= wx.NewId()
ID_RUN= wx.NewId()
ip='3.0.0.1' #remote access router which ip is 3.0.0.1 for dynamically analyzing             
ip2='1.0.0.1'#attack packets and redirecting illegal flow from router to protected VM before forwarding packets to host 
user='root'  # router username password
passwd='000000'
#contt=["","",""]
udpranking=["",""]
tcpranking=["",""]
icmpranking=["",""]
podranking=["",""]
os.system("modprobe ip_queue")



#class TimeoutException(Exception): 
#    pass 
class GuiFrame(wx.Frame):
    title = 'Model-bsed Security Structure'
    def __init__(self, parent):
        wx.Frame.__init__(self, parent, -1, self.title, size=(1024,768))
        panel = wx.Panel(self, -1, size =wx.DefaultSize )
        #self.CreateStatusBar()
        #self.makeMenu()
        
        self.filename   = None
        self.debuglevel = 1
        #self.wildcard = 'TFPG files (*.fpg)|*.fpg|All files (*.*)|*.*'
        
        # define the splitting windows
        #Hsplitter = wx.SplitterWindow(self, -1, style=wx.SP_3D)
        #HHsplitter = wx.SplitterWindow(Hsplitter, -1, style=wx.SP_3D)
        #Vsplitter = wx.SplitterWindow(Hsplitter, -1, style=wx.SP_3D)
        
        # main Controller frame
        #Left Weight
        #self.LeftPanel = LPanel(Hsplitter, -1,self)
        #right Values
        #self.RightPanel = RPanel(Hsplitter, -1,self)
        #Button Frame
        NPanel =  NotePage(panel,-1)
        # Set up a log on the View Log Notebook page
        #self.log = wx.TextCtrl(Hsplitter,-1, style = wx.TE_MULTILINE|wx.TE_READONLY|wx.TE_RICH)
        #self.log.SetFont(wx.Font(11, wx.MODERN , wx.NORMAL, wx.NORMAL, False, 'Courier'))
        #wx.Log_SetActiveTarget(wx.LogTextCtrl(self.log))
        #page1=
        hbox = wx.BoxSizer(wx.VERTICAL)
        hbox.Add(NPanel, 3, wx.EXPAND )
        # Controller       
        panel.SetSizer(hbox)
        self.Show(True)
        
        # add the windows to the splitter and split it.
        #Hsplitter.SplitHorizontally(self.NPanel, 500)
        #Vsplitter.SplitVertically(self.CPanel, Hsplitter, 145)

        #Hsplitter.SetMinimumPaneSize(150)   
        #Vsplitter.SetMinimumPaneSize(145)        
           
        #self.writeText('Welcome to The Security Tool','BLUE')
        #self.writeText('Please select attack types first then select protection methods','RED')
        #GlobeFun=Globe(self.log)
        #GlobeFun.Initial()
    
        
class  NotePage(wx.Notebook):       
    def __init__(self, parent, id):
        wx.Notebook.__init__(self, parent, id)
        #self.log     = log
        
        self.CPanel = ControllerPanel(self , -1)
        self.AddPage(self.CPanel, 'Controller') #page 1: Fuzzy Logic Controller     
	self.MPanel = MultiPanel(self,-1)
        self.AddPage(self.MPanel, 'MControl')   #page 2: Multi-Criteria Controller
        self.DPanel = DividePanel(self,-1)
        self.AddPage(self.DPanel, 'Devices')   # VM, Host, Router
        
        self.SetSelection(0)

        #wx.EVT_NOTEBOOK_PAGE_CHANGED(self, self.GetId(), self.onPageChanged)    
class ControllerPanel(wx.Panel):
    def __init__(self, parent, id):
        self.debuglevel = 1
        wx.Panel.__init__(self, parent, id,size=wx.DefaultSize)
        #text = wx.StaticText(self, -1,'Controller')
        #sizer = wx.BoxSizer(wx.HORIZONTAL) 
        #Hsplitter = wx.SplitterWindow(self, -1, style=wx.SP_3D)
        text = wx.StaticBox(self,-1, 'Controller Page ')       
        sizer= wx.StaticBoxSizer(text,wx.VERTICAL) 
        self.log=wx.TextCtrl(self,-1,style = wx.TE_MULTILINE|wx.TE_READONLY|wx.TE_RICH)
        self.log.SetFont(wx.Font(11, wx.MODERN , wx.NORMAL, wx.NORMAL, False, 'Courier'))
        wx.Log_SetActiveTarget(wx.LogTextCtrl(self.log))
        self.writeText('Welcome to The Security Tool','BLUE')
        self.writeText('Please select attack types first then select protection methods','RED')
       
        GlobeFun=Globe(self.log)
        GlobeFun.Initial()
    
        control=ControlPan(self, -1,self.log,self)
        sizer.Add(control, 2, wx.EXPAND| wx.ALL, 20 )  
        sizer.Add(self.log,1, wx.EXPAND| wx.ALL, 20)            
        self.SetSizer(sizer)

    def writeText(self, text, color='BLACK', DL=0):
        if DL > self.debuglevel:
            return
        if text[-1:] != '\n':
            text += '\n'
        self.log.SetDefaultStyle(wx.TextAttr(wx.NamedColour(color)))
        self.log.AppendText(text)
        
    def Clear(self):
        self.log.Clear()
    
class ControlPan(wx.Panel):
    def __init__(self, parent,id,log,controller):
        self.log=log
        self.controller=controller
        wx.Panel.__init__(self, parent, id,size=wx.DefaultSize)
        
        text = wx.StaticBox(self,-1, 'Controller')       
        sizer= wx.StaticBoxSizer(text,wx.HORIZONTAL)
        left = LPanel(self, -1,self.log)
        right = RPanel(self,-1,left,self.log,self.controller)
             
        
        sizer.Add(left, 1, wx.EXPAND| wx.ALL, 2) 
        sizer.Add(right, 1, wx.EXPAND| wx.ALL, 2)             
        self.SetSizer(sizer) 

#-----------Page 2 Multi-Criteria---------------
class MultiPanel(wx.Panel):
    def __init__(self, parent, id):
        
        wx.Panel.__init__(self, parent, id,size=(50, 80))
	self.debuglevel = 1
        	 
        #text = wx.StaticBox(self,-1,'Multi-Creteria Controller Page and Log')       
        sizer= wx.BoxSizer(wx.VERTICAL) 
        self.log=wx.TextCtrl(self,-1,style = wx.TE_MULTILINE|wx.TE_READONLY|wx.TE_RICH)
        self.log.SetFont(wx.Font(11, wx.MODERN , wx.NORMAL, wx.NORMAL, False, 'Courier'))
        wx.Log_SetActiveTarget(wx.LogTextCtrl(self.log))
        self.writeText('Welcome to The Security Tool','BLUE')
        self.writeText('Please choose the paremeter to be estimated, and then set the threshold. After that pick the forecaster (left panel). Select attack types first then select Alternative Unit ','RED')
       
        GlobeFun=MGlobe(self.log)
        GlobeFun.Initial()
    
        mcontrol=MControlPan(self, -1,self.log,self)
        sizer.Add(mcontrol, 3, wx.EXPAND| wx.ALL, 20 )  
        sizer.Add(self.log,1, wx.EXPAND| wx.ALL, 20)            
        self.SetSizer(sizer)

    def writeText(self, text, color='BLACK', DL=0):
        if DL > self.debuglevel:
            return
        if text[-1:] != '\n':
            text += '\n'
        self.log.SetDefaultStyle(wx.TextAttr(wx.NamedColour(color)))
        self.log.AppendText(text)
        
    def Clear(self):
        self.log.Clear()
    
class MControlPan(wx.Panel):
    def __init__(self, parent,id,log,mcontroller):
        self.log=log
        self.mcontroller=mcontroller
        wx.Panel.__init__(self, parent, id,size=wx.DefaultSize)
        
        text = wx.StaticBox(self,-1, 'Multi-Creteria Controller Page') 
        #text = wx.StaticBox(parent, -1)
        sizer= wx.StaticBoxSizer(text,wx.HORIZONTAL)      
        #self.Mleft = MLPanel(self, -1,self.log)
        #self.Mright = MRPanel(self,-1,self.Mleft,self.log,self.mcontroller)             
        self.Mright = MRPanel(self,-1,self.log,self.mcontroller) 
        #sizer.Add(self.Mleft, 3, wx.EXPAND| wx.ALL, 2) 
        sizer.Add(self.Mright, 4, wx.EXPAND| wx.ALL, 2)             
        self.SetSizer(sizer)
    

#----------Page 3---------        
class DividePanel(wx.Panel):
    def __init__(self, parent, id):
        #self.log = log
        wx.Panel.__init__(self, parent, id,  size=(50, 80))
        self.debuglevel = 1
        text = wx.StaticText(self, -1,' Devices and Protected Methods')
        sizer = wx.BoxSizer(wx.VERTICAL) 
        self.log=wx.TextCtrl(self,-1,size=wx.DefaultSize,style = wx.TE_MULTILINE|wx.TE_READONLY|wx.TE_RICH)
        self.log.SetFont(wx.Font(11, wx.MODERN , wx.NORMAL, wx.NORMAL, False, 'Courier'))
        wx.Log_SetActiveTarget(wx.LogTextCtrl(self.log))
       
        self.writeText('Device Logs','BLUE')    
       
        device=DevicePanel(self,-1,self)
        sizer.Add(device, 2, wx.EXPAND | wx.ALL, 20)
        sizer.Add(self.log, 1, wx.EXPAND| wx.ALL, 20)            
        self.SetSizer(sizer)
    def writeText(self, text, color='BLACK', DL=0):
        if DL > self.debuglevel:
            return
        if text[-1:] != '\n':
            text += '\n'
        self.log.SetDefaultStyle(wx.TextAttr(wx.NamedColour(color)))
        self.log.AppendText(text)
        
    def Clear(self):
        self.log.Clear()
#-----------Device Panel-----------------------
class DevicePanel(wx.Panel):
    def __init__(self, parent,id,Device):
        self.log=Device
        
        wx.Panel.__init__(self, parent, id, size=wx.DefaultSize)
        text = wx.StaticBox(self,-1, 'Device')       
        sizer= wx.StaticBoxSizer(text,wx.HORIZONTAL)        
        self.vm=VmPanel(self, -1,self.log)
        
        self.vertical=ButtonPanel(self,-1,self.log,self.vm)
        #sizer.Add(self.router, 1, wx.EXPAND| wx.ALL, 20) 
        sizer.Add(self.vertical, 2, wx.EXPAND| wx.ALL,20) 
        sizer.Add(self.vm, 1, wx.EXPAND| wx.ALL,0) 
        #sizer.Add(self.outputtext, 1, wx.EXPAND)        
        self.SetSizer(sizer)



#class VerticalDevice(wx.Panel):
 #   def __init__(self, parent,id,Device):
  #      self.log=Device
         
        
        #wx.Panel.__init__(self, parent, id, size=wx.DefaultSize)
        #text = wx.StaticBox(self,-1, 'Device')       
        #sizer= wx.StaticBoxSizer(text,wx.VERTICAL)    
        #self.button = ButtonPanel(self, -1,self.log)
        #self.router=RouterPanel(self, -1,self.log)
        #self.vm=VmPanel(self, -1,self.log)
        #self.host=HostPanel(self, -1,self.log)
       # sizer.Add(self.button, 1, wx.EXPAND | wx.ALL, 20)
       # sizer.Add(self.router, 1, wx.EXPAND| wx.ALL, 20) 
        #sizer.Add(self.vm, 2, wx.EXPAND| wx.ALL, 20) 
       # sizer.Add(self.host, 1, wx.EXPAND| wx.ALL, 20) 
        #sizer.Add(self.outputtext, 1, wx.EXPAND)        
     #   self.SetSizer(sizer)
        
#------------Button Panel on page 2--------------      
class ButtonPanel(wx.Panel):
    def __init__(self, parent, id,Device,VM):
        wx.Panel.__init__(self, parent, id, size=(40,80))
        self.log = Device
        self.vm=VM
        #self.vPanel = VmPanel(self, -1,self.log)
        #self.vPanel.Show(False)
        #DevicePanel(self, -1,self.log)
        spacing=2
        #--------------------------------------
        #wx.StaticBitmap(self, bitmap=wx.Bitmap('disconnect.png'),pos=(250,120))
        text = wx.StaticBox(self, -1,'Protection Methods')
        sizer = wx.BoxSizer(wx.VERTICAL) 
        sizer.Add(text, 1, wx.EXPAND)         
        self.SetSizer(sizer) 
        self.working = 0
        sampleList = ['Automatic Protection','F-Ranking','M-Ranking', 'IPS', 'Port Disablement', 'Network Disconnection', 'Firewall', 'Legal Flow Filter','Host Shutdown','Replica','Process Priority']
        wx.StaticText(self, -1, "Protection Methods", (8, 50))
        self.protection=wx.ComboBox(self, -1,"Choose One Protection Methods", (150, 45), wx.DefaultSize,sampleList) 
        self.Bind(wx.EVT_COMBOBOX, self.protectfun, self.protection)  
        self.run=wx.Button(self, ID_RUN, 'Run', pos=(360,45)) #--------quick choose IPS method to protect against attack--------
        self.run.Bind (wx.EVT_BUTTON, self.runfun, id=ID_RUN)
        #-------import button functions--------
        
        self.Stop=wx.Button(self, ID_STOP, 'Stop', pos=(480,45))   
        self.Stop.Bind (wx.EVT_BUTTON, self.OnStop, id=ID_STOP)
        self.Stop.Disable()  
        self.router=RouterPanel(self, -1,self.log)
        #self.vm=VmPanel(self, -1,self.log)
        self.host=HostPanel(self, -1,self.log)
        sizer.Add(self.router, 1, wx.EXPAND) 
        #sizer.Add(self.vm, 1, wx.EXPAND) 
        sizer.Add(self.host, 1, wx.EXPAND)         
        self.SetSizer(sizer)
        self.BFunction=ButtonFunction(self.log)
        self.Show(True)
    
    def protectfun(self,event):
        item1 = event.GetString()        
        print "Protection Method is %s"%item1   # cost weight
        fcost=open('/home/Write/protectmethod.txt','w') #save to file for later calculate total score for the method
        fcost.write(item1)    
        fcost.close()	


    def runfun(self,event):
        self.Stop.Enable()
        self.run.Disable()
        
        if((os.path.isfile( '/home/Write/protectmethod.txt')==False)):
            self.log.writeText('Please choose a protection method','RED')
            print "false"
            return
        else:
            if not  self.working:
            #self.status.SetLabel('Starting Computation')
                self.working = 1
                self.need_abort = 0
            GlobeFun=Globe(self.log)
	    MGlobeFun=MGlobe(self.log)
            previous=""
            self.vm.outputtext.Clear()
            for i in range(0,15): #The gui running 10 times
    		self.vm.icon.SetLabel('')
    		#self.router.hlabel.SetLabel('')               
    		self.host.hlabel.SetLabel('')
    		self.host.llabel.SetLabel('')
                frun=open('/home/Write/protectmethod.txt','r')
                method=frun.readline()
                print method
                self.log.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLUE')
                if(cmp(method,'Automatic Protection')==0):
                    
        	    previous=GlobeFun.Defaultfun(self.vm,self.host,self.router,previous)
                if(cmp(method,'F-Ranking')==0):
                    previous=GlobeFun.OnStart(self.vm,self.host,self.router,previous)
		if(cmp(method,'M-Ranking')==0):
                    previous=MGlobeFun.MRank(self.vm,self.host,self.router,previous)
                if(cmp(method,'IPS')==0):
                    function=self.UDP()	            
		    connection10="The controller selects IPS to protect against attack\n"
		    connection11="IPS is running in the background\n"
		    previous=GlobeFun.Combinefun(self.vm,self.host,self.router,previous,connection10,function,connection11)
                if(cmp(method,'Port Disablement')==0):
		    previous=GlobeFun.Disablefun(self.vm,self.host,self.router,previous)
                if(cmp(method,'Network Disconnection')==0):
  		    function=self.disconnection()
     		    connection10="The controller selects Network Disconnection to protect against attack\n"
		    connection11="Host network is disabeled\n"
                    previous=GlobeFun.Combinefun(self.vm,self.host,self.router,previous)
                if(cmp(method,'Firewall')==0):
		    function=self.Firewall()
		    connection10="The Controller selects Firewall to protect against attack\n"
		    connection11="The OS default firewall is the best method which has already run\n"
                    previous=GlobeFun.Combinefun(self.vm,self.host,self.router,previous,connection10,function,connection11)
                if(cmp(method,'Legal Flow Filter')==0):
		    function=self.Legalflow()
		    connection10="Only legal users can access host's resources\n"
		    connection11="Registered user can access confidential data\n"
                    previous=GlobeFun.Combinefun(self.vm,self.host,self.router,previous,connection10,function,connection11)
                if(cmp(method,'Host Shutdown')==0): 
		    function=self.Shutdown()
		    connection10="The controller selects Shut Down the Host to protect against attack\n"
		    connection11="The host is shutted\n"
                    previous=GlobeFun.Combinefun(self.vm,self.host,self.router,previous,connection10,function,connection11)
                if(cmp(method,'Replica')==0): 
                    #previous=GlobeFun.Replicafun(self.vm,self.host,self.router,previous)
                    connection10="The host is attacked, Legistimate Requests are sent to the Replica Server."
		    connection11="Legitimate Packets are sent to 1.0.0.3"
		    function=self.Replica()
                    previous=GlobeFun.Replica_Priorityfun(self.vm,self.host,self.router,previous,connection10,function,connection11)
		if(cmp(method,'Process Priority')==0): 
		    print "Process Priority is running\n"
		    connection10="The host is attacked. Based on the threshold the priority of the CPU or Memory are adjusted; or the Process is terminated."
		    connection11="The Priority is Adjusted/Terminated."
		    function=self.Priority()
                    previous=GlobeFun.Replica_Priorityfun(self.vm,self.host,self.router,previous,connection10,function,connection11)
                fdata=open("/home/file/test.csv",'r')
                data=fdata.readlines()
                self.vm.Clear()
                name=data[0]
                fdata.close()
                
                utilization=name.split(',')
                #print utilization
                memory=utilization[0]
                ByteR=utilization[1]
                ByteS=utilization[2]
                PacketR=utilization[3]
                PacketS=utilization[4]
                IOR=utilization[5]
                IOW=utilization[6]
                Idle=utilization[7]
                System=utilization[8]
                User=utilization[9][:-2]
                #len(User)
                
                self.vm.writeText("-------------%s-----------\n\n"%str(datetime.datetime.now()),'BLUE')
                for i in range (1,len(data)):
                     data_input=data[i]
		     dataprint=data_input.split(',')
                     time='('+str(i)+')'
                     print1=memory+time+"= %s\n"%dataprint[0]
                     print2=ByteR+time+"= %s\n"%dataprint[1]
                     print3= ByteS+time+"= %s\n"%dataprint[2]
                     print4= PacketR+time+"= %s\n"%dataprint[3]
                     print5= PacketS+time+"= %s\n"%dataprint[4]
                     print6= IOR+time+"= %s\n"%dataprint[5]
                     print7= IOW+time+"= %s\n"%dataprint[6]
                     print8= Idle+time+"= %s\n"%dataprint[7]
                     print9= System+time+"= %s\n"%dataprint[8]
                     print10= User+time+"= %s\n"%dataprint[9]
                     printall=print1+print2+print3+print4+print5+print6+print7+print8+print9+print10
                     self.vm.writeText(printall,'BLUE')
                
                wx.Yield()
                if self.need_abort:
                   
                    break
           
            self.working = 0  
    #-----------------IPS------------------------------------------------
    def UDP(self):# run IPS for UDP attack        
                
            os.system("iptables -I FORWARD -d 1.0.0.9 -p udp --dport 5009 -j QUEUE") #packets put into ip_queue for snort_inline to analyze        
            os.system("killall -9 snort_inline") #multiple processes for snort_inline are not allowed, kill all processes if they are running in background
            os.system("snort_inline -c /etc/snort_inline/snort_inline.conf -Q -N -l /var/log/snort_inline/ \-t /var/log/snort_inline/ -v -D") # run IPS  

   #------------------------Disconnection Network----------------------
    def disconnection(self):
        print "The host is disconnect to network \n"
        """os.system("python disconnection.py") # run disconnection script"""
        Disconnect()
       
    #----------------send disconnection signal to host----------
    
    def Legalflow(self):
        print "The host only allow registered user to access resources \n"
        """os.system("python legalflowsignal.py")"""
        Legal=LegalFlow()
   #----------------send disconnection signal to host----------
    
    def Firewall(self):
        print "Firewall is running \n"
        """os.system("python legalflowsignal.py")"""
        
   #----------------send shutdown signal to host----------

    def Shutdown(self):
    
        print "The host is shutted down \n"
        """os.system("python shutdownsend.py") # run shutdown script"""
        Shut=ShutDown()
   #------------------------Replica Function----------------------------   
    def Replica(self):
	print "The host is under attacked. The Replica is implemented   \n"
        """os.system("python Replica.py")"""
        ChangeHost()
    #----------------send Kill/Adjust Process Priority signal to host----------
    def Priority(self):
	print "The host is under attacked, the Process/Thread which consumes the most CPU and Mem will be terminated or the priority of certain Process/Thread will be adjusted   \n"
        """os.system("python Priority.py")"""
        KillPriority()
    
    def OnStop(self,event): # terminate infinite loop, if need
        """Stop Computation."""
        self.Stop.Disable()
        if self.working:
            #self.status.SetLabel('Trying to abort computation')
            self.need_abort = 1 
        self.run.Enable()  
#-------------------------------Fuzzy Logic Panel------------------------    TOP Right Panel 
class LPanel(wx.Panel):   
    def __init__(self, parent,id,log):    
        wx.Panel.__init__(self, parent, id,size=wx.DefaultSize)
        self.log=log
        text = wx.StaticBox(self, -1, 'Weights of Security Assessment Metrics')
        sizer= wx.StaticBoxSizer(text,wx.HORIZONTAL)
        sizer.Add(text, 1, wx.EXPAND)         
        self.SetSizer(sizer)
        #self.text = wx.StaticText(self, -1, 'Values')
        sampleList = ['0', '0.2', '0.5', '0.8', '1', '1.2','1.5','1.8','2']
        wx.StaticText(self, -1, "Recovery Rate:", (60, 50))
        self.choice1=wx.ComboBox(self, -1,"2", (210, 50), wx.DefaultSize,sampleList)        
        wx.StaticText(self, -1, "Availability:", (60, 120))
        self.choice2=wx.ComboBox(self, -1,"2", (210, 120),wx.DefaultSize,sampleList)
        wx.StaticText(self, -1, "Latency:",(60, 190))
        self.choice3=wx.ComboBox(self, -1, '1',(210, 190), wx.DefaultSize,sampleList)
        wx.StaticText(self, -1, "Cost:", (60, 260))
        self.choice4=wx.ComboBox(self, -1,'1', (210, 260), wx.DefaultSize,sampleList)    
        wx.StaticText(self, -1, "Resource  Utilization:",(60, 330))

        self.choice5=wx.ComboBox(self, -1, '0.5',(210, 330), wx.DefaultSize,sampleList)
        self.Bind(wx.EVT_COMBOBOX, self.selChoice1, self.choice1)    
        self.Bind(wx.EVT_COMBOBOX, self.selChoice2, self.choice2)
        self.Bind(wx.EVT_COMBOBOX, self.selChoice3, self.choice3)
        self.Bind(wx.EVT_COMBOBOX, self.selChoice4, self.choice4)
        self.Bind(wx.EVT_COMBOBOX, self.selChoice5, self.choice5)
 
    def selChoice1(self, event):    
        item1 = event.GetString()        
        print "Recovery Rate =%s"%item1   # cost weight
        fcost=open('/home/Write/recovery.txt','w') #save to file for later calculate total score for the method
        fcost.write(item1)    
        fcost.close()

    def selChoice2(self, event):
        item1 = event.GetString()    
        print "Availability =", item1   
        fcost=open('/home/Write/efficiency.txt','w')
        fcost.write(item1)
        fcost.close()
    
    def selChoice3(self, event):
        item1 = event.GetString()
        print "Latency=", item1   
    #return item1
        fcost=open('/home/Write/performance.txt','w')
        fcost.write(item1)
        fcost.close()
    
    def selChoice4(self, event):
        item1 = event.GetString()
        print "cost =", item1  
    #return item1
        fcost=open('/home/Write/cost.txt','w')
        fcost.write(item1)
        fcost.close()
    
    def selChoice5(self, event):
        item1 = event.GetString()
        print "Resource Utilization =", item1  
        #return item1
        fcost=open('/home/Write/effect.txt','w')
        fcost.write(item1)
        fcost.close()
      
#--------------------------------Top Right Panal set value for controller parameters---------------------
class RPanel(wx.Panel):
    
    def __init__(self, parent, id,left,log,controller):
        self.controller=controller
        self.log=log
        self.left=left
        wx.Panel.__init__(self, parent, id)
        text = wx.StaticBox(self, -1, 'Values of Security Assessment Metrics')
        sizer= wx.StaticBoxSizer(text,wx.HORIZONTAL)
        sizer.Add(text, 1, wx.EXPAND)         
        self.SetSizer(sizer)
        #self.bOX = wx.StaticText(self,-1, 'Weight')              
        self.text = wx.StaticText(self, -1, 'Attack Type:',(60,50))
        sampleList = ['UDP', 'TCP_SYN', 'ICMP', 'POD']
        methodList = ["IPS", "Port Disablement", "Legal Flow Filtering", "Network Disconnection","Firewall","Host Shutdown"]
        self.typeofattack=wx.ComboBox(self, -1, '', (210, 50), wx.DefaultSize,sampleList)    
        self.Bind(wx.EVT_COMBOBOX, self.value, self.typeofattack)
        self.text2 = wx.StaticText(self, -1, 'Methods:',(60,90))    
        self.typeofmethod=wx.ComboBox(self, -1, '',(210, 90), wx.DefaultSize,methodList)    
        self.Bind(wx.EVT_COMBOBOX, self.methodtype,self.typeofmethod)
        sList = ['0', '0.2', '0.5', '0.8', '1']
        wx.StaticText(self, -1, "Recovery Rate:", (60, 130))
        self.choice1=wx.ComboBox(self, -1, '',(210, 130), wx.DefaultSize,sList)    
        #print event.GetString()
        wx.StaticText(self, -1, "Availability:", (60, 170))
        self.choice2=wx.ComboBox(self, -1,'', (210, 170), wx.DefaultSize, sList)
        wx.StaticText(self, -1, "Latency:", (60, 210))
        self.choice3=wx.ComboBox(self, -1,'', (210, 210),  wx.DefaultSize,sList)
        wx.StaticText(self, -1, "Cost:", (60, 250))
        self.choice4=wx.ComboBox(self, -1, '',(210, 250),  wx.DefaultSize,sList)
        
        wx.StaticText(self, -1, "Resource Utilization:", (60,290))
        self.choice6=wx.ComboBox(self, -1,'', (210, 290),  wx.DefaultSize,sList)
#        wx.StaticText(self, -1, "False Alarm \n Reduction:", (200, 120))
#        self.choice7=wx.Choice(self, -1, (270, 120), choices=sList)
#        wx.StaticText(self, -1, "Impact on \n legal flow:", (200, 160))
#        self.choice8=wx.Choice(self, -1, (270, 160), choices=sList)
#        # effectiveness no.8
#        wx.StaticText(self, -1, "Effective-\n ness:", (200, 200))
#        self.choice5=wx.Choice(self, -1, (270, 200), choices=sList)
        self.Bind(wx.EVT_COMBOBOX, self.selChoice1, self.choice1)    
        self.Bind(wx.EVT_COMBOBOX, self.selChoice2, self.choice2)
        self.Bind(wx.EVT_COMBOBOX, self.selChoice3, self.choice3)
        self.Bind(wx.EVT_COMBOBOX, self.selChoice4, self.choice4)
        self.Bind(wx.EVT_COMBOBOX, self.selChoice6, self.choice6)
#        self.Bind(wx.EVT_CHOICE, self.selChoice6, self.choice6)
#        self.Bind(wx.EVT_CHOICE, self.selChoice7, self.choice7)
#        self.Bind(wx.EVT_CHOICE, self.selChoice8, self.choice8)
        
        #----------ok button-----------------
        self.ok = wx.Button(self, id=-1, label='Submit',pos=(60, 330))
        self.ok.Bind(wx.EVT_BUTTON, self.OkButton)
        self.restore= wx.Button(self, id=-1, label='Restore Default Value',pos=(210, 330))
        self.restore.Bind(wx.EVT_BUTTON, self.restorebutton)
        #------------Rank button ------------
        #self.realrank = wx.Button(self, id=-1, label='Ranking', pos=(270, 330), size=(80, 35))
        #self.realrank.Bind(wx.EVT_BUTTON, self.rankButton)
        self.RightOk=RightOkButton(self.controller)
        self.GlobeFun=Globe(self.controller)
        
        #self.left=LPanel(self,-1,self.log)
        
    def restorebutton(self,event):
        #GlobeFun=Globe(self.log)
        self.GlobeFun.Initial()
        self.left.choice1.SetValue('0')
        message1="""UDP Default Protected Methods Ranking:\n
        No. 1  : IPS (0.5)\n
        No. 2  : Port Disablement (1.8)\n
        No. 3  : Firewall (2.1)\n
        No. 4 : Host Shutdown (3.1)\n
        No. 5  : Legal Flow Filtering (3.3)\n
        No. 6  : Networking Disconnection (3.3)\n\n"""
        
        message2="""TCP SYN Default Protected Methods Ranking:\n
        No. 1  : Port Disablement (1.5)\n        
        No. 2  : Firewall (3.1)\n
        No. 3 : Host Shutdown (3.1)\n
        No. 4  : IPS (3.3)\n
        No. 5  : Legal Flow Filtering (3.3)\n
        No. 6  : Networking Disconnection (3.3)\n \n     """
        
        
        message3="""ICMP Default Protected Methods Ranking:\n
        No. 1  : IPS (0.5)\n
        No. 2  : Port Disablement (1.8)\n
        No. 3  : Firewall (2.1)\n
        No. 4 : Host Shutdown (3.1)\n
        No. 5  : Legal Flow Filtering (3.3)\n
        No. 6  : Networking Disconnection (3.3)\n\n"""
        
        message4="""POD Default Protected Methods Ranking:\n
        No. 1  : IPS (0.5)\n
        No. 2  : Port Disablement (1.8)\n
        No. 3  : Firewall (2.1)\n
        No. 4 : Host Shutdown (3.1)\n
        No. 5  : Legal Flow Filtering (3.3)\n
        No. 6  : Networking Disconnection (3.3)\n\n"""
        if((os.path.isfile( '/home/Write/attacktype.txt')==False) or (os.path.isfile( '/home/Write/methodtype.txt')==False)):#
             self.controller.writeText('Please select attack types and protection methods','RED')
         
             
        fcost=open('/home/Write/attacktype.txt','r')
        attack=fcost.readline()
        fmethod=open('/home/Write/methodtype.txt','r')
        types=fmethod.readline()
        fmethod.close()
        
        if(cmp(attack,'UDP')==0 or cmp(attack,'POD')==0 or cmp(attack,'ICMP')==0 ):
            if(cmp(types,'IPS')==0 ):             
                
                self.choice1.SetValue('0')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0.2')
                self.choice4.SetValue('0.2')
                self.choice6.SetValue('0.2')
               
     
            elif(cmp(types,'Port Disablement')==0):
                
                self.choice1.SetValue('0')
                self.choice2.SetValue('0.5')
                self.choice3.SetValue('0.8')
                self.choice4.SetValue('0')
                self.choice6.SetValue('0')
                
            elif(cmp(types,'Legal Flow Filtering')==0):
               
                self.choice1.SetValue('1')
                self.choice2.SetValue('0.5')
                self.choice3.SetValue('0')
                self.choice4.SetValue('0.2')
                self.choice6.SetValue('0.2')
            elif(cmp(types,'Network Disconnection')==0):
                
                self.choice1.SetValue('0')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0.2')
                self.choice6.SetValue('0.2')
                
            elif(cmp(types,'Firewall')==0):
                self.choice6=wx.ComboBox(self, -1,'0', (90, 290),  wx.DefaultSize,sList)
                self.choice1.SetValue('0.8')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0.5')
                self.choice4.SetValue('0')
                self.choice6.SetValue('0')
                
            elif(cmp(types,'Host Shutdown')==0):
               
                self.choice1.SetValue('0')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0')
                self.choice6.SetValue('0.2')
            if(cmp(attack,'UDP')==0 ):
                #self.log.Clear()
                self.controller.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLUE')
                self.controller.writeText(message1,'BLUE')
                
            if(cmp(attack,'POD')==0):
                #self.log.Clear()
                self.controller.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLUE')
                self.controller.writeText(message4,'BLUE')
                
            if(cmp(attack,'ICMP')==0):
                #self.log.Clear()
                self.controller.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLUE')
                self.controller.writeText(message3,'BLUE')
                
        elif(cmp(attack,'TCP_SYN')==0):
            #self.log.Clear()
            self.controller.writeText(message2,'Blue')
            if(cmp(types,'IPS')==0 ):             
                
                self.choice1.SetValue('1')
                self.choice2.SetValue('0')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0.2')
                self.choice6.SetValue('0.2')
               
                
            elif(cmp(types,'Port Disablement')==0):
                self.choice1.SetValue('0')
                self.choice2.SetValue('0.5')
                self.choice3.SetValue('0.5')
                self.choice4.SetValue('0')
                self.choice6.SetValue('0')
            elif(cmp(types,'Legal Flow Filtering')==0):
                self.choice1.SetValue('1')
                self.choice2.SetValue('0.5')
                self.choice3.SetValue('0')
                self.choice4.SetValue('0.2')
                self.choice6.SetValue('0.2')
            elif(cmp(types,'Network Disconnection')==0):
                self.choice1.SetValue('0')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0.2')
                self.choice6.SetValue('0.2')  
            
                
            elif(cmp(types,'Firewall')==0):
                self.choice1.SetValue('0.8')
                self.choice2.SetValue('0.5')
                self.choice3.SetValue('0.5')
                self.choice4.SetValue('0')
                self.choice6.SetValue('0')
                
            elif(cmp(types,'Host Shutdown')==0):
                self.choice1.SetValue('0')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0')
                self.choice6.SetValue('0.2')
        
        #fcost.write(types) #save for later check which process need to be calculated its score
        fcost.close()
    def methodtype(self, event): #get the protect method
        message1="""UDP Default Protected Methods Ranking:\n
        No. 1  : IPS (0.5)\n
        No. 2  : Port Disablement (1.8)\n
        No. 3  : Firewall (2.1)\n
        No. 4 : Host Shutdown (3.1)\n
        No. 5  : Legal Flow Filtering (3.3)\n
        No. 6  : Networking Disconnection (3.3)\n\n"""
        
        message2="""TCP SYN Default Protected Methods Ranking:\n
        No. 1  : Port Disablement (1.5)\n        
        No. 2  : Firewall (3.1)\n
        No. 3 : Host Shutdown (3.1)\n
        No. 4  : IPS (3.3)\n
        No. 5  : Legal Flow Filtering (3.3)\n
        No. 6  : Networking Disconnection (3.3)\n \n     """
        
        
        message3="""ICMP Default Protected Methods Ranking:\n
        No. 1  : IPS (0.5)\n
        No. 2  : Port Disablement (1.8)\n
        No. 3  : Firewall (2.1)\n
        No. 4 : Host Shutdown (3.1)\n
        No. 5  : Legal Flow Filtering (3.3)\n
        No. 6  : Networking Disconnection (3.3)\n\n"""
        
        message4="""POD Default Protected Methods Ranking:\n
        No. 1  : IPS (0.5)\n
        No. 2  : Port Disablement (1.8)\n
        No. 3  : Firewall (2.1)\n
        No. 4 : Host Shutdown (3.1)\n
        No. 5  : Legal Flow Filtering (3.3)\n
        No. 6  : Networking Disconnection (3.3)\n\n"""
        types = event.GetString()
        print "Mprotectiontype= ", str(types)  #protected process as IPS, Port Disablement and ...
        fcost=open('/home/Write/attacktype.txt','r')
        attack=fcost.readline()        
        fmethod=open('/home/Write/methodtype.txt','w')
        fmethod.write(types) #save for later check which process need to be calculated its score
        fcost.close()
        fmethod.close()
        if(cmp(attack,'UDP')==0 or cmp(attack,'POD')==0 or cmp(attack,'ICMP')==0 ):
            if(cmp(types,'IPS')==0 ):             
                
                self.choice1.SetValue('0')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0.2')
                self.choice4.SetValue('0.2')
                self.choice6.SetValue('0.2')
               
     
            elif(cmp(types,'Port Disablement')==0):
                
                self.choice1.SetValue('0')
                self.choice2.SetValue('0.5')
                self.choice3.SetValue('0.8')
                self.choice4.SetValue('0')
                self.choice6.SetValue('0')
                
            elif(cmp(types,'Legal Flow Filtering')==0):
               
                self.choice1.SetValue('1')
                self.choice2.SetValue('0.5')
                self.choice3.SetValue('0')
                self.choice4.SetValue('0.2')
                self.choice6.SetValue('0.2')
            elif(cmp(types,'Network Disconnection')==0):
                
                self.choice1.SetValue('0')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0.2')
                self.choice6.SetValue('0.2')
                
            elif(cmp(types,'Firewall')==0):
                self.choice6=wx.ComboBox(self, -1,'0', (90, 290),  wx.DefaultSize,sList)
                self.choice1.SetValue('0.8')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0.5')
                self.choice4.SetValue('0')
                self.choice6.SetValue('0')
                
            elif(cmp(types,'Host Shutdown')==0):
               
                self.choice1.SetValue('0')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0')
                self.choice6.SetValue('0.2')
            if(cmp(attack,'UDP')==0 ):
                #self.log.Clear()
                self.controller.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLUE')
                self.controller.writeText(message1,'BLUE')
                
            if(cmp(attack,'POD')==0):
                #self.log.Clear()
                self.controller.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLUE')
                self.controller.writeText(message4,'BLUE')
                
            if(cmp(attack,'ICMP')==0):
                #self.log.Clear()
                self.controller.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLUE')
                self.controller.writeText(message3,'BLUE')
               
        elif(cmp(attack,'TCP_SYN')==0):
            #self.log.Clear()
            self.controller.writeText(message2,'Blue')
            if(cmp(types,'IPS')==0 ):             
                
                self.choice1.SetValue('1')
                self.choice2.SetValue('0')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0.2')
                self.choice6.SetValue('0.2')
               
                
            elif(cmp(types,'Port Disablement')==0):
                self.choice1.SetValue('0')
                self.choice2.SetValue('0.5')
                self.choice3.SetValue('0.5')
                self.choice4.SetValue('0')
                self.choice6.SetValue('0')
            elif(cmp(types,'Legal Flow Filtering')==0):
                self.choice1.SetValue('1')
                self.choice2.SetValue('0.5')
                self.choice3.SetValue('0')
                self.choice4.SetValue('0.2')
                self.choice6.SetValue('0.2')
            elif(cmp(types,'Network Disconnection')==0):
                self.choice1.SetValue('0')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0.2')
                self.choice6.SetValue('0.2')  
            
                
            elif(cmp(types,'Firewall')==0):
                self.choice1.SetValue('0.8')
                self.choice2.SetValue('0.5')
                self.choice3.SetValue('0.5')
                self.choice4.SetValue('0')
                self.choice6.SetValue('0')
                
            elif(cmp(types,'Host Shutdown')==0):
                self.choice1.SetValue('0')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0')
                self.choice6.SetValue('0.2')
    def value(self, event):# get the specific attack type UDP, POD and TCP...
        types = event.GetString()
        print types
        
        print "attacktype= ", str(types) 
        fcost=open('/home/Write/attacktype.txt','w')
        fcost.write(types)
        fcost.close()

    def selChoice1(self, event):
        if((os.path.isfile( '/home/Write/attacktype.txt')==False) or (os.path.isfile( '/home/Write/methodtype.txt')==False)):#Warming, if not set values for all of 8 parameters        
            self.controller.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
            return
       
        else: 
            #self.log.Clear() 
            fread=open('/home/Write/attacktype.txt','r')
            attack=fread.readline() #e.g. now choosing best option for 'UDP attack' 
            fread2=open('/home/Write/methodtype.txt','r') #e.g. now calculte cost score for method "IPS"
            pmethod=fread2.readline()    
                
            if((cmp(attack," ")==0) or(cmp(pmethod," ")==0) ):        
                self.controller.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
                return
            
            else:
                #self.log.Clear()
                item = event.GetString()    
                print "recoveryvalue =%s"%item   # test
                nfile="/home/Write/"+attack+"_"+pmethod+"_recoveryvalue.txt"            
                fcost=open(nfile,'w')
                fcost.write(item)    
                fcost.close()
                fread.close()
                fread2.close()
    def selChoice2(self, event): 
        if((os.path.isfile( '/home/Write/attacktype.txt')==False) or (os.path.isfile( '/home/Write/methodtype.txt')==False)):        
            self.controller.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
            return
        
        else:        
            #self.log.Clear()
            fread=open('/home/Write/attacktype.txt','r')
            attack=fread.readline()
            fread2=open('/home/Write/methodtype.txt','r')
            pmethod=fread2.readline()
            if((cmp(attack," ")==0) or(cmp(pmethod," ")==0)):            
                self.controller.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
                return
               
            else:
                #self.log.Clear()       
                item2 = event.GetString()        
                print "availabevalue =%s"%item2   # test
                nfile="/home/Write/"+attack+"_"+pmethod+"_efficiencyvalue.txt"
                #print nfile
                fcost=open(nfile,'w')
                fcost.write(item2)        
                fcost.close()
    def selChoice3(self, event):
        if((os.path.isfile( '/home/Write/attacktype.txt')==False) or (os.path.isfile( '/home/Write/methodtype.txt')==False)):        
            self.controller.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
            return
        
        else:        
            #self.log.Clear()
            fread=open('/home/Write/attacktype.txt','r')
            attack=fread.readline()
            fread2=open('/home/Write/methodtype.txt','r')
            pmethod=fread2.readline()
            if((cmp(attack," ")==0) or(cmp(pmethod," ")==0)):
                self.controller.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
                return
                  
            else:
                #self.log.Clear()     
                item3 = event.GetString()    
                print "LatencyValue =%s"%item3   # test
                nfile="/home/Write/"+attack+"_"+pmethod+"_performancevalue.txt"
                #print nfile
                fcost=open(nfile,'w')
                fcost.write(item3)    
                fcost.close()
    def selChoice4(self, event):  
        if((os.path.isfile( '/home/Write/attacktype.txt')==False) or (os.path.isfile( '/home/Write/methodtype.txt')==False)):        
            self.controller.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
            return
        else:
                #self.log.Clear()   
                fread=open('/home/Write/attacktype.txt','r')
                attack=fread.readline()
                fread2=open('/home/Write/methodtype.txt','r')
                pmethod=fread2.readline()
                if((cmp(attack," ")==0) or(cmp(pmethod," ")==0)):
                    self.controller.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
                    return         
                else:
                    #self.log.Clear()   
                    item4 = event.GetString()    
                    print "costvalue =%s"%item4   # test
                    nfile="/home/Write/"+attack+"_"+pmethod+"_costvalue.txt"
                    fcost=open(nfile,'w')
                    fcost.write(item4)    
                    fcost.close()
#    def selChoice5(self, event): 
#        if((os.path.isfile( '/root/Desktop/Write/attacktype.txt')==False) or (os.path.isfile( '/root/Desktop/Write/methodtype.txt')==False)):        
#            self.log.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
#            return
#        else: 
#            self.log.Clear()        
#            fread=open('/root/Desktop/Write/attacktype.txt','r')
#            attack=fread.readline()
#            fread2=open('/root/Desktop/Write/methodtype.txt','r')
#            pmethod=fread2.readline()
#            if((cmp(attack," ")==0) or(cmp(pmethod," ")==0)):
#                self.log.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
#                return         
#            else:
#                self.log.Clear() 
#                item5 = event.GetString()    
#                print "effectvalue =%s"%item5   # test
#                nfile="/root/Desktop/Write/"+attack+"_"+pmethod+"_effectvalue.txt"            
#                fcost=open(nfile,'w')
#                fcost.write(item5)    
#                fcost.close()
    def selChoice6(self, event):
        if((os.path.isfile( '/home/Write/attacktype.txt')==False) or (os.path.isfile( '/home/Write/methodtype.txt')==False)):        
            self.controller.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
            return
        else:
            #self.log.Clear() 
            fread=open('/home/Write/attacktype.txt','r')
            attack=fread.readline()
            fread2=open('/home/Write/methodtype.txt','r')
            pmethod=fread2.readline()
            if((cmp(attack," ")==0) or(cmp(pmethod," ")==0)):
                self.controller.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
                return          
            else:
                #self.log.Clear() 
                item6 = event.GetString()    
                print "ResourceValue =%s"%item6   # test
                nfile="/home/Write/"+attack+"_"+pmethod+"_effectvalue.txt"            
                fcost=open(nfile,'w')
                fcost.write(item6)    
                fcost.close()
#    def selChoice7(self, event):
#        if((os.path.isfile( '/root/Desktop/Write/attacktype.txt')==False) or (os.path.isfile( '/root/Desktop/Write/methodtype.txt')==False)):        
#            self.log.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
#            return
#        else:        
#            fread=open('/root/Desktop/Write/attacktype.txt','r')
#            attack=fread.readline()
#            fread2=open('/root/Desktop/Write/methodtype.txt','r')
#            pmethod=fread2.readline()
#            if((cmp(attack," ")==0) or(cmp(pmethod," ")==0)):
#                self.log.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
#                return            
#            else:
#                self.log.Clear() 
#                item7 = event.GetString()    
#                print "falsevalue =%s"%item7   # test
#                nfile="/root/Desktop/Write/"+attack+"_"+pmethod+"_falsevalue.txt"
#                #print nfile
#                fcost=open(nfile,'w')
#                fcost.write(item7)    
#                fcost.close()
#    def selChoice8(self, event):
#        if((os.path.isfile( '/root/Desktop/Write/attacktype.txt')==False) or (os.path.isfile( '/root/Desktop/Write/methodtype.txt')==False)):
#        
#            self.log.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
#            return
#        else:       
#            self.log.Clear()  
#            fread=open('/root/Desktop/Write/attacktype.txt','r')
#            attack=fread.readline()
#            fread2=open('/root/Desktop/Write/methodtype.txt','r')
#            pmethod=fread2.readline()
#            if((cmp(attack," ")==0) or(cmp(pmethod," ")==0)):
#                self.log.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
#                return          
#            else:
#                self.log.Clear() 
#                item8 = event.GetString()    
#                print "impactvalue =%s"%item8   # test
#                nfile="/root/Desktop/Write/"+attack+"_"+pmethod+"_impactvalue.txt"            
#                fcost=open(nfile,'w')
#                fcost.write(item8)    
#                fcost.close()
    def OkButton(self,event):
        #self.controller.writeText('test','red')

        self.RightOk=RightOkButton(self.controller)
        self.RightOk.ok()
        if(os.path.isfile('/home/Write/attacktype.txt')==False):        
            self.controller.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
            return
        else:
            self.GlobeFun=Globe(self.controller)
            attacktype=self.GlobeFun.Ranking()
            if (cmp(attacktype,'UDP')==0):
                callfun=self.GlobeFun.udprankfun()
            if (cmp(attacktype,'TCP_SYN')==0):
                callfun=self.GlobeFun.tcprankfun()
            if (cmp(attacktype,'ICMP')==0):
                callfun=self.GlobeFun.icmprankfun()
            if (cmp(attacktype,'POD')==0):
                callfun=self.GlobeFun.podrankfun() 
    def rankButton(self, event):
        
        if(os.path.isfile('/home/Write/attacktype.txt')==False):        
            self.controller.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
            return
        else:
            self.GlobeFun=Globe(self.controller)
            attacktype=self.GlobeFun.Ranking()
            if (cmp(attacktype,'UDP')==0):
                callfun=self.GlobeFun.udprankfun()
            if (cmp(attacktype,'TCP_SYN')==0):
                callfun=self.GlobeFun.tcprankfun()
            if (cmp(attacktype,'ICMP')==0):
                callfun=self.GlobeFun.icmprankfun()
            if (cmp(attacktype,'POD')==0):
                callfun=self.GlobeFun.podrankfun()        
            #printout=callfun[0] #all ranking
            #print printout    
            #rankdlgt = wx.MessageDialog(None,printout,'A Message Box', wx.OK | wx.ICON_QUESTION)
            #rankCodet = rankdlgt.ShowModal()
            #rankdlgt.Destroy()
            #self.log.writeText(printout,'BLACK')
            #return



#---------------------Multi-Criteria Panel---------------


      
#--------------------------------Top Right Panal set value for controller parameters---------------------
class MRPanel(wx.Panel):
    
    #def __init__(self, parent, id,left,log,mcontroller):
    def __init__(self, parent, id,log,mcontroller):
        self.mcontroller=mcontroller
        self.log=log
        #self.left=left
        wx.Panel.__init__(self, parent, id)
        #text = wx.StaticBox(self, -1, 'Values of Security Assessment Metrics')
        #sizer= wx.StaticBoxSizer(text,wx.HORIZONTAL)
        #sizer.Add(text, 1, wx.EXPAND)         
        #self.SetSizer(sizer)
        #self.bOX = wx.StaticText(self,-1, 'Weight')              
        sList = ['0','0.1', '0.2', '0.3','0.4','0.5', '0.6','0.7','0.8','0.9','1']
	weightList=['1','2','3','4','5','6','7','8','9','10']
        sampleList = ['UDP', 'TCP_SYN', 'ICMP', 'POD','SQL','Exhaustion Attacks']
        methodList = ["IPS", "Packet Filter", "Trust Platform","Replica","Network Disconnection","Host Shutdown","Process Termination", "ModSecurity"]
	criteriaList=["Usual","Quasi","V-Shape","Level","U-Shape","Gaussian"]
        self.text = wx.StaticText(self, -1, 'Attack Type:',(50,30))
	self.typeofattack=wx.ComboBox(self, -1, '', (150, 25), (200,30),sampleList) 
        self.text2 = wx.StaticText(self, -1, 'Alternative Unit:',(500,30))    
        self.typeofmethod=wx.ComboBox(self, -1, '',(620, 25), (200,30),methodList)        
        text1=wx.StaticText(self, -1, 'Criteria:',(50,70))    #---Criteria, Weight, Value---
	text1.SetForegroundColour('blue')
	text2=wx.StaticText(self, -1, 'Value:',(300,70)) 
        text2.SetForegroundColour('blue')
        text3=wx.StaticText(self, -1, 'Weight:',(550,70)) 
        text3.SetForegroundColour('blue')
	text4=wx.StaticText(self, -1, 'Criteria Function:',(780,70))  
	text4.SetForegroundColour('blue')
	#self.criteria=wx.ComboBox(self, -1, '', (270, 45), (100,30),criteriaList) 
        
        wx.StaticText(self, -1, "Execution Speed:", (45, 100))
        self.choice1=wx.ComboBox(self, -1, '',(230, 95), (200,30),sList)            
	self.weight1=wx.ComboBox(self, -1, '',(480, 95), (200,30),weightList)  
  	self.criteria1=wx.ComboBox(self, -1, '', (730, 95), (200,30),criteriaList)
        wx.StaticText(self, -1, "CPU Utilization Recovery:", (45, 140))
        self.choice2=wx.ComboBox(self, -1,'', (230, 135), (200,30),sList)
	self.weight2=wx.ComboBox(self, -1, '',(480, 135), (200,30),weightList)
        self.criteria2=wx.ComboBox(self, -1, '', (730, 135), (200,30),criteriaList)
	wx.StaticText(self, -1, "Packet Rate Recovery:", (45, 180))
        self.choice3=wx.ComboBox(self, -1,'', (230, 175), (200,30),sList)
	self.weight3=wx.ComboBox(self, -1, '',(480, 175), (200,30),weightList) 
	self.criteria3=wx.ComboBox(self, -1, '', (730, 175), (200,30),criteriaList)       
	wx.StaticText(self, -1, "Legitimate Data Recovery:", (45, 220))
        self.choice4=wx.ComboBox(self, -1, '',(230, 215),  (200,30),sList)
	self.weight4=wx.ComboBox(self, -1, '',(480, 215), (200,30),weightList)
	self.criteria4=wx.ComboBox(self, -1, '', (730, 215), (200,30),criteriaList)
        wx.StaticText(self, -1, "Memory Utilization Recovery:", (45, 260))
        self.choice5=wx.ComboBox(self, -1, '',(230, 255),  (200,30),sList)
	self.weight5=wx.ComboBox(self, -1, '',(480, 255), (200,30),weightList)
	self.criteria5=wx.ComboBox(self, -1, '', (730, 255), (200,30),criteriaList)

	wx.StaticText(self, -1, "Connection Rate Recovery:", (45, 300))
        self.choice6=wx.ComboBox(self, -1, '',(230, 295),  (200,30),sList)
	self.weight6=wx.ComboBox(self, -1, '',(480, 295), (200,30),weightList)
	self.criteria6=wx.ComboBox(self, -1, '', (730, 295), (200,30),criteriaList)

        wx.StaticText(self, -1, "Failure Login Rate Recovery:", (45,340))
        self.choice7=wx.ComboBox(self, -1,'', (230, 335),  (200,30),sList)
	self.weight7=wx.ComboBox(self, -1, '',(480, 335), (200,30),weightList)
	self.criteria7=wx.ComboBox(self, -1, '', (730, 335), (200,30),criteriaList)

	wx.StaticText(self, -1, "Cost:", (45,380))
        self.choice8=wx.ComboBox(self, -1,'', (230, 375),  (200,30),sList)
	self.weight8=wx.ComboBox(self, -1, '',(480, 375), (200,30),weightList)
	self.criteria8=wx.ComboBox(self, -1, '', (730, 375), (200,30),criteriaList)


#        wx.StaticText(self, -1, "False Alarm \n Reduction:", (200, 120))
#        self.choice7=wx.Choice(self, -1, (270, 120), choices=sList)
#        wx.StaticText(self, -1, "Impact on \n legal flow:", (200, 160))
#        self.choice8=wx.Choice(self, -1, (270, 160), choices=sList)
#        # effectiveness no.8
#        wx.StaticText(self, -1, "Effective-\n ness:", (200, 200))
#        self.choice5=wx.Choice(self, -1, (270, 200), choices=sList)
	self.Bind(wx.EVT_COMBOBOX, self.value, self.typeofattack)
	self.Bind(wx.EVT_COMBOBOX, self.methodtype,self.typeofmethod)
        self.Bind(wx.EVT_COMBOBOX, self.selChoice1, self.choice1)    
        self.Bind(wx.EVT_COMBOBOX, self.selChoice2, self.choice2)
        self.Bind(wx.EVT_COMBOBOX, self.selChoice3, self.choice3)
        self.Bind(wx.EVT_COMBOBOX, self.selChoice4, self.choice4)
        self.Bind(wx.EVT_COMBOBOX, self.selChoice5, self.choice5)
        self.Bind(wx.EVT_COMBOBOX, self.selChoice6, self.choice6)
        self.Bind(wx.EVT_COMBOBOX, self.selChoice7, self.choice7)
	self.Bind(wx.EVT_COMBOBOX, self.selWeight1, self.weight1)
	self.Bind(wx.EVT_COMBOBOX, self.selWeight2, self.weight2)
	self.Bind(wx.EVT_COMBOBOX, self.selWeight3, self.weight3)
	self.Bind(wx.EVT_COMBOBOX, self.selWeight4, self.weight4)
	self.Bind(wx.EVT_COMBOBOX, self.selWeight5, self.weight5)
	self.Bind(wx.EVT_COMBOBOX, self.selWeight6, self.weight6)
	self.Bind(wx.EVT_COMBOBOX, self.selWeight7, self.weight7)
        self.Bind(wx.EVT_COMBOBOX, self.selCriteria1, self.criteria1)
	self.Bind(wx.EVT_COMBOBOX, self.selCriteria2, self.criteria2)
	self.Bind(wx.EVT_COMBOBOX, self.selCriteria3, self.criteria3)
	self.Bind(wx.EVT_COMBOBOX, self.selCriteria4, self.criteria4)
	self.Bind(wx.EVT_COMBOBOX, self.selCriteria5, self.criteria5)
	self.Bind(wx.EVT_COMBOBOX, self.selCriteria6, self.criteria6)
	self.Bind(wx.EVT_COMBOBOX, self.selCriteria7, self.criteria7)
	# Add Cost
	self.Bind(wx.EVT_COMBOBOX, self.selChoice8, self.choice8)
	self.Bind(wx.EVT_COMBOBOX, self.selWeight8, self.weight8)
        self.Bind(wx.EVT_COMBOBOX, self.selCriteria8, self.criteria8)
        #----------ok button-----------------
        self.ok = wx.Button(self, id=-1, label='Submit',pos=(480, 420), size=(200,30))
        self.ok.Bind(wx.EVT_BUTTON, self.OkButton)
        self.restore= wx.Button(self, id=-1, label='Restore Default Value',pos=(730, 420),size=(200,30))
        self.restore.Bind(wx.EVT_BUTTON, self.restorebutton)
        #------------Rank button ------------
        #self.realrank = wx.Button(self, id=-1, label='Ranking', pos=(270, 330), size=(80, 35))
        #self.realrank.Bind(wx.EVT_BUTTON, self.rankButton)
        self.MRightOk=MRightOkButton(self.mcontroller)
        self.GlobeFun=MGlobe(self.mcontroller)
        
        #self.left=LPanel(self,-1,self.log)
    def methodtype(self, event): #get the protect method
	message1="UDP Attack Default Candiate Protection Methods Ranking:\n"
	message2="TCP Attack Default Candiate Protection Methods Ranking:\n"
	message3="ICMP Attack Default Candiate Protection Methods Ranking:\n"
	message4="POD Attack Default Candiate Protection Methods Ranking:\n"
	message5="SQL Attack Default Candiate Protection Methods Ranking:\n"
	message6="Exhaution Attack Default Candiate Protection Methods Ranking:\n"
        ##message1="""UDP Default Protected Processes Ranking:\n
##        No. 1  : IPS (0.5)\n
##        No. 2  : Filter (1.8)\n
##        No. 3  : Firewall (2.1)\n
##        No. 4 : Host Shutdown (3.1)\n
##        No. 5  : Trust Platform (3.3)\n
##        No. 6  : Networking Disconnection (3.3)\n"""
##        
##        message2="""TCP SYN Default Protected Processes Ranking:\n
##        No. 1  : Filter (1.5)\n        
##        No. 2  : Firewall (3.1)\n
##        No. 3 : Host Shutdown (3.1)\n
##        No. 4  : IPS (3.3)\n
##        No. 5  : Trust Platform (3.3)\n
##        No. 6  : Networking Disconnection (3.3)\n      """
##        
##        
##        message3="""ICMP Default Protected Processes Ranking:\n
##        No. 1  : IPS (0.5)\n
##        No. 2  : Filter (1.8)\n
##        No. 3  : Firewall (2.1)\n
##        No. 4 : Host Shutdown (3.1)\n
##        No. 5  : Trust Platform (3.3)\n
##        No. 6  : Networking Disconnection (3.3)\n"""
##        
##        message4="""POD Default Protected Processes Ranking:\n
##        No. 1  : IPS (0.5)\n
##        No. 2  : Filter (1.8)\n
##        No. 3  : Firewall (2.1)\n
##        No. 4 : Host Shutdown (3.1)\n
##        No. 5  : Trust Platform (3.3)\n
##        No. 6  : Networking Disconnection (3.3)\n"""
        types = event.GetString()
        print "Mprotectiontype= ", str(types)  #protected process as IPS, Port Disablement and ...
        fcost=open('/home/MWrite/Mattacktype.txt','r')
        attack=fcost.readline()        
        fmethod=open('/home/MWrite/Mmethodtype.txt','w')
        fmethod.write(types) #save for later check which process need to be calculated its score
        fcost.close()
        fmethod.close()
	
        if(cmp(attack,'UDP')==0 or cmp(attack,'POD')==0 or cmp(attack,'ICMP')==0 ):
            if(cmp(types,'IPS')==0 ):             
                
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0.2')
                self.choice3.SetValue('0.2')
                self.choice4.SetValue('0')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.2')
		self.choice7.SetValue('1')
     		self.choice8.SetValue('0.2')
            elif(cmp(types,'Packet Filter')==0):
                
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0')
		self.choice7.SetValue('1')
                self.choice8.SetValue('0.2')

            elif(cmp(types,'Trust Platform')==0):
               
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('1')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.2')

	    elif(cmp(types,'Replica')==0):
                
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('1')
                self.choice3.SetValue('0')
                self.choice4.SetValue('0')
                self.choice5.SetValue('1')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.8')
                        
            elif(cmp(types,'Network Disconnection')==0):
                #self.choice6=wx.ComboBox(self, -1,'0', (90, 290),  wx.DefaultSize,sList)
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.5')
                
            elif(cmp(types,'Host Shutdown')==0):
               
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.5')
	    elif(cmp(types,'Process Termination')==0):
               
                self.choice1.SetValue('0.1')
                self.choice2.SetValue('0.6')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0.5')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.4')
	    
	    elif(cmp(types,'ModSecurity')==0):
               
                self.choice1.SetValue('0')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0')
	    self.weight1.SetValue('1')
            self.weight2.SetValue('1')
            self.weight3.SetValue('1')
            self.weight4.SetValue('1')
            self.weight5.SetValue('1')
            self.weight6.SetValue('1')
            self.weight7.SetValue('1')
	    self.weight8.SetValue('1')
	    self.criteria1.SetValue('Gaussian')
	    self.criteria2.SetValue('V-shape')
	    self.criteria3.SetValue('V-shape')
	    self.criteria4.SetValue('V-shape')
	    self.criteria5.SetValue('V-shape')
	    self.criteria6.SetValue('V-shape')
	    self.criteria7.SetValue('V-shape')
	    self.criteria8.SetValue('V-shape')
            if(cmp(attack,'UDP')==0 ):
                #self.log.Clear()
                self.mcontroller.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLUE')
                self.mcontroller.writeText(message1,'BLUE')
                
            if(cmp(attack,'POD')==0):
                #self.log.Clear()
                self.mcontroller.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLUE')
                self.mcontroller.writeText(message4,'BLUE')
                
            if(cmp(attack,'ICMP')==0):
                #self.log.Clear()
                self.mcontroller.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLUE')
                self.mcontroller.writeText(message3,'BLUE')
                
        elif(cmp(attack,'TCP_SYN')==0):
            #self.log.Clear()
            self.mcontroller.writeText(message2,'Blue')
            if(cmp(types,'IPS')==0 ):             
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0.2')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.2')
		self.choice7.SetValue('1')
     		self.choice8.SetValue('0.2')
            elif(cmp(types,'Packet Filter')==0):
                
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('0.5')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0')
		self.choice7.SetValue('1')
                self.choice8.SetValue('0.2')

            elif(cmp(types,'Trust Platform')==0):
               
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('1')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.2')

	    elif(cmp(types,'Replica')==0):
                
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('1')
                self.choice3.SetValue('0')
                self.choice4.SetValue('0')
                self.choice5.SetValue('1')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.8')
                        
            elif(cmp(types,'Network Disconnection')==0):
                #self.choice6=wx.ComboBox(self, -1,'0', (90, 290),  wx.DefaultSize,sList)
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.5')
                
            elif(cmp(types,'Host Shutdown')==0):
               
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.5')
            elif(cmp(types,'Process Termination')==0):
               
                self.choice1.SetValue('0.1')
                self.choice2.SetValue('0.6')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0.5')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.4')
	    
	    elif(cmp(types,'ModSecurity')==0):
               
                self.choice1.SetValue('0')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0')
	    self.weight1.SetValue('1')
            self.weight2.SetValue('1')
            self.weight3.SetValue('1')
            self.weight4.SetValue('1')
            self.weight5.SetValue('1')
            self.weight6.SetValue('1')
            self.weight7.SetValue('1')
	    self.weight8.SetValue('1')
	    self.criteria1.SetValue('Gaussian')
	    self.criteria2.SetValue('V-shape')
	    self.criteria3.SetValue('V-shape')
	    self.criteria4.SetValue('V-shape')
	    self.criteria5.SetValue('V-shape')
	    self.criteria6.SetValue('V-shape')
	    self.criteria7.SetValue('V-shape')
	    self.criteria8.SetValue('V-shape')
        elif(cmp(attack,'SQL')==0):
            #self.log.Clear()
            self.mcontroller.writeText(message5,'Blue')
            if(cmp(types,'IPS')==0 ):             
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0.2')
                self.choice3.SetValue('0.2')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.2')
		self.choice7.SetValue('1')
     		self.choice8.SetValue('0.2')
            elif(cmp(types,'Packet Filter')==0):
                
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0')
		self.choice7.SetValue('0')
                self.choice8.SetValue('0.2')

            elif(cmp(types,'Trust Platform')==0):
               
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0.8')
                self.choice5.SetValue('1')
               	self.choice6.SetValue('0')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.2')

	    elif(cmp(types,'Replica')==0):
                
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0')
                self.choice5.SetValue('1')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.8')
                        
            elif(cmp(types,'Network Disconnection')==0):
                #self.choice6=wx.ComboBox(self, -1,'0', (90, 290),  wx.DefaultSize,sList)
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.5')
                
            elif(cmp(types,'Host Shutdown')==0):
               
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.5')

	    elif(cmp(types,'Process Termination')==0):
               
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('0.6')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0.5')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.4')

	    elif(cmp(types,'ModSecurity')==0):
               
                self.choice1.SetValue('0')
                self.choice2.SetValue('0')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0')  
            self.weight1.SetValue('1')
            self.weight2.SetValue('1')
            self.weight3.SetValue('1')
            self.weight4.SetValue('1')
            self.weight5.SetValue('1')
            self.weight6.SetValue('1')
            self.weight7.SetValue('1')
	    self.weight8.SetValue('1')
	    self.criteria1.SetValue('Gaussian')
	    self.criteria2.SetValue('V-shape')
	    self.criteria3.SetValue('V-shape')
	    self.criteria4.SetValue('V-shape')
	    self.criteria5.SetValue('V-shape')
	    self.criteria6.SetValue('V-shape')
	    self.criteria7.SetValue('V-shape')
	    self.criteria8.SetValue('V-shape')
	elif(cmp(attack,'Exhaustion Attacks')==0):
            #self.log.Clear()
            self.mcontroller.writeText(message6,'Blue')
            if(cmp(types,'IPS')==0 ):             
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0.2')
                self.choice3.SetValue('0.2')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.2')
		self.choice7.SetValue('1')
     		self.choice8.SetValue('0.2')
            elif(cmp(types,'Packet Filter')==0):
                
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0')
		self.choice7.SetValue('0')
                self.choice8.SetValue('0.2')

            elif(cmp(types,'Trust Platform')==0):
               
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0.8')
                self.choice5.SetValue('1')
               	self.choice6.SetValue('0')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.2')

	    elif(cmp(types,'Replica')==0):
                
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0')
                self.choice5.SetValue('1')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.8')
                        
            elif(cmp(types,'Network Disconnection')==0):
                #self.choice6=wx.ComboBox(self, -1,'0', (90, 290),  wx.DefaultSize,sList)
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.5')
                
            elif(cmp(types,'Host Shutdown')==0):
               
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.5')

	    elif(cmp(types,'Process Termination')==0):
               
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('0.6')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0.5')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.4')

	    elif(cmp(types,'ModSecurity')==0):
               
                self.choice1.SetValue('0')
                self.choice2.SetValue('0')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0')  
	    self.weight1.SetValue('1')
            self.weight2.SetValue('1')
            self.weight3.SetValue('1')
            self.weight4.SetValue('1')
            self.weight5.SetValue('1')
            self.weight6.SetValue('1')
            self.weight7.SetValue('1')
	    self.weight8.SetValue('1')
	    self.criteria1.SetValue('Gaussian')
	    self.criteria2.SetValue('V-shape')
	    self.criteria3.SetValue('V-shape')
	    self.criteria4.SetValue('V-shape')
	    self.criteria5.SetValue('V-shape')
	    self.criteria6.SetValue('V-shape')
	    self.criteria7.SetValue('V-shape')
	    self.criteria8.SetValue('V-shape')
            
    
    def restorebutton(self,event):
        #GlobeFun=Globe(self.log)
        self.GlobeFun.Initial()
        self.left.choice1.SetValue('0')
	message1="UDP Attack Default Candidate Protection Methods Ranking:\n"
	message2="TCP Attack Default Candiate Protection Methods Ranking:\n"
	message3="ICMP Attack Default Candiate Protection Methods Ranking:\n"
	message4="POD Attack Default Candiate Protection Methods Ranking:\n"
	message5="SQL Attack Default Candiate Protection Methods Ranking:\n"
	message6="Exhaution Attack Default Candiate Protection Methods Ranking:\n"
        ##message1="""UDP Default Protected Processes Ranking:\n
##        No. 1  : IPS (0.5)\n
##        No. 2  : Filter (1.8)\n
##        No. 3  : Firewall (2.1)\n
##        No. 4 : Host Shutdown (3.1)\n
##        No. 5  : Trust Platform (3.3)\n
##        No. 6  : Networking Disconnection (3.3)\n"""
##        
##        message2="""TCP SYN Default Protected Processes Ranking:\n
##        No. 1  : Filter (1.5)\n        
##        No. 2  : Firewall (3.1)\n
##        No. 3 : Host Shutdown (3.1)\n
##        No. 4  : IPS (3.3)\n
##        No. 5  : Trust Platform (3.3)\n
##        No. 6  : Networking Disconnection (3.3)\n      """
##        
##        
##        message3="""ICMP Default Protected Processes Ranking:\n
##        No. 1  : IPS (0.5)\n
##        No. 2  : Filter (1.8)\n
##        No. 3  : Firewall (2.1)\n
##        No. 4 : Host Shutdown (3.1)\n
##        No. 5  : Trust Platform (3.3)\n
##        No. 6  : Networking Disconnection (3.3)\n"""
##        
##        message4="""POD Default Protected Processes Ranking:\n
##        No. 1  : IPS (0.5)\n
##        No. 2  : Filter (1.8)\n
##        No. 3  : Firewall (2.1)\n
##        No. 4 : Host Shutdown (3.1)\n
##        No. 5  : Trust Platform (3.3)\n
##        No. 6  : Networking Disconnection (3.3)\n"""
        if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):#
             self.mcontroller.writeText('Please select attack types and protection methods','RED')
         
             
        fcost=open('/home/MWrite/Mattacktype.txt','r')
        attack=fcost.readline()
        fmethod=open('/home/MWrite/Mmethodtype.txt','r')
        types=fmethod.readline()
        fmethod.close()
        
        if(cmp(attack,'UDP')==0 or cmp(attack,'POD')==0 or cmp(attack,'ICMP')==0 ):
            if(cmp(types,'IPS')==0 ):             
                
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0.2')
                self.choice3.SetValue('0.2')
                self.choice4.SetValue('0')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.2')
		self.choice7.SetValue('1')
     		self.choice8.SetValue('0.2')
            elif(cmp(types,'Packet Filter')==0):
                
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0')
		self.choice7.SetValue('1')
                self.choice8.SetValue('0.2')

            elif(cmp(types,'Trust Platform')==0):
               
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('1')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.2')

	    elif(cmp(types,'Replica')==0):
                
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('1')
                self.choice3.SetValue('0')
                self.choice4.SetValue('0')
                self.choice5.SetValue('1')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.8')
                        
            elif(cmp(types,'Network Disconnection')==0):
                #self.choice6=wx.ComboBox(self, -1,'0', (90, 290),  wx.DefaultSize,sList)
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.5')
                
            elif(cmp(types,'Host Shutdown')==0):
               
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.5')
	    elif(cmp(types,'Process Termination')==0):
               
                self.choice1.SetValue('0.1')
                self.choice2.SetValue('0.6')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0.5')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.4')
	    
	    elif(cmp(types,'ModSecurity')==0):
               
                self.choice1.SetValue('0')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0')

            if(cmp(attack,'UDP')==0 ):
                #self.log.Clear()
                self.mcontroller.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLUE')
                self.mcontroller.writeText(message1,'BLUE')
                
            if(cmp(attack,'POD')==0):
                #self.log.Clear()
                self.mcontroller.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLUE')
                self.mcontroller.writeText(message4,'BLUE')
                
            if(cmp(attack,'ICMP')==0):
                #self.log.Clear()
                self.mcontroller.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLUE')
                self.mcontroller.writeText(message3,'BLUE')
                
        elif(cmp(attack,'TCP_SYN')==0):
            #self.log.Clear()
            self.mcontroller.writeText(message2,'Blue')
            if(cmp(types,'IPS')==0 ):             
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0.2')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.2')
		self.choice7.SetValue('1')
     		self.choice8.SetValue('0.2')
            elif(cmp(types,'Packet Filter')==0):
                
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('0.5')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0')
		self.choice7.SetValue('1')
                self.choice8.SetValue('0.2')

            elif(cmp(types,'Trust Platform')==0):
               
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('1')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.2')

	    elif(cmp(types,'Replica')==0):
                
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('1')
                self.choice3.SetValue('0')
                self.choice4.SetValue('0')
                self.choice5.SetValue('1')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.8')
                        
            elif(cmp(types,'Network Disconnection')==0):
                #self.choice6=wx.ComboBox(self, -1,'0', (90, 290),  wx.DefaultSize,sList)
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.5')
                
            elif(cmp(types,'Host Shutdown')==0):
               
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.5')
            elif(cmp(types,'Process Termination')==0):
               
                self.choice1.SetValue('0.1')
                self.choice2.SetValue('0.6')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0.5')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.4')
	    
	    elif(cmp(types,'ModSecurity')==0):
               
                self.choice1.SetValue('0')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0')
        elif(cmp(attack,'SQL')==0):
            #self.log.Clear()
            self.mcontroller.writeText(message5,'Blue')
            if(cmp(types,'IPS')==0 ):             
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0.2')
                self.choice3.SetValue('0.2')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.2')
		self.choice7.SetValue('1')
     		self.choice8.SetValue('0.2')
            elif(cmp(types,'Packet Filter')==0):
                
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0')
		self.choice7.SetValue('0')
                self.choice8.SetValue('0.2')

            elif(cmp(types,'Trust Platform')==0):
               
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0.8')
                self.choice5.SetValue('1')
               	self.choice6.SetValue('0')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.2')

	    elif(cmp(types,'Replica')==0):
                
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0')
                self.choice5.SetValue('1')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.8')
                        
            elif(cmp(types,'Network Disconnection')==0):
                #self.choice6=wx.ComboBox(self, -1,'0', (90, 290),  wx.DefaultSize,sList)
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.5')
                
            elif(cmp(types,'Host Shutdown')==0):
               
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.5')

	    elif(cmp(types,'Process Termination')==0):
               
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('0.6')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0.5')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.4')

	    elif(cmp(types,'ModSecurity')==0):
               
                self.choice1.SetValue('0')
                self.choice2.SetValue('0')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0')  
	elif(cmp(attack,'Exhaustion Attacks')==0):
            #self.log.Clear()
            self.mcontroller.writeText(message6,'Blue')
            if(cmp(types,'IPS')==0 ):             
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0.2')
                self.choice3.SetValue('0.2')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.2')
		self.choice7.SetValue('1')
     		self.choice8.SetValue('0.2')
            elif(cmp(types,'Packet Filter')==0):
                
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0')
		self.choice7.SetValue('0')
                self.choice8.SetValue('0.2')

            elif(cmp(types,'Trust Platform')==0):
               
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0.8')
                self.choice5.SetValue('1')
               	self.choice6.SetValue('0')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.2')

	    elif(cmp(types,'Replica')==0):
                
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('1')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0')
                self.choice5.SetValue('1')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.8')
                        
            elif(cmp(types,'Network Disconnection')==0):
                #self.choice6=wx.ComboBox(self, -1,'0', (90, 290),  wx.DefaultSize,sList)
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.5')
                
            elif(cmp(types,'Host Shutdown')==0):
               
                self.choice1.SetValue('0.3')
                self.choice2.SetValue('0')
                self.choice3.SetValue('0')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0.5')

	    elif(cmp(types,'Process Termination')==0):
               
                self.choice1.SetValue('0.2')
                self.choice2.SetValue('0.6')
                self.choice3.SetValue('1')
                self.choice4.SetValue('1')
                self.choice5.SetValue('0.5')
               	self.choice6.SetValue('1')
		self.choice7.SetValue('1')
		self.choice8.SetValue('0.4')

	    elif(cmp(types,'ModSecurity')==0):
               
                self.choice1.SetValue('0')
                self.choice2.SetValue('0')
                self.choice3.SetValue('1')
                self.choice4.SetValue('0')
                self.choice5.SetValue('0')
               	self.choice6.SetValue('0.5')
		self.choice7.SetValue('0')
		self.choice8.SetValue('0')        
            self.weight1.SetValue('1')
            self.weight2.SetValue('1')
            self.weight3.SetValue('1')
            self.weight4.SetValue('1')
            self.weight5.SetValue('1')
            self.weight6.SetValue('1')
            self.weight7.SetValue('1')
	    self.weight8.SetValue('1')
	    self.criteria1.SetValue('Gaussian')
	    self.criteria2.SetValue('V-shape')
	    self.criteria3.SetValue('V-shape')
	    self.criteria4.SetValue('V-shape')
	    self.criteria5.SetValue('V-shape')
	    self.criteria6.SetValue('V-shape')
	    self.criteria7.SetValue('V-shape')
	    self.criteria8.SetValue('V-shape')
        #fcost.write(types) #save for later check which process need to be calculated its score
        fcost.close()
    def value(self, event):# get the specific attack type UDP, POD and TCP...
        types = event.GetString()
        print types
        
        print "Mattacktype= ", str(types) 
        fcost=open('/home/MWrite/Mattacktype.txt','w')
        fcost.write(types)
        fcost.close()
    #-----------Criteria Function---------------- 
    def selCriteria1(self, event):# get the specific criteria function V-shape...
	if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):#Warming, if not set values for all of 8 parameters        
            self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
            return        
	else:
	    fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline() 
	    types = event.GetString()        
            print "Mfunction= ", str(types) 
            nfile="/home/MWrite/"+attack+"_Speed_MCriteria.txt"            
            fcost=open(nfile,'w')
            fcost.write(types)    
            fcost.close()
            fread.close()
    def selCriteria2(self, event):# get the specific criteria function V-shape...
	if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):
            self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
            return        
	else:
	    fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline() 
	    types = event.GetString()        
            print "Mfunction= ", str(types) 
            nfile="/home/MWrite/"+attack+"_CPU_MCriteria.txt"            
            fcost=open(nfile,'w')
            fcost.write(types)    
            fcost.close()
            fread.close()       
    def selCriteria3(self, event):# get the specific criteria function V-shape...
	if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):
            self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
            return        
	else:
	    fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline() 
	    types = event.GetString()        
            print "Mfunction= ", str(types) 
            nfile="/home/MWrite/"+attack+"_Packet_MCriteria.txt"            
            fcost=open(nfile,'w')
            fcost.write(types)    
            fcost.close()
            fread.close()
    def selCriteria4(self, event):# get the specific criteria function V-shape...
	if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):
            self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
            return        
	else:
	    fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline() 
	    types = event.GetString()        
            print "Mfunction= ", str(types) 
            nfile="/home/MWrite/"+attack+"_Data_MCriteria.txt"            
            fcost=open(nfile,'w')
            fcost.write(types)    
            fcost.close()
            fread.close()
    def selCriteria5(self, event):# get the specific criteria function V-shape...
	if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):
            self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
            return        
	else:
	    fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline() 
	    types = event.GetString()        
            print "Mfunction= ", str(types) 
            nfile="/home/MWrite/"+attack+"_Loss_MCriteria.txt"            
            fcost=open(nfile,'w')
            fcost.write(types)    
            fcost.close()
            fread.close()
    def selCriteria6(self, event):# get the specific criteria function V-shape...
	if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):
            self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
            return        
	else:
	    fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline() 
	    types = event.GetString()        
            print "Mfunction= ", str(types) 
            nfile="/home/MWrite/"+attack+"_Connection_MCriteria.txt"            
            fcost=open(nfile,'w')
            fcost.write(types)    
            fcost.close()
            fread.close()
    def selCriteria7(self, event):# get the specific criteria function V-shape...
	if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):
            self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
            return        
	else:
	    fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline() 
	    types = event.GetString()        
            print "Mfunction= ", str(types) 
            nfile="/home/MWrite/"+attack+"_Login_MCriteria.txt"            
            fcost=open(nfile,'w')
            fcost.write(types)    
            fcost.close()
            fread.close()

    def selCriteria8(self, event):# get the specific criteria function V-shape...
	if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):
            self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
            return        
	else:
	    fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline() 
	    types = event.GetString()        
            print "Mfunction= ", str(types) 
            nfile="/home/MWrite/"+attack+"_Login_MCriteria.txt"            
            fcost=open(nfile,'w')
            fcost.write(types)    
            fcost.close()
            fread.close()

#-----------------selChoice----------------

    def selChoice1(self, event):
        if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):#Warming, if not set values for all of 8 parameters        
            self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
            return
       
        else: 
            #self.log.Clear() 
            fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline() #e.g. now choosing best option for 'UDP attack' 
            fread2=open('/home/MWrite/Mmethodtype.txt','r') #e.g. now calculte cost score for method "IPS"
            pmethod=fread2.readline()    
                
            if((cmp(attack," ")==0) or(cmp(pmethod," ")==0) ):        
                self.mcontroller.writeText('Error: Please Choose Attack Type, Alternative And Reset The Value','RED')
                return
            
            else:
                #self.log.Clear()
                item = event.GetString()    
                print "recoveryvalue =%s"%item   # test
                nfile="/home/MWrite/"+attack+"_"+pmethod+"_Mspeed.txt"            
                fcost=open(nfile,'w')
                fcost.write(item)    
                fcost.close()
                fread.close()
                fread2.close()
    def selChoice2(self, event): 
        if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):        
            self.mcontroller.writeText('Error: Please Choose Attack Type, Alternative and Reset The Value','RED')
            return
        
        else:        
            #self.log.Clear()
            fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline()
            fread2=open('/home/MWrite/Mmethodtype.txt','r')
            pmethod=fread2.readline()
            if((cmp(attack," ")==0) or(cmp(pmethod," ")==0)):            
                self.mcontroller.writeText('Error: Please Choose Attack Type, Alternative And Reset The Value','RED')
                return
               
            else:
                #self.log.Clear()       
                item2 = event.GetString()        
                print "availabevalue =%s"%item2   # test
                nfile="/home/MWrite/"+attack+"_"+pmethod+"_Mcpu.txt"
                #print nfile
                fcost=open(nfile,'w')
                fcost.write(item2)        
                fcost.close()
    def selChoice3(self, event):
        if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):        
            self.mcontroller.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
            return
        
        else:        
            #self.log.Clear()
            fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline()
            fread2=open('/home/MWrite/Mmethodtype.txt','r')
            pmethod=fread2.readline()
            if((cmp(attack," ")==0) or(cmp(pmethod," ")==0)):
                self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
                return
                  
            else:
                #self.log.Clear()     
                item3 = event.GetString()    
                print "LatencyValue =%s"%item3   # test
                nfile="/home/MWrite/"+attack+"_"+pmethod+"_Mpacket.txt"
                #print nfile
                fcost=open(nfile,'w')
                fcost.write(item3)    
                fcost.close()
    def selChoice4(self, event):  
        if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):        
            self.mcontroller.writeText('Error: Please Choose Attack Type, Alternative And Reset The Value','RED')
            return
        else:
                #self.log.Clear()   
                fread=open('/home/MWrite/Mattacktype.txt','r')
                attack=fread.readline()
                fread2=open('/home/MWrite/Mmethodtype.txt','r')
                pmethod=fread2.readline()
                if((cmp(attack," ")==0) or(cmp(pmethod," ")==0)):
                    self.mcontroller.writeText('Error: Please Choose Attack Type, Alternative And Reset The Value','RED')
                    return         
                else:
                    #self.log.Clear()   
                    item4 = event.GetString()    
                    print "costvalue =%s"%item4   # test
                    nfile="/home/MWrite/"+attack+"_"+pmethod+"_Mdata.txt"
                    fcost=open(nfile,'w')
                    fcost.write(item4)    
                    fcost.close()
    def selChoice5(self, event): 
        if((os.path.isfile( '/root/Desktop/Write/Mattacktype.txt')==False) or (os.path.isfile( '/root/Desktop/Write/Mmethodtype.txt')==False)):        
            self.log.writeText('Error: Please Choose Attack Type, Alternative And Reset The Value','RED')
            return
        else: 
            self.log.Clear()        
            fread=open('/root/Desktop/Write/Mattacktype.txt','r')
            attack=fread.readline()
            fread2=open('/root/Desktop/Write/Mmethodtype.txt','r')
            pmethod=fread2.readline()
            if((cmp(attack," ")==0) or(cmp(pmethod," ")==0)):
                self.log.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
                return         
            else:
                self.log.Clear() 
                item5 = event.GetString()    
                print "effectvalue =%s"%item5   # test
                nfile="/root/Desktop/Write/"+attack+"_"+pmethod+"_Mlegitimate.txt"            
                fcost=open(nfile,'w')
                fcost.write(item5)    
                fcost.close()
    def selChoice6(self, event):
        if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):        
            self.mcontroller.writeText('Error: Please Choose Attack Type, Alternative And Reset The Value','RED')
            return
        else:
            #self.log.Clear() 
            fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline()
            fread2=open('/home/MWrite/Mmethodtype.txt','r')
            pmethod=fread2.readline()
            if((cmp(attack," ")==0) or(cmp(pmethod," ")==0)):
                self.mcontroller.writeText('Error: Please Choose Attack Type, Alternative And Reset The Value','RED')
                return          
            else:
                #self.log.Clear() 
                item6 = event.GetString()    
                print "ResourceValue =%s"%item6   # test
                nfile="/home/MWrite/"+attack+"_"+pmethod+"_Mconnection.txt"            
                fcost=open(nfile,'w')
                fcost.write(item6)    
                fcost.close()
    def selChoice7(self, event):
        if((os.path.isfile( '/root/Desktop/Write/Mattacktype.txt')==False) or (os.path.isfile( '/root/Desktop/Write/Mmethodtype.txt')==False)):        
            self.log.writeText('Error: Please Choose Attack Type, Alternative And Reset The Value','RED')
            return
        else:        
            fread=open('/root/Desktop/Write/Mattacktype.txt','r')
            attack=fread.readline()
            fread2=open('/root/Desktop/Write/Mmethodtype.txt','r')
            pmethod=fread2.readline()
            if((cmp(attack," ")==0) or(cmp(pmethod," ")==0)):
                self.log.writeText('Error: Please Choose Attack Type, Alternative And Reset The Value','RED')
                return            
            else:
                self.log.Clear() 
                item7 = event.GetString()    
                print "falsevalue =%s"%item7   # test
                nfile="/root/Desktop/Write/"+attack+"_"+pmethod+"_Mfalsevalue.txt"
                #print nfile
                fcost=open(nfile,'w')
                fcost.write(item7)    
                fcost.close()

    def selChoice8(self, event):
        if((os.path.isfile( '/root/Desktop/Write/Mattacktype.txt')==False) or (os.path.isfile( '/root/Desktop/Write/Mmethodtype.txt')==False)):        
            self.log.writeText('Error: Please Choose Attack Type, Alternative And Reset The Value','RED')
            return
        else:        
            fread=open('/root/Desktop/Write/Mattacktype.txt','r')
            attack=fread.readline()
            fread2=open('/root/Desktop/Write/Mmethodtype.txt','r')
            pmethod=fread2.readline()
            if((cmp(attack," ")==0) or(cmp(pmethod," ")==0)):
                self.log.writeText('Error: Please Choose Attack Type, Alternative And Reset The Value','RED')
                return            
            else:
                self.log.Clear() 
                item8 = event.GetString()    
                print "falsevalue =%s"%item8   # test
                nfile="/root/Desktop/Write/"+attack+"_"+pmethod+"_Mfalsevalue.txt"
                #print nfile
                fcost=open(nfile,'w')
                fcost.write(item8)    
                fcost.close()
#    def selChoice8(self, event):
#        if((os.path.isfile( '/root/Desktop/Write/attacktype.txt')==False) or (os.path.isfile( '/root/Desktop/Write/methodtype.txt')==False)):
#        
#            self.log.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
#            return
#        else:       
#            self.log.Clear()  
#            fread=open('/root/Desktop/Write/attacktype.txt','r')
#            attack=fread.readline()
#            fread2=open('/root/Desktop/Write/methodtype.txt','r')
#            pmethod=fread2.readline()
#            if((cmp(attack," ")==0) or(cmp(pmethod," ")==0)):
#                self.log.writeText('Error: Please Choose Attack Type,Protected Method And Reset The Value','RED')
#                return          
#            else:
#                self.log.Clear() 
#                item8 = event.GetString()    
#                print "impactvalue =%s"%item8   # test
#                nfile="/root/Desktop/Write/"+attack+"_"+pmethod+"_impactvalue.txt"            
#                fcost=open(nfile,'w')
#                fcost.write(item8)    
#                fcost.close()
   #-----------Weight---------
    def selWeight1(self, event):
                
        if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):
            self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
            return        
	else:
	    fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline() 
	    types = event.GetString()        
            print "WeightMain= ", str(types) 
            nfile="/home/MWrite/"+attack+"_SpeedWeight.txt"            
            fcost=open(nfile,'w')
            fcost.write(types)    
            fcost.close()
            fread.close()  
        
    def selWeight2(self, event):
	if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):
            self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
            return        
	else:
	    fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline() 
	    types = event.GetString()        
            print "WeightMain= ", str(types) 
            nfile="/home/MWrite/"+attack+"_CPUWeight.txt"            
            fcost=open(nfile,'w')
            fcost.write(types)    
            fcost.close()
            fread.close()  
        
    def selWeight3(self, event):
	if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):
            self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
            return        
	else:
	    fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline() 
	    types = event.GetString()        
            print "WeightMain= ", str(types) 
            nfile="/home/MWrite/"+attack+"_PacketWeight.txt"            
            fcost=open(nfile,'w')
            fcost.write(types)    
            fcost.close()
            fread.close()  

        
    def selWeight4(self, event):
	if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):
            self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
            return        
	else:
	    fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline() 
	    types = event.GetString()        
            print "WeightMain= ", str(types) 
            nfile="/home/MWrite/"+attack+"_DataWeight.txt"            
            fcost=open(nfile,'w')
            fcost.write(types)    
            fcost.close()
            fread.close()  
	
    def selWeight5(self, event):
	if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):
            self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
            return        
	else:
	    fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline() 
	    types = event.GetString()        
            print "WeightMain= ", str(types) 
            nfile="/home/MWrite/"+attack+"_LossWeight.txt"            
            fcost=open(nfile,'w')
            fcost.write(types)    
            fcost.close()
            fread.close()  

    def selWeight6(self, event):
	if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):
            self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
            return        
	else:
	    fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline() 
	    types = event.GetString()        
            print "WeightMain= ", str(types) 
            nfile="/home/MWrite/"+attack+"_ConnectionWeight.txt"            
            fcost=open(nfile,'w')
            fcost.write(types)    
            fcost.close()
            fread.close()  

    def selWeight7(self, event):
	if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):
            self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
            return        
	else:
	    fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline() 
	    types = event.GetString()        
            print "WeightMain= ", str(types) 
            nfile="/home/MWrite/"+attack+"_LoginWeight.txt"            
            fcost=open(nfile,'w')
            fcost.write(types)    
            fcost.close()
            fread.close()  
    def selWeight8(self, event):
	if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):
            self.mcontroller.writeText('Error: Please Choose Attack Type,Alternative And Reset The Value','RED')
            return        
	else:
	    fread=open('/home/MWrite/Mattacktype.txt','r')
            attack=fread.readline() 
	    types = event.GetString()        
            print "WeightMain= ", str(types) 
            nfile="/home/MWrite/"+attack+"_LoginWeight.txt"            
            fcost=open(nfile,'w')
            fcost.write(types)    
            fcost.close()
            fread.close() 

	#-------OkButton---------
    def OkButton(self,event):
        #self.controller.writeText('test','red')

        self.MRightOk=MRightOkButton(self.mcontroller)
        self.MRightOk.ok()
        ##if(os.path.isfile('/home/MWrite/Mattacktype.txt')==False):        
##            self.mcontroller.writeText('Error: Please Choose Attack Type, Alternative And Reset The Value','RED')
##            return
##        else:
##            self.MGlobeFun=MGlobe(self.mcontroller)
##            attacktype=self.MGlobeFun.Ranking()
##            if (cmp(attacktype,'UDP')==0):
##                callfun=self.MGlobeFun.udprankfun()
##            if (cmp(attacktype,'TCP_SYN')==0):
##                callfun=self.MGlobeFun.tcprankfun()
##            if (cmp(attacktype,'ICMP')==0):
##                callfun=self.MGlobeFun.icmprankfun()
##            if (cmp(attacktype,'POD')==0):
##                callfun=self.MGlobeFun.podrankfun() 

    
            
#---------------------Router Panel-----------------------
class RouterPanel(wx.Panel):
    def __init__(self, parent, id,Device):    
        wx.Panel.__init__(self, parent, id)
        self.log=Device
       
        text = wx.StaticBox(self, -1, 'Router State')
        sizer= wx.StaticBoxSizer(text,wx.HORIZONTAL)
        #sizer.Add(text, 1, wx.EXPAND)
        sizer.Add(text, 1, wx.EXPAND)         
        self.SetSizer(sizer)
        #rbutton = wx.StaticText(self,-1,label="Router Redirects New Flows",pos=(20,50))
        #icon = wx.StaticBitmap(self, bitmap=wx.Bitmap('disconnect.png'),pos=(250,50))
        #self.Bind(wx.EVT_BUTTON, self.RButton, rbutton)
        self.hlabel=wx.StaticText(self, -1, 'Router is not redirecting flow', (10,55)) 
        
        self.GlobeFun=Globe(self.log)
#        if(cmp(GlobeFun.routernew,"")!=0):
#            bmp = wx.ArtProvider.GetBitmap(wx.ART_TICK_MARK, wx.ART_OTHER,size=(16, 16))
#            titleIco = wx.StaticBitmap(self, wx.ID_ANY, bmp, pos=(200,50))
#        elif (cmp(GlobeFun.routernew,"")==0):
#            bmp = wx.ArtProvider.GetBitmap(wx.ART_CROSS_MARK, wx.ART_OTHER,size=(16, 16))
#            titleIco = wx.StaticBitmap(self, wx.ID_ANY, bmp, pos=(200,50))
        #self.rlabel = wx.StaticText(self,-1,label=u' ',pos=(0,80))     
        #self.GlobeFun.RButton()
        self.Show(True) 
    def RButton(self,event):
        #self.log=log
        if(os.path.isfile('/home/Write/routerstring.txt')==False):        
            #dlg = wx.MessageDialog(None, "The Router does nothing  ",'A Message Box', wx.OK | wx.ICON_QUESTION)
            #retCode = dlg.ShowModal()
            #dlg.Destroy()
            self.icon = wx.StaticBitmap(self, bitmap=wx.Bitmap('disconnect.png'),pos=(250,50))
            self.log.writeText('The Router does nothing','BLACK')
            return
        elif(os.path.isfile('/home/Write/routerstring.txt')==True):
            #self.log.Clear()
            self.icon = wx.StaticBitmap(self, bitmap=wx.Bitmap('connect.png'),pos=(250,50))
            frouter=open('/home/Write/routerstring.txt','r')        
            routerstrnew=frouter.readlines()
            no2=len(routerstrnew)    
            whole=routerstrnew[0:no2]
            routershow=""
            for printing in whole:
                print printing
                routershow=routershow+printing        
            print "routerstrnew %s" %routershow
            self.log.writeText( "routerstrnew %s" %routershow)
            frouter.close()
            #self.rlabel.SetLabel(routershow)     
    
            
    

#-----------------VM Panel---------------------
class VmPanel(wx.Panel):
    def __init__(self, parent, id,Device):
    
        wx.Panel.__init__(self, parent, id, size=(100, 200)) 
        self.log=Device
        #self.text = wx.StaticText(self, -1, 'VM State')
        text = wx.StaticBox(self, -1, 'VM State')
        sizer= wx.StaticBoxSizer(text,wx.HORIZONTAL)
        sizer.Add(text, 1, wx.EXPAND)         
        self.SetSizer(sizer)
        #self.text = wx.StaticText(self, -1, 'VM Parameters collected: ',pos=(20,40))
        #self.data = wx.Button(self, id=-1, label='Data', pos=(20, 40), size=(80, 35))
        #self.data.Bind(wx.EVT_BUTTON, self.dataButton,self.data)
        self.figure = wx.Button(self, id=-1, label='Figure', pos=(250, 380), size=(60, 35))
        self.figure.Bind(wx.EVT_BUTTON, self.figureButton,self.figure)  
        #label = wx.StaticText(self,-1,label="Data:",pos=(120,40))
        self.outputtext=wx.TextCtrl(self,-1,pos=(20,50),size=(280,320),style = wx.TE_MULTILINE|wx.TE_READONLY|wx.TE_RICH)
        self.outputtext.SetFont(wx.Font(11, wx.MODERN , wx.NORMAL, wx.NORMAL, False, 'Courier'))
        wx.Log_SetActiveTarget(wx.LogTextCtrl(self.outputtext))
        self.icon= wx.StaticText(self,-1,label=u'',pos=(10,390))
        self.writeText('Data of Figure','BLUE')    
        self.Show(True)  
    def writeText(self, text, color='BLACK', DL=0):
        #if DL > self.debuglevel:
        #    return
        if text[-1:] != '\n':
            text += '\n'
        self.outputtext.SetDefaultStyle(wx.TextAttr(wx.NamedColour(color)))
        self.outputtext.AppendText(text)
        
    def Clear(self):
        self.outputtext.Clear()
    def figureButton(self, event):    
        os.system("eog /home/file/test.png")   #Figure button plots parameters of current system and network utilization
    
    def dataButton(self, event):
        os.system("gedit /home/file/test.csv") # The data of current system and network utilization
        
    def OnButtonClick(self, event): #Print output message when press Click Me button.
        if(os.path.isfile('/home/Write/vmstring.txt')==False):
            #dlg = wx.MessageDialog(None, "The VM is collecting data  ",'A Message Box', wx.OK | wx.ICON_QUESTION)
            #retCode = dlg.ShowModal()
            #dlg.Destroy()
            self.icon = wx.StaticBitmap(self, bitmap=wx.Bitmap('disconnect.png'),pos=(250,120))
            self.log.writeText('The VM is collecting data','BLACK')
            return
        else:
            self.icon = wx.StaticBitmap(self, bitmap=wx.Bitmap('connect.png'),pos=(250,120))
            #self.log.Clear()
            fvm=open('/home/Write/vmstring.txt','r')
            vmstrnew=fvm.readlines()
            no2=len(vmstrnew)    
            whole=vmstrnew[0:no2]
            vmshow=""
            for printing in whole:
                print printing
                vmshow=vmshow+printing        
            print "vmstrnew %s" % vmshow
            fvm.close()
            #self.label.SetLabel(vmshow)

    def label(self):
        self.label = wx.StaticText(self,-1,label='Attack',pos=(20,120))
#------------Host Panel--------------
    

class HostPanel(wx.Panel):
    def __init__(self, parent, id,Device):    
        wx.Panel.__init__(self, parent, id)
        self.log=Device
        #self.text = wx.StaticText(self, -1, 'Host')
        text = wx.StaticBox(self, -1, 'Host')
        sizer= wx.StaticBoxSizer(text,wx.HORIZONTAL)
        sizer.Add(text, 1, wx.EXPAND)         
        self.SetSizer(sizer) 
        hbutton = wx.StaticText(self,-1,label="Host State (Before Protection):",pos=(10,40))
        #self.Bind(wx.EVT_BUTTON, self.Hostbutton, hbutton)
        lbutton = wx.StaticText(self,-1,label="Host State (After Protection):",pos=(10,90))
        #self.Bind(wx.EVT_BUTTON, self.Afterbutton, lbutton)
        #wx.StaticText(self, -1, 'Output is:', (10,50)) 
        self.hlabel = wx.StaticText(self,-1,label=u'',pos=(210,40))
	self.llabel = wx.StaticText(self,-1,label=u'',pos=(210,90))
        self.Show(True)

    def Hostbutton(self, event):
        if(os.path.isfile( '/home/Write/hoststring.txt')==False):    
            print "host false"
            #dlg = wx.MessageDialog(None, "The Host is under protected \n or implementing protected method \n wait for message...  ",'A Message Box', wx.OK | wx.ICON_QUESTION)
            #retCode = dlg.ShowModal()
            #dlg.Destroy()    
            self.icon = wx.StaticBitmap(self, bitmap=wx.Bitmap('disconnect.png'),pos=(200,50))
            self.log.writeText('The Host is under protected or implementing protected method wait for message... ','BLACK')
            
            return
        else:
            fhost=open('/home/Write/hoststring.txt','r')
            hoststrnew=fhost.readline()
            #no2=len(hoststrnew)    
            #whole=hoststrnew[0:no2]
            hostshow=""
            printing=fhost.readline()
            #for printing in whole:
            #print printing
            if(cmp(printing,"The anomaly-based IDS on Host detected the victim host(Before Protected Method implemented) is: abnormal")==0):
               self.icon = wx.StaticBitmap(self, bitmap=wx.Bitmap('disconnect.png'),pos=(200,50))
            elif(cmp(printing,"The anomaly-based IDS on Host detected the victim host(Before Protected Method implemented) is: normal")==0):
                   self.icon = wx.StaticBitmap(self, bitmap=wx.Bitmap('connect.png'),pos=(200,50))
            hostshow=hostshow+printing 
            print "hoststrnew %s" %hostshow #print host messages
            #self.hlabel.SetLabel(hostshow)
            fhost.close()
    def Afterbutton(self, event):
        if(os.path.isfile( '/home/Write/hoststring.txt')==False):    
            print "host false"
            #dlg = wx.MessageDialog(None, "The Host is under protected \n or implementing protected method \n wait for message...  ",'A Message Box', wx.OK | wx.ICON_QUESTION)
            #retCode = dlg.ShowModal()
            #dlg.Destroy()    
            self.icon = wx.StaticBitmap(self, bitmap=wx.Bitmap('disconnect.png'),pos=(200,100))
            self.log.writeText('The Host is under protected or implementing protected method wait for message... ','BLACK')
            
            return
        else:
            fhost=open('/home/Write/hoststring.txt','r')
            hoststrnew=fhost.readlines()
            no2=len(hoststrnew)    
            whole=hoststrnew[no2-1:no2]
            hostshow=""
            for printing in whole:
                print printing
                if(cmp(printing,"The anomaly-based IDS on Host detected the victim host(After Protected Method implemented) is: abnormal")==0):
                   self.icon = wx.StaticBitmap(self, bitmap=wx.Bitmap('disconnect.png'),pos=(200,100))
                elif(cmp(printing,"The anomaly-based IDS on Host detected the victim host(After Protected Method implemented) is: normal")==0):
                       self.icon = wx.StaticBitmap(self, bitmap=wx.Bitmap('connect.png'),pos=(200,100))
                hostshow=routershow+printing  
            print "hoststrnew %s" %hostshow #print host messages
            #self.hlabel.SetLabel(hostshow)
            fhost.close()
class TFPGApp(wx.App):
    def OnInit(self):
        wx.lib.colourdb.updateColourDB()
        frame = GuiFrame(None)
        frame.Show(True)
        self.SetTopWindow(frame)
        return True

app = TFPGApp(0)
app.MainLoop()
os.system("rm -rf /home/Write/*")
os.system("rm -rf /home/MWrite/*")
#app = wx.App()
#GuiFrame(None)
#app.MainLoop()

#app = TFPGApp(0)
#app.MainLoop()
#class Communicate(wx.Frame):
#    def __init__(self, parent, id, title):
#        wx.Frame.__init__(self, parent, id, title, size=(1000, 1000))
#        panel = wx.Panel(self, -1, size =wx.DefaultSize )    
#        topPanel = Controller(panel, -1)    
#        midPanel = Device(panel, -1)
#        lowPanel = Button(panel, -1)    
#        hbox = wx.BoxSizer(wx.VERTICAL)
#        hbox.Add(topPanel, 3, wx.EXPAND | wx.ALL, 2)
#        hbox.Add(midPanel, 5, wx.EXPAND| wx.ALL, 2)
#        hbox.Add(lowPanel, 1, wx.EXPAND | wx.ALL, 2)            
#        panel.SetSizer(hbox) 
#        self.Show(True)

#app = wx.App()
#Communicate(None, -1, 'widgets communicate')
#app.MainLoop()


#----------------Later Use------------
#draw figures of VM panels
#Figure=graph()  

# process data collected by sensors
#DataProcess=ProcessData() 

# Preprocessing
#PreProcess=Preprocessing() 

#disconnect host Network
#NetworkDisconnection=Disconnect()  

#Shutdown host 

#HostShutDown=ShutDown()  

# Legal Flow Filter

#LegalFlowFilter= LegalFlow()


