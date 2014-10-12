import wx #cross platform gui-api hai.. c,c++ mai likha hai
import wx.lib.colourdb
from multiprocessing import Process
from threading import *
import socket
import os,re,sys
import time
from AttackForecast import *

ID_STOP = wx.NewId() #newid menu stuff se related hai
ID_RUN= wx.NewId()

class GuiFrame(wx.Frame): #wx.frame - parent widget..container widget..specifies none for the parent parameter.. top in the hierarchy.. show ko call karne se ye dikhne lagega
    title = 'Forecaster Structure'
    def __init__(self, parent):
    	wx.Frame.__init__(self, parent, -1, self.title, size=(580,630)) #ye sari default hai.. parent = type = window; id = -1 int; title = name aa ja raha.. size  
    	#self.debuglevel = 1
	#self.log=log
        self.CreateStatusBar()#wx mai hai status bar banane ke liye
        self.filename   = None
        self.debuglevel = 1     #low cost debug assertions         
        Hsplitter = wx.SplitterWindow(self, -1, style=wx.SP_3D)        #2 sub window ko manage karti hai.. jo split dikh raha hai wo iski wajah se hai .. sp_3d - draws a 3d effect border and sash 
        self.FPanel =ForecastPanel(Hsplitter, -1,  self) #shayad aade ko forecast panel bana diya
        
        self.log = wx.TextCtrl(Hsplitter,-1, style = wx.TE_MULTILINE|wx.TE_READONLY|wx.TE_RICH) #multiline = allows kahi saari lines.. readonly- the text wil not be user readable.. rich - rich cntrol under win32..ignored otherwise..txtcntrol text input wagera ke liye shayad
        self.log.SetFont(wx.Font(11, wx.MODERN , wx.NORMAL, wx.NORMAL, False, 'Courier')) #modern- using a fixed pitch font, normal - weight hai ya to light ya to bold rah sakta hai.. 
        wx.Log_SetActiveTarget(wx.LogTextCtrl(self.log))
        
        self.Show(True)
        
        # add the windows to the splitter and split it.
        Hsplitter.SplitHorizontally(self.FPanel ,self.log, 300)  #100 mai srf forecast params he dikh raha tha
        self.writeText('Welcome to The Forecaster Tool','BLUE')
        self.writeText('Please select the attack(s) to be forecasted','RED') #dono print ho rahi hai
    def writeText(self, text, color='BLACK', DL=0):
        if DL > self.debuglevel:
            return
        if text[-1:] != '\n':
            text += '\n'
        self.log.SetDefaultStyle(wx.TextAttr(wx.NamedColour(color))) #text attr txt.cntrol ki text ko attributes deta hai.. ki won kaise dikhti hai and stuff.. wx.namedcolour - tum tuple bhi de doge to wo usse color mai convert kar dega
        self.log.AppendText(text)
        
    def Clear(self):
        self.log.Clear()      
        self.SetSelection(0)
    
class ForecastPanel(wx.Panel):   #wx.panel - construct n shw a generic window
    def __init__(self, parent,id,log):
        wx.Panel.__init__(self, parent, id)
        self.log=log
	self.working = 0
        #self.log.writeText('ForecastPanel','RED')
        text = wx.StaticBox(self, -1, '') #rectangle around windows draw hoti hai grouping of items dikhane ke liye..label = empty string
        sizer= wx.StaticBoxSizer(text,wx.HORIZONTAL)#staticboxsizer and normal boxsizer mai wahi antar hai ki statticboxsizer ek panel ki window bhi banata hai un sab cheezo ko ek mai group karne ke liye..horizontal = shayad horizontal expansion se related hai
        sizer.Add(text, 1, wx.EXPAND)  #sizer se subwindows bana lo..sizer.add se khali cheeze add kar lo and fr aur content add karte rahna..       sizer.Add, proportion is set to identify the scaling ratio of the children widget, and wx.EXPAND tells the children to expand to occupy the available width.
        self.SetSizer(sizer)#itne size pe ser kar do
        self.text = wx.StaticText(self, -1, '')#little box type to hold the text
        #show()
	paraList=['All','UDP', 'TCP_SYN', 'ICMP', 'POD','Host SQL Injection Attack','CPU Utilization','Memory Avaliable', 'Packet Rate'] 
	#attackList = ['UDP', 'TCP_SYN', 'ICMP', 'POD']
	forecastList=["ARIMA","Kalman Filter"]	
        #sampleList = ['0', '0.2', '0.5', '0.8', '1', '1.2','1.5','1.8','2']
        wx.StaticText(self, -1, "Forecast Attacks\n/Parameters:", (20, 40)) #displays one or more lines of read only text ..1st drop down
        
        self.choice1=wx.ComboBox(self, -1," ", (180, 40), wx.DefaultSize,paraList) #A combobox is like a combination of an edit control and a listbox. It can be displayed as static list with editable or read-only text field; or a drop-down list with text field.#jab 100 ko 500 kiye to forecast attacks ke baazu mai jo attack tha wo aur right ki taraf khisak gaya

#A combobox permits a single selection only. Combobox items are numbered from zero.
              
        #wx.StaticText(self, -1, "Attack Type:", (20, 10))
        #self.choice2=wx.ComboBox(self, -1," ", (180, 120),wx.DefaultSize,attackList)
        #wx.StaticText(self, -1, "Value:",(20, 190))
        #wx.TextCtrl(self, -1, pos=(180, 190))
	#self.choice3= wx.Button(self, id=-1, label='Submit',pos=(275, 190))
        
        wx.StaticText(self, -1, "Forecaster:", (20, 120))
        self.choice4=wx.ComboBox(self, -1,' ', (180, 120), wx.DefaultSize,forecastList)
	sampleList = ['Automatic Protection','F-Ranking','M-Ranking','Replica','Process Priority']
        wx.StaticText(self, -1, "Prevention Methods", (20, 200))
        self.prevention=wx.ComboBox(self, -1,"Choose One Protection Methods", (180, 200), wx.DefaultSize,sampleList) 
        self.Bind(wx.EVT_COMBOBOX, self.preventionfun, self.prevention)     #jaise forecast ka banaya bilkul waisa
        #wx.StaticText(self, -1, "Figure:",(20, 200))
	self.choice5= wx.Button(self,  ID_RUN ,'Submit',pos=(400, 45))#submit n stp buttons
        
	self.Stop=wx.Button(self, ID_STOP, 'Stop', pos=(400,120))   
        self.Stop.Bind (wx.EVT_BUTTON, self.OnStop, id=ID_STOP)#self.onstop is called  when the button is clicked..bind - Not only does it tell the system which kind of event we are looking for, but it also tells the system where to examine that criteria.
        self.Stop.Disable() #agar isko comment kar do to stop button dikhti he rahti hai but u canoot click on it  
	#self.choice5= wx.Button(self, id=-1, label='Estimated Values',pos=(150, 195), size=(120,30))
        #self.choice6= wx.Button(self, id=-1, label='Real Values',pos=(300, 195),size=(120,30))
        self.Bind(wx.EVT_COMBOBOX, self.selChoice1, self.choice1)    
        #self.Bind(wx.EVT_COMBOBOX, self.selChoice2, self.choice2)
        #self.Bind(wx.EVT_COMBOBOX, self.selChoice3, self.choice3)
	#self.Bind(wx.EVT_BUTTON, self.selChoice3, self.choice3)
        self.Bind(wx.EVT_COMBOBOX, self.selChoice4, self.choice4)
        print "done" #getresponse ke baad exactly print hota hai
        self.Bind(wx.EVT_BUTTON, self.selChoice5, self.choice5)
	#self.Bind(wx.EVT_BUTTON, self.selChoice6, self.choice6)
    
    def OnStop(self,event): # terminate infinite loop, if need
        """Stop Computation."""
        self.Stop.Disable()
        if self.working:
            #self.status.SetLabel('Trying to abort computation')
            self.need_abort = 1 
        self.choice5.Enable()
    def selChoice1(self, event):    
        item1 = event.GetString()        
        print "The attack needs to be forecasted is %s"%item1   # cost weight 
        fcost=open('/home/MWrite/forecastattack.txt','w') #save to file for later calculate total score for the method
        fcost.write(item1)    #tcp likha fr usse erase kar diya and pod likh diya
        fcost.close()

    def selChoice2(self, event):
        item1 = event.GetString()    
        print "Availability =", item1   
        fcost=open('/home/MWrite/efficiency.txt','w')
        fcost.write(item1)
        fcost.close() #ye kbhi execute he nahi ho raha
    
    def selChoice3(self, event):
        item1 = event.GetString()
        print "Latency=", item1   
    #return item1
        fcost=open('/home/MWrite/performance.txt','w')
        fcost.write(item1) #never executed
        fcost.close()
    
    def selChoice4(self, event):
        item1 = event.GetString()
        print "The Forecaster selected is", item1  
    #return item1
        fcost=open('/home/MWrite/forecaster.txt','w')
        fcost.write(item1) #ja raha hai
        fcost.close()
    
    def selChoice5(self, event):
	
        self.choice5.Disable() #execution is going
	self.Stop.Enable()
        ForecastFun=Forecast(self.log)	
        print "Forecaster is working.\n"  
	if((os.path.isfile( '/home/MWrite/forecastattack.txt')==False) or (os.path.isfile( '/home/MWrite/forecaster.txt')==False)):#
	     print "Please select the attacks that will be forecasted and the forecaster\n"
             self.writeText('Please select the attacks that will be forecasted and the forecaster','RED')
         
        else: 
	    if not  self.working:
            #self.status.SetLabel('Starting Computation')
                self.working = 1
                self.need_abort = 0
	    #print "try to predict\n"  
	    self.log.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'PURPLE')  #yaha pe ja raha hai
            fcost=open('/home/MWrite/forecastattack.txt','r')
            fattack=fcost.readline()
	    print fattack #ye dikh raha hai
            fmethod=open('/home/MWrite/forecaster.txt','r')
            forecaster=fmethod.readline()
	    print forecaster #ye bhi dikh raha hai.. same strategy as used with forecaster.txt
            fcost.close()
            fmethod.close()
            if(cmp(forecaster,'ARIMA')==0):
                if(cmp(fattack,'Host SQL Injection Attack')==0):
			ForecastFun.ProcessLog('SQL')
		elif(cmp(fattack,'CPU Utilization')==0):
			ForecastFun.ProcessLog('CPU')
		elif(cmp(fattack,'Memory Avaliable')==0):
			ForecastFun.ProcessLog('Mem')
		elif(cmp(fattack,'Packet Rate')==0):
			ForecastFun.ProcessLog('Packet')
				
        		ForecastFun.ProcessLog(fattack)
#usko kya karna hai bata de rahi hai			
		else:
			#ForecastFun=Forecast(self.log)			
        		ForecastFun.ProcessLog(fattack)
		#elif(cmp(fattack,'TCP')==0):
		#else:
	self.working = 0 		

    
    def preventionfun(self, event):
	item1 = event.GetString()
        print "Prevention Method is ",item1
        fcost=open('/home/MWrite/prevention.txt','w')
        fcost.write(item1) #ye kbhi exec nahi hua
        fcost.close()
	#ForecastFun=Forecast(self.log)
class ForecastApp(wx.App):
    def OnInit(self):
        wx.lib.colourdb.updateColourDB()#saare colrs ko update rakhne ke liye
        frame = GuiFrame(None)
        frame.Show(True)
        self.SetTopWindow(frame)
        return True

app = ForecastApp(0)
app.MainLoop()
#os.system("rm -rf /home/Write/*")
#os.system("rm -rf /home/MWrite/*")
