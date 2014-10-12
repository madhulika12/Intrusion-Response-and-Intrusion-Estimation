# ---------------------------------------------------------------------
# The Graph shows current system and network resource utilization of VM 
# ------------------------------------------------------------------
from globe import *
#from main import *
from mcontroller import *
import wx
import os

#Log=main()
class MRightOkButton():
    def __init__(self,log):
        self.log=log
        
#    def writeText(self, text, color='BLACK', DL=0):
#        if DL > self.debuglevel:
#            return
#        if text[-1:] != '\n':
#            text += '\n'
#        self.log.SetDefaultStyle(wx.TextAttr(wx.NamedColour(color)))
#        self.log.AppendText(text)
#------------------------Legitimate Data Transmission Recovery part--------------------------------------
    def setLog(self, log):
        self.log = log
    def ok(self):
        
        if((os.path.isfile( '/home/MWrite/Mattacktype.txt')==False) or (os.path.isfile( '/home/MWrite/Mmethodtype.txt')==False)):        
#            dlg = wx.MessageDialog(None, "Please Choose Attack Type,Protected Method And Values For Each Parameters Before Pressing Rank Button ",'A Message Box', wx.OK | wx.ICON_QUESTION)
#            retCode = dlg.ShowModal()
#            dlg.Destroy()
            self.log.writeText(' Please Choose Attack Type, Alternative And Values For Each Parameters Before Pressing Rank Button','BLACK')
            return
        else:
            
            GlobeFun=MGlobe(self.log)
            attack=GlobeFun.Ranking()
	    #print "GolbeFun_MRight"
	    #print attack
            pmethod=GlobeFun.ProtectMethod()
            if(cmp(attack," ")==0 or(cmp(pmethod," ")==0)):
#                dlg = wx.MessageDialog(None, "Please Choose Attack Type or Protected Method And Reset The Value ",'A Message Box', wx.OK | wx.ICON_QUESTION)
#                retCode = dlg.ShowModal()
#                dlg.Destroy()
                self.log.writeText(' Please Choose Attack Type, Alternative And Values For Each Parameters Before Pressing Rank Button','BLACK')
                return
            else:
                nfile1="/home/MWrite/"+attack+"_"+pmethod+"_Mdata.txt"            
                if(os.path.isfile(nfile1)==False):
#                    dlg1 = wx.MessageDialog(None, "The value of cost has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                    retCode1 = dlg1.ShowModal()
#                    dlg1.Destroy()
                    self.log.writeText("The value of Legitimate Data Transmission Recovery has not been set, please set it for attack %s, method %s" % (attack,pmethod),'BLACK')
                    return
                else:
                    fcost=open(nfile1,'r')
                    tmp=fcost.readline()
                    if(cmp(tmp," ")==0):
#                            dalg = wx.MessageDialog(None, "The value of cost has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                            rretCode = dalg.ShowModal()
#                            dalg.Destroy()
                        self.log.writeText("The value of Legitimate Data Transmission Recovery has not been set, please set it for attack %s, method %s" % (attack,pmethod),'BLACK')
                        return
                    else:
                        costvalue=float(tmp) # value
                        print costvalue
                        path='/home/MWrite/'+attack+'_DataWeight.txt'
                        if(os.path.isfile(path)==False):
#                            cdlg1 = wx.MessageDialog(None, "The value of cost weight has not been set, please go to the left panel and set it first" ,'A Message Box', wx.OK | wx.ICON_QUESTION)
#                            cretCode1 = cdlg1.ShowModal()
#                            cdlg1.Destroy()  
                            self.log.writeText("The value of Legitimate Data Transmission Recovery weight has not been set, please set it first",'BLACK')
                            return              
                        else:
                            fcostW=open(path,'r')
                            temp=fcostW.readline()
                            if(cmp(temp," ")==0):
#                                wdlg = wx.MessageDialog(None, "The value of cost weight has not been set, please go to the left panel and set it first",'A Message Box', wx.OK | wx.ICON_QUESTION)
#                                wretCode = wdlg.ShowModal()
#                                wdlg.Destroy()
                                 self.log.writeText("The value of Legitimate Data Transmission Recovery Weight has not been set, please set it for attack %s, method %s" % (attack,pmethod),'BLACK')
                                 return
			    
                            ##else:
##                                weight=float(temp)# weight
##                                #print weight
##                                #costscore=GlobeFun.cScore(weight,costvalue)
##                                #print "Cost Value is %s" %str(costscore)
##                                npath1="/home/MWrite/"+attack+"_"+pmethod+"_Datascore.txt"
##                                fnew1=open(npath1,'w')
##                                fnew1.write(str(costscore))
##                                fnew1.close()
    
    
#--------------------Execution Speed part--------------------------------------
        
            nfile2="/home/MWrite/"+attack+"_"+pmethod+"_Mspeed.txt"        
                
            if(os.path.isfile(nfile2)==False):
#                    dlg2 = wx.MessageDialog(None, "The value of recovery has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                    retCode2 = dlg2.ShowModal()
#                    dlg2.Destroy()
                    self.log.writeText("The value of Execution Speed has not been set, please set it for attack %s, method %s" % (attack,pmethod),'BLACK')
                    return
            else:
                    frecovery=open(nfile2,'r')
                    tmp2=frecovery.readline()
                    if(cmp(tmp2," ")==0):
#                            dalg2 = wx.MessageDialog(None, "The value of recovery has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                            rretCode2 = dalg2.ShowModal()
#                            dalg2.Destroy()
                            self.log.writeText("The value of Execution Speed has not been set, please set it for attack %s, method %s" % (attack,pmethod),'BLACK')
                            return
                    else:
                        recoveryvalue=float(tmp2) # value
                        path2='/home/MWrite/'+attack+'_SpeedWeight.txt'
                        if(os.path.isfile(path2)==False):
#                            cdlg2 = wx.MessageDialog(None, "The value of recovery weight has not been set, please go to the left panel and set it first" ,'A Message Box', wx.OK | wx.ICON_QUESTION)
#                            cretCode2 = cdlg2.ShowModal()
#                            cdlg2.Destroy()         
                            self.log.writeText("The value of Execution Speed weight has not been set, please set it first",'BLACK')
                            return       
                        else:
                            frecoveryW=open(path2,'r')
                            temp2=frecoveryW.readline()
                            if(cmp(temp2," ")==0):
#                                wdlg2 = wx.MessageDialog(None, "The value of recovery weight has not been set, please go to the left panel and set it first",'A Message Box', wx.OK | wx.ICON_QUESTION)
#                                wretCode2 = wdlg2.ShowModal()
#                                wdlg2.Destroy()
                                self.log.writeText("The value of Execution Speed weight has not been set, please set it first",'BLACK')
                                return   
                            ##else:
##                                weight2=float(temp2)# weight
##                                #recoveryscore=GlobeFun.cScore(weight2,recoveryvalue)
##                                npath2="/home/MWrite/"+attack+"_"+pmethod+"_Speedscore.txt"
##                                fnew2=open(npath2,'w')
##                                fnew2.write(str(recoveryscore))
##                                fnew2.close()                            
##                                print recoveryscore
#--------------------Packet Rate Recovery part--------------------------------------
        
            nfile3="/home/MWrite/"+attack+"_"+pmethod+"_Mpacket.txt"
            if(os.path.isfile(nfile3)==False):
#                    dlg3 = wx.MessageDialog(None, "The value of performance has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                    retCode3 = dlg3.ShowModal()
#                    dlg3.Destroy()
                    self.log.writeText("The value of Packet Rate Recovery has not been set, please set it for attack %s, method %s" % (attack,pmethod),'RED')
                    return   
            else:
                    fperformance=open(nfile3,'r')
                    tmp3=fperformance.readline()
                    if(cmp(tmp3," ")==0):
#                            dalg3 = wx.MessageDialog(None, "The value of performance has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                            rretCode3 = dalg3.ShowModal()
#                            dalg3.Destroy()
                             self.log.writeText("The value of Packet Rate Recovery has not been set, please set it for attack %s, method %s" % (attack,pmethod),'RED')
                             return 
                    else:
                        performancevalue=float(tmp3) # value
                        path3='/home/MWrite/'+attack+'_PacketWeight.txt'
                        if(os.path.isfile(path3)==False):
#                            cdlg3 = wx.MessageDialog(None, "The value of performance weight has not been set, please go to the left panel and set it first" ,'A Message Box', wx.OK | wx.ICON_QUESTION)
#                            cretCode3 = cdlg3.ShowModal()
#                            cdlg3.Destroy() 
                            self.log.writeText("The value of Packet Rate Recovery weight has not been set, please set it first" % (attack,pmethod),'RED')
                            return                
                        else:
                            fperformanceW=open(path3,'r')
                            temp3=fperformanceW.readline()
                            if(cmp(temp3," ")==0):
#                                wdlg3 = wx.MessageDialog(None, "The value of performance weight has not been set, please go to the left panel and set it first",'A Message Box', wx.OK | wx.ICON_QUESTION)
#                                wretCode3 = wdlg3.ShowModal()
#                                wdlg3.Destroy()
                                self.log.writeText("The value of Packet Rate Recovery weight has not been set, please set it first" % (attack,pmethod),'RED')
                                return
                                
                            ##else:
##                                weight3=float(temp3)# weight
##                                #performancescore=GlobeFun.cScore(weight3,performancevalue)
##                                npath3="/home/MWrite/"+attack+"_"+pmethod+"_Packetscore.txt"
##                                fnew3=open(npath3,'w')
##                                fnew3.write(str(performancescore))
##                                fnew3.close()
##                                #print costscore
##                                print performancescore

    
    
#--------------------CPU Recovery part--------------------------------------
        
            nfile4="/home/MWrite/"+attack+"_"+pmethod+"_Mcpu.txt"
                
            if(os.path.isfile(nfile4)==False):
#                    dlg4 = wx.MessageDialog(None, "The value of efficiency has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                    retCode4 = dlg4.ShowModal()
#                    dlg4.Destroy()
                    self.log.writeText("The value of efficiency has not been set, please set it for attack %s, method %s" % (attack,pmethod),'RED')
                    return
                    
            else:
                    fefficiency=open(nfile4,'r')
                    tmp4=fefficiency.readline()
                    if(cmp(tmp4," ")==0):
#                        dalg4 = wx.MessageDialog(None, "The value of efficiency has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                        rretCode4 = dalg4.ShowModal()
#                        dalg4.Destroy()
                        self.log.writeText("The value of efficiency has not been set, please set it for attack %s, method %s" % (attack,pmethod),'RED')
                        return
                    else:  
                        efficiencyvalue=float(tmp4) # value
                        path4='/home/MWrite/'+attack+'_CPUWeight.txt'
                        if(os.path.isfile(path4)==False):
#                                cdlg4 = wx.MessageDialog(None, "The value of efficiency weight has not been set, please go to the left panel and set it first" ,'A Message Box', wx.OK | wx.ICON_QUESTION)
#                                cretCode4 = cdlg4.ShowModal()
#                                cdlg4.Destroy()
                                 self.log.writeText("The value of CPU Utilization Recovery weight has not been set, please set it first",'RED')
                                 return
                  
                        else:
                                fefficiencyW=open(path4,'r')
                                temp4=fefficiencyW.readline()
                                if(cmp(temp4," ")==0):
#                                        wdlg4 = wx.MessageDialog(None, "The value of efficiency weight has not been set, please go to the left panel and set it first",'A Message Box', wx.OK | wx.ICON_QUESTION)
#                                        wretCode4 = wdlg4.ShowModal()
#                                        wdlg4.Destroy()
                                         self.log.writeText("The value of CPU Utilization Recovery weight has not been set, please set it first",'RED')
                                         return
                                ##else:
##                                        weight4=float(temp4)# weight
##                                        #efficiencyscore=GlobeFun.cScore(weight4,efficiencyvalue)
##                                        npath4="/home/MWrite/"+attack+"_"+pmethod+"_CPUscore.txt"
##                                        fnew4=open(npath4,'w')
##                                        fnew4.write(str(efficiencyscore))
##                                        fnew4.close()
##                                        #print costscore
##                                        print efficiencyscore
##    

    
#--------------------Connection Rate Recovery part--------------------------------------
        
            nfile5="/home/MWrite/"+attack+"_"+pmethod+"_Mconnection.txt"        
                
            if(os.path.isfile(nfile5)==False):
                dlg5 = wx.MessageDialog(None, "The value of Connection Rate Recovery has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
                retCode5 = dlg5.ShowModal()
                dlg5.Destroy()
    
            else:
                feffect=open(nfile5,'r')
                tmp5=feffect.readline()
                if(cmp(tmp5," ")==0):
#                    dalg5 = wx.MessageDialog(None, "The value of effect has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                    rretCode5 = dalg5.ShowModal()
#                    dalg5.Destroy()
                    self.log.writeText("The value of Connection Rate Recovery has not been set, please set it for attack %s, method %s" % (attack,pmethod),'RED')
                    return
                else:   
                    effectvalue=float(tmp5) # value
                    path5='/home/MWrite/'+attack+'_ConnectionWeight.txt'
                    if(os.path.isfile(path5)==False):
#                        cdlg5 = wx.MessageDialog(None, "The value of effect weight has not been set, please go to the left panel and set it first" ,'A Message Box', wx.OK | wx.ICON_QUESTION)
#                        cretCode5 = cdlg5.ShowModal()
#                        cdlg5.Destroy() 
                        self.log.writeText("The value of Connection Rate Recovery weight has not been set, please set it first",'RED')
                        return   
                                                  
                    else:
                        feffectW=open(path5,'r')
                        temp5=feffectW.readline()
                        if(cmp(temp5," ")==0):
#                            wdlg5 = wx.MessageDialog(None, "The value of effect weight has not been set, please go to the left panel and set it first",'A Message Box', wx.OK | wx.ICON_QUESTION)
#                            wretCode5 = wdlg5.ShowModal()
#                            wdlg5.Destroy()
                            self.log.writeText("The value of Connection Rate Recovery weight has not been set, please  set it first",'RED')
                            return 
                        ##else:
##                            weight5=float(temp5)# weight
##                            #effectscore=GlobeFun.cScore(weight5,effectvalue)
##                            npath5="/home/MWrite/"+attack+"_"+pmethod+"_Connectionscore.txt"
##                            fnew5=open(npath5,'w')
##                            fnew5.write(str(effectscore))
##                            fnew5.close()
##                            #print costscore
##                            print effectscore

        
#--------------------Legitimate Packet Loss Rate part--------------------------------------
        
            nfile6="/home/MWrite/"+attack+"_"+pmethod+"_Mlegitimate.txt"        
                
            if(os.path.isfile(nfile6)==False):
                dlg6 = wx.MessageDialog(None, "The value of Legitimate Packet Loss Rate has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
                retCode6 = dlg6.ShowModal()
                dlg6.Destroy()
    
            else:
                floss=open(nfile6,'r')
                tmp6=floss.readline()
                if(cmp(tmp6," ")==0):
#                    dalg5 = wx.MessageDialog(None, "The value of effect has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                    rretCode5 = dalg5.ShowModal()
#                    dalg5.Destroy()
                    self.log.writeText("The value of Legitimate Packet Loss Rate has not been set, please set it for attack %s, method %s" % (attack,pmethod),'RED')
                    return
                else:   
                    lossvalue=float(tmp6) # value
                    path6='/home/MWrite/'+attack+'_LossWeight.txt'
                    if(os.path.isfile(path6)==False):
#                        cdlg5 = wx.MessageDialog(None, "The value of effect weight has not been set, please go to the left panel and set it first" ,'A Message Box', wx.OK | wx.ICON_QUESTION)
#                        cretCode5 = cdlg5.ShowModal()
#                        cdlg5.Destroy() 
                        self.log.writeText("The value of Legitimate Packet Loss Rate weight has not been set, please set it first",'RED')
                        return   
                                                  
                    else:
                        flossW=open(path6,'r')
                        temp6=flossW.readline()
                        if(cmp(temp6," ")==0):
#                            wdlg5 = wx.MessageDialog(None, "The value of effect weight has not been set, please go to the left panel and set it first",'A Message Box', wx.OK | wx.ICON_QUESTION)
#                            wretCode5 = wdlg5.ShowModal()
#                            wdlg5.Destroy()
                            self.log.writeText("The value of Legitimate Packet Loss Rate weight has not been set, please set it first",'RED')
                            return 
                        ##else:
##                            weight6=float(temp6)# weight
##                            #losscore=GlobeFun.cScore(weight6,lossvalue)
##                            npath6="/home/MWrite/"+attack+"_"+pmethod+"_Losscore.txt"
##                            fnew6=open(npath6,'w')
##                            fnew6.write(str(losscore))
##                            fnew6.close()
##                            #print costscore
##                            print losscore   
    
    #--------------------Failure Login Rate Recovery part--------------------------------------
        
            nfile7="/home/MWrite/"+attack+"_"+pmethod+"_Mfalsevalue.txt"        
                
            if(os.path.isfile(nfile7)==False):
                dlg7 = wx.MessageDialog(None, "The value of Failure Login Rate Recovery has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
                retCode7 = dlg7.ShowModal()
                dlg7.Destroy()
    
            else:
                flogin=open(nfile7,'r')
                tmp7=flogin.readline()
                if(cmp(tmp7," ")==0):
#                    dalg5 = wx.MessageDialog(None, "The value of effect has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                    rretCode5 = dalg5.ShowModal()
#                    dalg5.Destroy()
                    self.log.writeText("The value of Failure Login Rate Recovery has not been set, please set it for attack %s, method %s" % (attack,pmethod),'RED')
                    return
                else:   
                    loginvalue=float(tmp7) # value
                    path7='/home/MWrite/'+attack+'_LoginWeight.txt'
                    if(os.path.isfile(path7)==False):
#                        cdlg5 = wx.MessageDialog(None, "The value of effect weight has not been set, please go to the left panel and set it first" ,'A Message Box', wx.OK | wx.ICON_QUESTION)
#                        cretCode5 = cdlg5.ShowModal()
#                        cdlg5.Destroy() 
                        self.log.writeText("The value of Failure Login Rate Recovery weight has not been set, please set it first",'RED')
                        return   
                                                  
                    else:
                        floginW=open(path7,'r')
                        temp7=floginW.readline()
                        if(cmp(temp7," ")==0):

                            self.log.writeText("The value of Failure Login Rate Recovery weight has not been set, please set it first",'RED')
                            return 
            		
	    GlobeFun.Multicriteria(attack)
            
  
            
