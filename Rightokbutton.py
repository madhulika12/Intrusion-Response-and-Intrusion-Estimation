# ---------------------------------------------------------------------
# The Graph shows current system and network resource utilization of VM 
# ------------------------------------------------------------------
from globe import *
#from main import *
import wx
import os

#Log=main()
class RightOkButton():
    def __init__(self,log):
        self.log=log
        
#    def writeText(self, text, color='BLACK', DL=0):
#        if DL > self.debuglevel:
#            return
#        if text[-1:] != '\n':
#            text += '\n'
#        self.log.SetDefaultStyle(wx.TextAttr(wx.NamedColour(color)))
#        self.log.AppendText(text)
#------------------------Cost part--------------------------------------
    def setLog(self, log):
        self.log = log
    def ok(self):
        
        if((os.path.isfile( '/home/Write/attacktype.txt')==False) or (os.path.isfile( '/home/Write/methodtype.txt')==False)):        
#            dlg = wx.MessageDialog(None, "Please Choose Attack Type,Protected Method And Values For Each Parameters Before Pressing Rank Button ",'A Message Box', wx.OK | wx.ICON_QUESTION)
#            retCode = dlg.ShowModal()
#            dlg.Destroy()
            self.log.writeText(' Please Choose Attack Type,Protected Method And Values For Each Parameters Before Pressing Rank Button','BLACK')
            return
        else:
            
            GlobeFun=Globe(self.log)
            attack=GlobeFun.Ranking()
            pmethod=GlobeFun.ProtectMethod()
            if(cmp(attack," ")==0 or(cmp(pmethod," ")==0)):
#                dlg = wx.MessageDialog(None, "Please Choose Attack Type or Protected Method And Reset The Value ",'A Message Box', wx.OK | wx.ICON_QUESTION)
#                retCode = dlg.ShowModal()
#                dlg.Destroy()
                self.log.writeText(' Please Choose Attack Type,Protected Method And Values For Each Parameters Before Pressing Rank Button','BLACK')
                return
            else:
                nfile1="/home/Write/"+attack+"_"+pmethod+"_costvalue.txt"            
                if(os.path.isfile(nfile1)==False):
#                    dlg1 = wx.MessageDialog(None, "The value of cost has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                    retCode1 = dlg1.ShowModal()
#                    dlg1.Destroy()
                    self.log.writeText("The value of cost has not been set, please set it for attack %s, method %s" % (attack,pmethod),'BLACK')
                    return
                else:
                    fcost=open(nfile1,'r')
                    tmp=fcost.readline()
                    if(cmp(tmp," ")==0):
#                            dalg = wx.MessageDialog(None, "The value of cost has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                            rretCode = dalg.ShowModal()
#                            dalg.Destroy()
                        self.log.writeText("The value of cost has not been set, please set it for attack %s, method %s" % (attack,pmethod),'BLACK')
                        return
                    else:
                        costvalue=float(tmp) # value
                        print costvalue
                        path='/home/Write/cost.txt'
                        if(os.path.isfile(path)==False):
#                            cdlg1 = wx.MessageDialog(None, "The value of cost weight has not been set, please go to the left panel and set it first" ,'A Message Box', wx.OK | wx.ICON_QUESTION)
#                            cretCode1 = cdlg1.ShowModal()
#                            cdlg1.Destroy()  
                            self.log.writeText("The value of cost weight has not been set, please go to the left panel and set it first",'BLACK')
                            return              
                        else:
                            fcostW=open(path,'r')
                            temp=fcostW.readline()
                            if(cmp(temp," ")==0):
#                                wdlg = wx.MessageDialog(None, "The value of cost weight has not been set, please go to the left panel and set it first",'A Message Box', wx.OK | wx.ICON_QUESTION)
#                                wretCode = wdlg.ShowModal()
#                                wdlg.Destroy()
                                 self.log.writeText("The value of cost has not been set, please set it for attack %s, method %s" % (attack,pmethod),'BLACK')
                                 return
                            else:
                                weight=float(temp)# weight
                                #print weight
                                costscore=GlobeFun.cScore(weight,costvalue)
                                #print "Cost Value is %s" %str(costscore)
                                npath1="/home/Write/"+attack+"_"+pmethod+"_costscore.txt"
                                fnew1=open(npath1,'w')
                                fnew1.write(str(costscore))
                                fnew1.close()
                                #print costscore
    
    
#--------------------recovery part--------------------------------------
        
            nfile2="/home/Write/"+attack+"_"+pmethod+"_recoveryvalue.txt"        
                
            if(os.path.isfile(nfile2)==False):
#                    dlg2 = wx.MessageDialog(None, "The value of recovery has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                    retCode2 = dlg2.ShowModal()
#                    dlg2.Destroy()
                    self.log.writeText("The value of recovery has not been set, please set it for attack %s, method %s" % (attack,pmethod),'BLACK')
                    return
            else:
                    frecovery=open(nfile2,'r')
                    tmp2=frecovery.readline()
                    if(cmp(tmp2," ")==0):
#                            dalg2 = wx.MessageDialog(None, "The value of recovery has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                            rretCode2 = dalg2.ShowModal()
#                            dalg2.Destroy()
                            self.log.writeText("The value of recovery has not been set, please set it for attack %s, method %s" % (attack,pmethod),'BLACK')
                            return
                    else:
                        recoveryvalue=float(tmp2) # value
                        path2='/home/Write/recovery.txt'
                        if(os.path.isfile(path2)==False):
#                            cdlg2 = wx.MessageDialog(None, "The value of recovery weight has not been set, please go to the left panel and set it first" ,'A Message Box', wx.OK | wx.ICON_QUESTION)
#                            cretCode2 = cdlg2.ShowModal()
#                            cdlg2.Destroy()         
                            self.log.writeText("The value of recovery weight has not been set, please go to the left panel and set it first",'BLACK')
                            return       
                        else:
                            frecoveryW=open(path2,'r')
                            temp2=frecoveryW.readline()
                            if(cmp(temp2," ")==0):
#                                wdlg2 = wx.MessageDialog(None, "The value of recovery weight has not been set, please go to the left panel and set it first",'A Message Box', wx.OK | wx.ICON_QUESTION)
#                                wretCode2 = wdlg2.ShowModal()
#                                wdlg2.Destroy()
                                self.log.writeText("The value of recovery weight has not been set, please go to the left panel and set it first",'BLACK')
                                return   
                            else:
                                weight2=float(temp2)# weight
                                recoveryscore=GlobeFun.cScore(weight2,recoveryvalue)
                                npath2="/home/Write/"+attack+"_"+pmethod+"_recoveryscore.txt"
                                fnew2=open(npath2,'w')
                                fnew2.write(str(recoveryscore))
                                fnew2.close()                            
                                print recoveryscore
    
#--------------------performance part--------------------------------------
        
            nfile3="/home/Write/"+attack+"_"+pmethod+"_performancevalue.txt"
            if(os.path.isfile(nfile3)==False):
#                    dlg3 = wx.MessageDialog(None, "The value of performance has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                    retCode3 = dlg3.ShowModal()
#                    dlg3.Destroy()
                    self.log.writeText("The value of performance has not been set, please set it for attack %s, method %s" % (attack,pmethod),'RED')
                    return   
            else:
                    fperformance=open(nfile3,'r')
                    tmp3=fperformance.readline()
                    if(cmp(tmp3," ")==0):
#                            dalg3 = wx.MessageDialog(None, "The value of performance has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                            rretCode3 = dalg3.ShowModal()
#                            dalg3.Destroy()
                             self.log.writeText("The value of performance has not been set, please set it for attack %s, method %s" % (attack,pmethod),'RED')
                             return 
                    else:
                        performancevalue=float(tmp3) # value
                        path3='/home/Write/performance.txt'
                        if(os.path.isfile(path3)==False):
#                            cdlg3 = wx.MessageDialog(None, "The value of performance weight has not been set, please go to the left panel and set it first" ,'A Message Box', wx.OK | wx.ICON_QUESTION)
#                            cretCode3 = cdlg3.ShowModal()
#                            cdlg3.Destroy() 
                            self.log.writeText("The value of performance weight has not been set, please go to the left panel and set it first" % (attack,pmethod),'RED')
                            return                
                        else:
                            fperformanceW=open(path3,'r')
                            temp3=fperformanceW.readline()
                            if(cmp(temp3," ")==0):
#                                wdlg3 = wx.MessageDialog(None, "The value of performance weight has not been set, please go to the left panel and set it first",'A Message Box', wx.OK | wx.ICON_QUESTION)
#                                wretCode3 = wdlg3.ShowModal()
#                                wdlg3.Destroy()
                                self.log.writeText("The value of performance weight has not been set, please go to the left panel and set it first" % (attack,pmethod),'RED')
                                return
                                
                            else:
                                weight3=float(temp3)# weight
                                performancescore=GlobeFun.cScore(weight3,performancevalue)
                                npath3="/home/Write/"+attack+"_"+pmethod+"_performancescore.txt"
                                fnew3=open(npath3,'w')
                                fnew3.write(str(performancescore))
                                fnew3.close()
                                #print costscore
                                print performancescore
    
    
#--------------------efficiency part--------------------------------------
        
            nfile4="/home/Write/"+attack+"_"+pmethod+"_efficiencyvalue.txt"
                
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
                        path4='/home/Write/efficiency.txt'
                        if(os.path.isfile(path4)==False):
#                                cdlg4 = wx.MessageDialog(None, "The value of efficiency weight has not been set, please go to the left panel and set it first" ,'A Message Box', wx.OK | wx.ICON_QUESTION)
#                                cretCode4 = cdlg4.ShowModal()
#                                cdlg4.Destroy()
                                 self.log.writeText("The value of efficiency weight has not been set, please go to the left panel and set it first",'RED')
                                 return
                  
                        else:
                                fefficiencyW=open(path4,'r')
                                temp4=fefficiencyW.readline()
                                if(cmp(temp4," ")==0):
#                                        wdlg4 = wx.MessageDialog(None, "The value of efficiency weight has not been set, please go to the left panel and set it first",'A Message Box', wx.OK | wx.ICON_QUESTION)
#                                        wretCode4 = wdlg4.ShowModal()
#                                        wdlg4.Destroy()
                                         self.log.writeText("The value of efficiency weight has not been set, please go to the left panel and set it first",'RED')
                                         return
                                else:
                                        weight4=float(temp4)# weight
                                        efficiencyscore=GlobeFun.cScore(weight4,efficiencyvalue)
                                        npath4="/home/Write/"+attack+"_"+pmethod+"_efficiencyscore.txt"
                                        fnew4=open(npath4,'w')
                                        fnew4.write(str(efficiencyscore))
                                        fnew4.close()
                                        #print costscore
                                        print efficiencyscore
    
    
#--------------------effect part--------------------------------------
        
            nfile5="/home/Write/"+attack+"_"+pmethod+"_effectvalue.txt"        
                
            if(os.path.isfile(nfile5)==False):
                dlg5 = wx.MessageDialog(None, "The value of effect has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
                retCode5 = dlg5.ShowModal()
                dlg5.Destroy()
    
            else:
                feffect=open(nfile5,'r')
                tmp5=feffect.readline()
                if(cmp(tmp5," ")==0):
#                    dalg5 = wx.MessageDialog(None, "The value of effect has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                    rretCode5 = dalg5.ShowModal()
#                    dalg5.Destroy()
                    self.log.writeText("The value of effect has not been set, please set it for attack %s, method %s" % (attack,pmethod),'RED')
                    return
                else:   
                    effectvalue=float(tmp5) # value
                    path5='/home/Write/effect.txt'
                    if(os.path.isfile(path5)==False):
#                        cdlg5 = wx.MessageDialog(None, "The value of effect weight has not been set, please go to the left panel and set it first" ,'A Message Box', wx.OK | wx.ICON_QUESTION)
#                        cretCode5 = cdlg5.ShowModal()
#                        cdlg5.Destroy() 
                        self.log.writeText("The value of effect weight has not been set, please go to the left panel and set it first",'RED')
                        return   
                                                  
                    else:
                        feffectW=open(path5,'r')
                        temp5=feffectW.readline()
                        if(cmp(temp5," ")==0):
#                            wdlg5 = wx.MessageDialog(None, "The value of effect weight has not been set, please go to the left panel and set it first",'A Message Box', wx.OK | wx.ICON_QUESTION)
#                            wretCode5 = wdlg5.ShowModal()
#                            wdlg5.Destroy()
                            self.log.writeText("The value of effect weight has not been set, please go to the left panel and set it first",'RED')
                            return 
                        else:
                            weight5=float(temp5)# weight
                            effectscore=GlobeFun.cScore(weight5,effectvalue)
                            npath5="/home/Write/"+attack+"_"+pmethod+"_effectscore.txt"
                            fnew5=open(npath5,'w')
                            fnew5.write(str(effectscore))
                            fnew5.close()
                            #print costscore
                            print effectscore
        
    
    
    
##--------------------overhead part--------------------------------------
#        
#            nfile6="/home/Write/"+attack+"_"+pmethod+"_overheadvalue.txt"
#                
#                
#            if(os.path.isfile(nfile6)==False):
##                    dlg6 = wx.MessageDialog(None, "The value of overhead has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
##                    retCode6 = dlg6.ShowModal()
##                    dlg6.Destroy()
#                    self.log.writeText("The value of overhead has not been set, please set it for attack %s, method %s" % (attack,pmethod),'RED')
#                    return 
#    
#            else:
#                    foverhead=open(nfile6,'r')
#                    tmp6=foverhead.readline()
#                    if(cmp(tmp6," ")==0):
##                        dalg6 = wx.MessageDialog(None, "The value of overhead has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
##                        rretCode6 = dalg6.ShowModal()
##                        dalg6.Destroy()
#                        self.log.writeText("The value of overhead has not been set, please set it for attack %s, method %s" % (attack,pmethod),'RED')
#                        return 
#                    else:
#    
#                        overheadvalue=float(tmp6) # value
#                        path6='/home/Write/overhead.txt'
#                        if(os.path.isfile(path6)==False):
##                            cdlg6 = wx.MessageDialog(None, "The value of overhead weight has not been set, please go to the left panel and set it first" ,'A Message Box', wx.OK | wx.ICON_QUESTION)
##                            cretCode6 = cdlg6.ShowModal()
##                            cdlg6.Destroy()    
#                            self.log.writeText("The value of effect overhead has not been set, please go to the left panel and set it first",'RED')
#                            return             
#                        else:
#                            foverheadW=open(path6,'r')
#                            temp6=foverheadW.readline()
#                            if(cmp(temp6," ")==0):
##                                wdlg6 = wx.MessageDialog(None, "The value of overhead weight has not been set, please go to the left panel and set it first",'A Message Box', wx.OK | wx.ICON_QUESTION)
##                                wretCode6 = wdlg6.ShowModal()
##                                wdlg6.Destroy()
#                                self.log.writeText("The value of Overhead weight has not been set, please go to the left panel and set it first",'RED')
#                                return 
#                            else:
#                                weight6=float(temp6)# weight
#                                overheadscore=GlobeFun.cScore(weight6,overheadvalue)
#                                npath6="/home/Write/"+attack+"_"+pmethod+"_overheadscore.txt"
#                                fnew6=open(npath6,'w')
#                                fnew6.write(str(overheadscore))
#                                fnew6.close()
#                                #print costscore
#                                print overheadscore
#    
#    
#    
#            #--------------------false part--------------------------------------
#        
#            nfile7="/home/Write/"+attack+"_"+pmethod+"_falsevalue.txt"
#                
#            if(os.path.isfile(nfile7)==False):
##                    dlg7 = wx.MessageDialog(None, "The value of false has not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
##                    retCode7 = dlg7.ShowModal()
##                    dlg7.Destroy()
#                    self.log.writeText("The value of false has not been set, please set it for attack %s, method %s" % (attack,pmethod),'RED')
#                    return 
#            else:
#                    ffalse=open(nfile7,'r')
#                    tmp7=ffalse.readline()
#                    if(cmp(tmp7," ")==0):
##                        dalg7 = wx.MessageDialog(None, "The value of falsehas not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
##                        rretCode7 = dalg7.ShowModal()
##                        dalg7.Destroy()
#                        self.log.writeText("The value of falsehas not been set, please set it for attack %s, method %s" % (attack,pmethod),'RED')
#                        return 
#                    else:
#                        falsevalue=float(tmp7) # value
#                        path7='/home/Write/false.txt'
#                        if(os.path.isfile(path7)==False):
##                            cdlg7 = wx.MessageDialog(None, "The value of falseweight has not been set, please go to the left panel and set it first" ,'A Message Box', wx.OK | wx.ICON_QUESTION)
##                            cretCode7 = cdlg7.ShowModal()
##                            cdlg7.Destroy()
#                            self.log.writeText("The value of false weight has not been set, please go to the left panel and set it first",'RED')
#                            return 
#                    
#                        else:
#                            ffalseW=open(path7,'r')
#                            temp7=ffalseW.readline()
#                            if(cmp(temp7," ")==0):
##                                wdlg7 = wx.MessageDialog(None, "The value of falseweight has not been set, please go to the left panel and set it first",'A Message Box', wx.OK | wx.ICON_QUESTION)
##                                wretCode7 = wdlg7.ShowModal()
##                                wdlg7.Destroy()
#                                self.log.writeText("The value of effect false has not been set, please go to the left panel and set it first",'RED')
#                                return 
#                            else:
#                                weight7=float(temp7)# weight
#                                falsescore=GlobeFun.cScore(weight7,falsevalue)
#                                npath7="/home/Write/"+attack+"_"+pmethod+"_falsescore.txt"
#                                fnew7=open(npath7,'w')
#                                fnew7.write(str(falsescore))
#                                fnew7.close()
#                                #print costscore
#                                print falsescore
#    
#    
#    
#    
##--------------------impact part--------------------------------------
#        
#            nfile8="/home/Write/"+attack+"_"+pmethod+"_impactvalue.txt"            
#                
#            if(os.path.isfile(nfile8)==False):
##                    dlg8 = wx.MessageDialog(None, "The value of impacthas not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
##                    retCode8 = dlg8.ShowModal()
##                    dlg8.Destroy()
#                    self.log.writeText("The value of impact has not been set, please set it for attack %s, method %s" % (attack,pmethod),'RED')
#                    return 
#            else:
#                    fimpact=open(nfile8,'r')
#                    tmp8=fimpact.readline()
#                    if(cmp(tmp8," ")==0):
##                        dalg8 = wx.MessageDialog(None, "The value of impacthas not been set, please set it for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
##                        rretCode8 = dalg8.ShowModal()
##                        dalg8.Destroy()
#                        self.log.writeText("The value of impact has not been set, please set it for attack %s, method %s" % (attack,pmethod),'RED')
#                        return 
#                    else:
#                    
#                        impactvalue=float(tmp8) # value
#                        path8='/home/Write/impact.txt'
#                        if(os.path.isfile(path8)==False):
##                                cdlg8 = wx.MessageDialog(None, "The value of impact weight has not been set, please go to the left panel and set it first" ,'A Message Box', wx.OK | wx.ICON_QUESTION)
##                                cretCode8 = cdlg8.ShowModal()
##                                cdlg8.Destroy()
#                                self.log.writeText("The value of impact weight has not been set, please go to the left panel and set it first",'RED')
#                                return 
#                        
#                        else:
#                                ffalseW=open(path8,'r')
#                                temp8=ffalseW.readline()
#                                if(cmp(temp8," ")==0):
##                                        wdlg8 = wx.MessageDialog(None, "The value of impactweight has not been set, please go to the left panel and set it first",'A Message Box', wx.OK | wx.ICON_QUESTION)
##                                        wretCode8 = wdlg8.ShowModal()
##                                        wdlg8.Destroy()
#                                        self.log.writeText("The value of impact weight has not been set, please go to the left panel and set it first",'RED')
#                                        return 
#                                else:
#                                        weight8=float(temp8)# weight
#                                        impactscore=GlobeFun.cScore(weight8,impactvalue)
#                                        npath8="/home/Write/"+attack+"_"+pmethod+"_impactscore.txt"
#                                        fnew8=open(npath8,'w')
#                                        fnew8.write(str(impactscore))
#                                        fnew8.close()
#                                        #print costscore
#                                        #print impactscore     
        
            filename="/home/Write/"+attack+"_"+pmethod
            cscore=filename+"_costscore.txt"
            rscore=filename+"_recoveryscore.txt"
            perfscore=filename+"_performancescore.txt"
            escore=filename+"_efficiencyscore.txt"
            ectscore=filename+"_effectscore.txt"
#            overscore=filename+"_overheadscore.txt"
#            falsescore=filename+"_falsescore.txt"
#            iscore=filename+"_impactscore.txt"
            bool1=os.path.isfile(cscore)
            bool2=os.path.isfile(rscore)
            bool3=os.path.isfile(perfscore)
            bool4=os.path.isfile(escore)
            bool5=os.path.isfile(ectscore)
#            bool6=os.path.isfile(overscore)
#            bool7=os.path.isfile(falsescore)
#            bool8=os.path.isfile(iscore)
            if(bool1==True and bool2==True and bool3==True and bool4==True and bool5==True): 
               #and bool6==True and bool7==True and bool8==True):
                totalscore=GlobeFun.allsum(attack,pmethod)
                toscore=str(totalscore)
#                dlgt = wx.MessageDialog(None, "The total score for attack: %s, method: %s is: %s" % (attack,pmethod,toscore),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                retCodet = dlgt.ShowModal()
#                dlgt.Destroy()
                self.log.writeText('The total score for attack: %s, method: %s is: %s' % (attack,pmethod,toscore),'Blue')
                
            else:
#                dlgall = wx.MessageDialog(None, "Please check the weights in left panel and the values in right panel, make sure every parameter gets a choice for attack %s, method %s" % (attack,pmethod),'A Message Box', wx.OK | wx.ICON_QUESTION)
#                retCodeall = dlgall.ShowModal()
#                dlgall.Destroy()
                self.log.writeText('Error:Please check the weights in left panel and the values in right panel, make sure every parameter gets a choice for attack %s, method %s' % (attack,pmethod),'RED')
