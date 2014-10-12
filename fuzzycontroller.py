#class MathController():
from decimal import *
import math

class Calculation():
    def __init__(self):
	print 'ok'
	
    def Initial(self): 
	Attack=['UDP','TCP_SYN','ICMP','POD','SQL','Exhaustion']
	Criteria=['Speed','CPU','Packet','Data','Loss','Connection','Login','Mem','Cost']
	Alternative=['IPS','Filter','TrustPlatform','Replica','Disconnection','Shutdown','KillProcess','Mod_Security']
	Location='/home/Initial/'
	#=======Initial Weights for Each Attack Each Alternative============
	for i in range(0,len(Attack)):
		for j in range (0,len(Criteria)):
			AttackName=str(Attack[i])
			CriteriaName=str(Criteria[j])
			SaveAs=Location+'Weight/'+AttackName+'_'+CriteriaName+'Weight.txt'
			FileName=AttackName+'_'+CriteriaName
			#print FileName
			FileName=open(SaveAs,'w')
			FileName.write('1')
			FileName.close()
			
	#======Initialize Value for Each Attack / Each Alternative/ Each Criteria '/home/Initial/Value/UDP_IPS_speedValue.txt'===================
	for i in range(0,len(Attack)):
		for j in range (0,len(Criteria)):
			for m in range (0,len(Alternative)):
				AttackName=str(Attack[i])
				CriteriaName=str(Criteria[j])
				AlternativeName=str(Alternative[m])
				SaveAs=Location+'Value/'+AttackName+'_'+AlternativeName+'_'+CriteriaName+'Value.txt'
				FileName=AttackName+'_'+AlternativeName+'_'+CriteriaName
				#print FileName
				FileName=open(SaveAs,'w')
				FileName.write('1')
				FileName.close()

    def FuzzyControl(self):
	 
	Attack=['UDP','TCP_SYN','ICMP','POD','SQL','Exhaustion']
	Criteria=['Speed','CPU','Packet','Data','Connection','Login','Mem','Cost']
	Alternative=['IPS','Filter','Trust','Replica','Disconnection','Shutdown','KillProcess','Mod']
	Location='/home/Initial/'
	UDP_Weight=['1','1','1','1','1','1','1','1']
	TCP_SYN_Weight=['1','1','1','1','1','1','1','0.2']
	ICMP_Weight=['1','1','1','1','1','1','1','1']
	POD_Weight=['1','1','1','1','1','1','1','1']
	SQL_Weight=['1','1','1','1','1','1','1','1']
	Exhaustion_Weight=['1','1','1','1','1','1','1','1']
	Total_Weight=[UDP_Weight,TCP_SYN_Weight,ICMP_Weight,POD_Weight,SQL_Weight,Exhaustion_Weight]
	#--------Value for UDP----------------
	UDP_IPS=[0.3,0.2,0,0,0,1,0,0.2]
	UDP_Filter=[0.3,0.2,0,1,0,1,0,0.2]
	UDP_Trust=[0.2,1,1,0.8,1,0,1,0.2]
	UDP_Replica=[0.2,1,1,0,1,1,1,0.8]
	UDP_Disconnection=[0.2,0,0,1,0.5,0,0,0.5]
	UDP_Shutdown=[0.3,0,0,1,0.5,0,0,0.8]
	UDP_Kill=[0.2,0.6,1,1,1,1,0.5,0.4]
	UDP_Mod=[0,1,1,1,1,1,1,0]
	UDPTotal=[UDP_IPS,UDP_Filter,UDP_Trust,UDP_Replica,UDP_Disconnection,UDP_Shutdown,UDP_Kill,UDP_Mod]
	#============TCP SYN=================
	TCP_SYN_IPS=[0.3,0.2,0.2,1,0.2,1,0,0.2]
	TCP_SYN_Filter=[0.3,0,0,1,0,0,0,0.2]
	TCP_SYN_Trust=[0.2,1,1,0.8,1,0,1,0.2]
	TCP_SYN_Replica=[0.2,1,1,0,1,1,1,0.8]
	TCP_SYN_Disconnection=[0.2,0,0,1,0,0,0,0.5]
	TCP_SYN_Shutdown=[0.3,0,0,1,0,0,0,0.8]
	TCP_SYN_Kill=[0.2,0.6,1,1,1,1,0.5,0.4]
	TCP_SYN_Mod=[0,0.8,0.8,0.8,0.8,1,0.8,0]
	TCP_SYNTotal=[TCP_SYN_IPS,TCP_SYN_Filter,TCP_SYN_Trust,TCP_SYN_Replica,TCP_SYN_Disconnection,TCP_SYN_Shutdown,TCP_SYN_Kill,TCP_SYN_Mod]

	#=============ICMP,POD Same as UDP================
	ICMP_IPS=[0.3,0.2,0,0,0,1,0,0.2]
	ICMP_Filter=[0.3,0.2,0,1,0,1,0,0.2]
	ICMP_Trust=[0.2,1,1,0.8,1,0,1,0.2]
	ICMP_Replica=[0.2,1,1,0,1,1,1,0.8]
	ICMP_Disconnection=[0.2,0,0,1,0.5,0,0,0.5]
	ICMP_Shutdown=[0.3,0,0,1,0.5,0,0,0.8]
	ICMP_Kill=[0.2,0.6,1,1,1,1,0.5,0.4]
	ICMP_Mod=[0,1,1,1,1,1,1,0]
	ICMPTotal=[ICMP_IPS,ICMP_Filter,ICMP_Trust,ICMP_Replica,ICMP_Disconnection,ICMP_Shutdown,ICMP_Kill,ICMP_Mod]

	POD_IPS=[0.3,0.2,0,0,0,1,0,0.2]
	POD_Filter=[0.3,0.2,0,1,0,1,0,0.2]
	POD_Trust=[0.2,1,1,0.8,1,0,1,0.2]
	POD_Replica=[0.2,1,1,0,1,1,1,0.8]
	POD_Disconnection=[0.2,0,0,1,0.5,0,0,0.5]
	POD_Shutdown=[0.3,0,0,1,0.5,0,0,0.8]
	POD_Kill=[0.2,0.6,1,1,1,1,0.5,0.4]
	POD_Mod=[0,1,1,1,1,1,1,0]
	PODTotal=[POD_IPS,POD_Filter,POD_Trust,POD_Replica,POD_Disconnection,POD_Shutdown,POD_Kill,POD_Mod]
	#========SQL Injection Attack===========
	SQL_IPS=[0.3,0.2,0.2,1,0.2,1,0,0.2]
	SQL_Filter=[0.3,0,0,1,0,0,0,0.2]
	SQL_Trust=[0.2,1,1,0.8,1,0,1,0.2]
	SQL_Replica=[0.2,1,1,0,1,1,1,0.8]
	SQL_Disconnection=[0.2,0,0,1,0.5,0,0,0.5]
	SQL_Shutdown=[0.3,0,0,1,0.5,0,0,0.8]
	SQL_Kill=[0.2,0.6,1,1,1,1,0.5,0.4]
	SQL_Mod=[0,0,1,0,0.5,0,0,0]
	SQLTotal=[SQL_IPS,SQL_Filter,SQL_Trust,SQL_Replica,SQL_Disconnection,SQL_Shutdown,SQL_Kill,SQL_Mod]
	#====Exhaustion==============
	Exhaustion_IPS=[0.3,1,1,1,1,1,1,0.2]
	Exhaustion_Filter=[0.3,1,1,1,1,1,1,0.2]
	Exhaustion_Trust=[0.2,1,1,0.8,1,0,1,0.2]
	Exhaustion_Replica=[0.2,1,1,0,1,1,1,0.8]
	Exhaustion_Disconnection=[0.2,0,0.5,1,0.5,0.5,0,0.5]
	Exhaustion_Shutdown=[0.3,0,0.5,1,0.5,0.5,0.5,0.8]
	Exhaustion_Kill=[0.2,0,1,0,1,1,0,0.4]
	Exhaustion_Mod=[0,1,1,1,1,1,1,0]
	ExhaustionTotal=[Exhaustion_IPS,Exhaustion_Filter,Exhaustion_Trust,Exhaustion_Replica,Exhaustion_Disconnection,Exhaustion_Shutdown,Exhaustion_Kill,Exhaustion_Mod]
	#=======All in one List==========
	AllTotal=[UDPTotal,TCP_SYNTotal,ICMPTotal,PODTotal,SQLTotal,ExhaustionTotal]
	#=====Set Weight for each Attack===
	for i in range(0,len(Attack)):
		AttackName=str(Attack[i])
		#WeightList=AttackName+"_Weight"
		#print WeightList
		for j in range (0,len(Criteria)):
			
			CriteriaName=str(Criteria[j])	
			
			SaveAs=Location+'Weight/'+AttackName+'_'+CriteriaName+'Weight.txt'
			FileName=AttackName+'_'+CriteriaName
			WeightValue=Total_Weight[i][j]
			#print WeightValue
			FileName=open(SaveAs,'w')
			FileName.write(WeightValue)
			FileName.close()
				
	
	#======Initialize Value for Each Attack / Each Alternative/ Each Criteria '/home/Initial/Value/UDP_IPS_speedValue.txt'===================
	AttackAlternativeValue={}
	for i in range(0,len(Attack)):
		AlternativeRank={}
		AttackName=str(Attack[i])
		for m in range (0,len(Alternative)):
			AlternativeName=str(Alternative[m])
			TotalValue=0			
			for j in range (0,len(Criteria)):
				EachValue=AllTotal[i][m][j]
				WeightValue=float(Total_Weight[i][j])  #--UDP_Speed_Weight 1
				TotalValue+=EachValue*WeightValue#--Total Value for UDP_IPS
				
					
			AlternativeRank[AlternativeName]=TotalValue	#UDP Alternative[IPS]=2.2; UDP Alternative[Filter]=X...
		
		sort=sorted(AlternativeRank.items(), key=lambda d: d[1]) 
		#print AttackName,sort
		for k in range (0,len(sort)):
                	attack=sort[k]
                	smallest=attack[0]
                	smallestscore=str(attack[1])
			smallestscore=Decimal(smallestscore).quantize(Decimal('.0001'),rounding=ROUND_UP)	
                	string=AttackName+" No. %d  : %s (%s) \n"%(k+1,smallest,smallestscore)
                	#print string	
		BestMethodScore=sort[0]
                BestMethod=BestMethodScore[0]
		#print AttackName
                AttackAlternativeValue[AttackName]=BestMethod
		#print  AttackAlternativeValue, len(AttackAlternativeValue)
	print  "Optimal Method", AttackAlternativeValue
	return  AttackAlternativeValue
							
	#UDP_IPS
	
    def MAC(self):
	 
	Attack=['UDP','TCP_SYN','ICMP','POD','SQL','Exhaustion']
	Criteria=['Speed','CPU','Packet','Data','Connection','Login','Mem','Cost']
	Alternative=['IPS','Filter','Trust','Replica','Disconnection','Shutdown','Kill','Mod']
	Location='/home/Initial/'
	UDP_Weight=['1','1','1','1','1','1','1','1','1']
	TCP_SYN_Weight=['1','1','1','1','1','1','1','1','1']
	ICMP_Weight=['1','1','1','1','1','1','1','1','1']
	POD_Weight=['1','1','1','1','1','1','1','1','1']
	SQL_Weight=['1','1','1','1','1','1','1','1','1']
	Exhaustion_Weight=['1','1','1','1','1','1','1','1','1']
	Total_Weight=[UDP_Weight,TCP_SYN_Weight,ICMP_Weight,POD_Weight,SQL_Weight,Exhaustion_Weight]
	#--------Value for UDP----------------
	UDP_IPS=   [0.3,0.2,0,0,0,1,0,0.2]
	UDP_Filter=[0.3,0.2,0,1,0,1,0,0.2]
	UDP_Trust= [0.2,1,1,0.8,1,0,1,0.2]
	UDP_Replica=[0.2,1,1,0,1,1,1,0.8]
	UDP_Disconnection=[0.2,0,0,1,0.5,0,0,0.5]
	UDP_Shutdown=[0.3,0,0,1,0.5,0,0,0.8]
	UDP_Kill=[0.2,0.6,1,1,1,1,0.5,0.4]
	UDP_Mod=[0,1,1,1,1,1,1,0]
	UDPTotal=[UDP_IPS,UDP_Filter,UDP_Trust,UDP_Replica,UDP_Disconnection,UDP_Shutdown,UDP_Kill,UDP_Mod]
	#============TCP SYN=================
	TCP_SYN_IPS=[0.3,0.2,0.2,1,0.2,1,0,0.2]
	TCP_SYN_Filter=[0.3,0,0,0.5,0,0,0,0.2]
	TCP_SYN_Trust=[0.2,1,1,0.8,1,0,1,0.2]
	TCP_SYN_Replica=[0.2,1,1,0,1,1,1,0.8]
	TCP_SYN_Disconnection=[0.2,0,0,1,0.5,0,0,0.5]
	TCP_SYN_Shutdown=[0.3,0,0,1,0.5,0,0,0.8]
	TCP_SYN_Kill=[0.2,0.6,1,1,1,1,0.5,0.4]
	TCP_SYN_Mod=[0,0.8,0.8,0.8,0.8,1,0.8,0]
	TCP_SYNTotal=[TCP_SYN_IPS,TCP_SYN_Filter,TCP_SYN_Trust,TCP_SYN_Replica,TCP_SYN_Disconnection,TCP_SYN_Shutdown,TCP_SYN_Kill,TCP_SYN_Mod]

	#=============ICMP,POD Same as UDP================
	ICMP_IPS=[0.3,0.2,0,0,0,1,0,0.2]
	ICMP_Filter=[0.3,0.2,0,1,0,1,0,0.2]
	ICMP_Trust=[0.2,1,1,0.8,1,0,1,0.2]
	ICMP_Replica=[0.2,1,1,0,1,1,1,0.8]
	ICMP_Disconnection=[0.2,0,0,1,0.5,0,0,0.5]
	ICMP_Shutdown=[0.3,0,0,1,0.5,0,0,0.8]
	ICMP_Kill=[0.2,0.6,1,1,1,1,0.5,0.4]
	ICMP_Mod=[0,1,1,1,1,1,1,0]
	ICMPTotal=[ICMP_IPS,ICMP_Filter,ICMP_Trust,ICMP_Replica,ICMP_Disconnection,ICMP_Shutdown,ICMP_Kill,ICMP_Mod]

	POD_IPS=[0.3,0.2,0,0,0,1,0,0.2]
	POD_Filter=[0.3,0.2,0,1,0,1,0,0.2]
	POD_Trust=[0.2,1,1,0.8,1,0,1,0.2]
	POD_Replica=[0.2,1,1,0,1,1,1,0.8]
	POD_Disconnection=[0.2,0,0,1,0.5,0,0,0.5]
	POD_Shutdown=[0.3,0,0,1,0.5,0,0,0.8]
	POD_Kill=[0.2,0.6,1,1,1,1,0.5,0.4]
	POD_Mod=[0,1,1,1,1,1,1,0]
	PODTotal=[POD_IPS,POD_Filter,POD_Trust,POD_Replica,POD_Disconnection,POD_Shutdown,POD_Kill,POD_Mod]
	#========SQL Injection Attack===========
	SQL_IPS=[0.3,0.2,0.2,1,0.2,1,0,0.2]
	SQL_Filter=[0.3,0,0,1,0,0,0,0.2]
	SQL_Trust=[0.2,1,1,0.8,1,0,1,0.2]
	SQL_Replica=[0.2,1,1,0,1,1,1,0.8]
	SQL_Disconnection=[0.2,0,0,1,0.5,0,0,0.5]
	SQL_Shutdown=[0.3,0,0,1,0.5,0,0,0.8]
	SQL_Kill=[0.2,0.6,1,1,1,1,0.5,0.4]
	SQL_Mod=[0,0,1,0,0.5,0,0,0]
	SQLTotal=[SQL_IPS,SQL_Filter,SQL_Trust,SQL_Replica,SQL_Disconnection,SQL_Shutdown,SQL_Kill,SQL_Mod]
	#====Exhaustion==============
	Exhaustion_IPS=[0.3,1,1,1,1,1,1,0.2]
	Exhaustion_Filter=[0.3,1,1,1,1,1,1,0.2]
	Exhaustion_Trust=[0.2,1,1,0.8,1,0,1,0.2]
	Exhaustion_Replica=[0.2,1,1,0,1,1,1,0.8]
	Exhaustion_Disconnection=[0.2,0,0.5,1,0.5,0.5,0,0.5]
	Exhaustion_Shutdown=[0.3,0,0.5,1,0.5,0.5,0.5,0.8]
	Exhaustion_Kill=[0.2,0,0,0,1,1,0,0.4]
	Exhaustion_Mod=[0,1,1,1,1,1,1,0]
	ExhaustionTotal=[Exhaustion_IPS,Exhaustion_Filter,Exhaustion_Trust,Exhaustion_Replica,Exhaustion_Disconnection,Exhaustion_Shutdown,Exhaustion_Kill,Exhaustion_Mod]
	
	#==========Criteria Function===============
	UDP_Function=['Gaussian','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape']
	TCP_Function=['Gaussian','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape']
	ICMP_Function=['Gaussian','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape']
	POD_Function=['Gaussian','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape']
	SQL_Function=['Gaussian','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape']
	Exhaustion_Function=['Gaussian','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape','V-Shape']
	
	CriteriaFunctionTotal=[UDP_Function,TCP_Function,ICMP_Function,POD_Function,SQL_Function,Exhaustion_Function]
	#======TCP_SYN======
	

	#=======All in one List==========
	AllTotal=[UDPTotal,TCP_SYNTotal,ICMPTotal,PODTotal,SQLTotal,ExhaustionTotal]
	#AllFunctionTotal=[UDPFunctionTotal,TCP_SYNFunctionTotal,ICMPFunctionTotal,PODFunctionTotal,SQLFunctionTotal,ExhaustionFunctionTotal]
	#print AllFunctionTotal
	AttackAlternativeValue={}
	for i in range(0,len(Attack)):	#len(Attack)
		AttackPair=[]
		PairFunctionList=[]
		AttackName=Attack[i]
		
		for j in range (0,len(Criteria)):#len(Criteria)
			
			functionValue=CriteriaFunctionTotal[i][j]
			EvaluationList=[]  #g_i(a) e.g.g_Speed(IPS), g_Speed(Filter)
			for m in range (0,len(Alternative)):			
				CriteriaValue=AllTotal[i][m][j]
				CriteriaValue=Decimal(str(CriteriaValue)).quantize(Decimal('.0001'),rounding=ROUND_UP)
				EvaluationList.append(CriteriaValue)
			#print "Evaluation", EvaluationList #UDP/TCP/... \SPeed/PacketRateRecorvery...
			CriteriaPair=[[0 for x in xrange(len(EvaluationList))] for x in xrange(len(EvaluationList))]	
			for k in range (0,len(EvaluationList)):
            			for n in range (0, len(EvaluationList)):
                			if (k==n):
                    				CriteriaPair[k][n]='NaN'
                			else:
                    				subtraction=float(EvaluationList[n])-float(EvaluationList[k])
						
                    				CriteriaPair[k][n]=subtraction #style[0,1,-1...]
			#print 	CriteriaPair
			#file1=open('/home/MTest/3.txt','a+')
			#file1.write(Attack[i]+'\n'+str(CriteriaPair))
			#file1.close()
			if(functionValue=="Usual"):
						UsualList=self.Usual(CriteriaPair)
						PairFunctionList.append(UsualList)
			elif(functionValue=="Quasi"):
						QuasiList=self.Quasi(CriteriaPair)
						PairFunctionList.append(QuasiList)
			elif(functionValue=="V-Shape"):
						VShapeList=self.VShape(CriteriaPair)
						PairFunctionList.append(VShapeList)
			elif(functionValue=="Level"):
						LevelList=self.Level(CriteriaPair)
						PairFunctionList.append(LevelList)
			elif(functionValue=="U-Shape"):
						UShapeList=self.UShape(CriteriaPair)
						PairFunctionList.append(UShapeList)
			elif(functionValue=="Gaussian"):
						GaussianList=self.Gaussian(CriteriaPair)
						PairFunctionList.append(GaussianList)
			#print 	PairFunctionList
		#print Attack[i],PairFunctionList
	        #file1=open('/home/MTest/3.txt','a+')
		#file1.write(Attack[i]+'\n'+str(CriteriaPair))

		#print Attack[i],PairFunctionList
	        #file2=open('/home/MTest/2.txt','a+')
		#file2.write(Attack[i]+'\n'+str(PairFunctionList))
		#for list1 in range (0, len(PairFunctionList)):
		#     for list2 in range (0, len(PairFunctionList[0])):	
		#	file1.write(str(PairFunctionList[list1][list2]))
		#     file1.write('\n')
		#file2.write('\n'+'\n')
		#file2.close()
	
		SumWeight=0
		for weightValue in Total_Weight[i]:
			SumWeight=SumWeight+float(weightValue)
		#print "Sum Weight is", SumWeight	
    		PairLen=len(PairFunctionList)
		#print "PairLen", PairLen
		row=len(PairFunctionList[0])
		column=len(PairFunctionList[0][0])
		PreferenceMatrix=[[0 for x in range(column)] for x in range(row)]
		for u in range (0,row):
	    		for v in range (0, column):
				AddValue=0
				for w in range (0, PairLen):
                    			PairValue=PairFunctionList[w]
            	    			if (PairValue[u][v]=='NaN'):
                   				AddValue='NaN'
						PreferenceMatrix[u][v]='NaN'
            	    			else:
                	#print AddValue

                				AddValue=AddValue+PairValue[u][v]*float(Total_Weight[i][w])
                    	#print ", ", AddValue
                		PreferenceMatrix[u][v]=AddValue
		
        			if(PreferenceMatrix[u][v]!='NaN'):
            				PreferenceMatrix[u][v]=PreferenceMatrix[u][v]/float(SumWeight)
		#print PreferenceMatrix
		file2=open('/home/MTest/pre.txt','a+')
		file2.write(Attack[i]+'\n'+str(PreferenceMatrix))
		file2.close()
		Incoming=[]
		Outgoing=[]
		for a in range (0,row):
	    		ValueTmp=0
	    		TmpValue=0
	    		for b in range (0, column):
				if(PreferenceMatrix[a][b]!='NaN'):
            				ValueTmp=ValueTmp+PreferenceMatrix[a][b]
				if(PreferenceMatrix[a][b]!='NaN'):
            				TmpValue=TmpValue+PreferenceMatrix[b][a]
            		Incoming.append(float(ValueTmp)/(column-1))
	    		Outgoing.append(float(TmpValue)/(row-1))
		print "Incoming: "
		print Incoming
		print "Outgoing: "
		print Outgoing
		FinalValue=0
		FinalList=[]
		for z in range (0, row):
			FinalValue=Incoming[z]-Outgoing[z]  #Incoming-Outgoing phi=phi(+)-phi(-)
			FinalList.append(FinalValue)
	#print "Final Result is: ", FinalList
		SortedDic={}
		#for m in range (0,len(Alternative)):
		for l in range (0, len(Alternative)):
			SortedDic[Alternative[l]]=FinalList[l]
		#print "Dic is ", SortedDic
		sort=sorted(SortedDic.items(), key=lambda d: d[1])
		
		for k in range (0,len(sort)):
                	attack=sort[len(sort)-k-1]
                	smallest=attack[0]
                	smallestscore=str(attack[1])
			#smallestscore=Decimal(smallestscore).quantize(Decimal('.0001'),rounding=ROUND_UP)	
                	string=AttackName+" No. %d  : %s (%s) \n"%(k+1,smallest,smallestscore)
                	print string	
		BestMethodScore=sort[len(sort)-1]
                BestMethod=BestMethodScore[0]
		#print AttackName
                AttackAlternativeValue[AttackName]=BestMethod
		#print  AttackAlternativeValue, len(AttackAlternativeValue)
	#print  "Optimal Method", AttackAlternativeValue
	return  AttackAlternativeValue
    def Usual(self,CriteriaList):
	
	row=len(CriteriaList)
	column=len(CriteriaList[0])
	functionList=[[0 for x in xrange(column)] for x in xrange(row)]
	for i in range (0,row):
	    for j in range (0,column):
	        if(CriteriaList[i][j]=='NaN'):
		   functionList[i][j]='NaN'
		elif(CriteriaList[i][j]>0):
		   functionList[i][j]=1
		elif(CriteriaList[i][j]<=0):
		   functionList[i][j]=0
	
	return functionList
    def Quasi(self,CriteriaList):
	
	row=len(CriteriaList)
	column=len(CriteriaList[0])
	functionList=[[0 for x in xrange(column)] for x in xrange(row)]
	for i in range (0,row):
	    for j in range (0,column):
	        if(CriteriaList[i][j]=='NaN'):
		   functionList[i][j]='NaN'
		elif(CriteriaList[i][j]>0.8):
		   functionList[i][j]=1
		elif(CriteriaList[i][j]<=0.8) :
		   functionList[i][j]=0
	return functionList
    def VShape(self,CriteriaList):
	
	row=len(CriteriaList)
	column=len(CriteriaList[0])
	functionList=[[0 for x in xrange(column)] for x in xrange(row)]
	for i in range (0,row):
	    for j in range (0,column):
	        if(CriteriaList[i][j]=='NaN'):
		   functionList[i][j]='NaN'
		elif(CriteriaList[i][j]>0.8):
		   functionList[i][j]=1
		elif((CriteriaList[i][j]<=0.8) and (CriteriaList[i][j]>0)):
		   functionList[i][j]=CriteriaList[i][j]/0.8
		else:
		   functionList[i][j]=0
	#print "VShape fun "
	#print functionList
	#print "--------------"
	return functionList
    def Level(self,CriteriaList):
	
	row=len(CriteriaList)
	column=len(CriteriaList[0])
	functionList=[[0 for x in xrange(column)] for x in xrange(row)]
	for i in range (0,row):
	    for j in range (0,column):
	        if(CriteriaList[i][j]=='NaN'):
		   functionList[i][j]='NaN'
		elif(CriteriaList[i][j]>0.8):
		   functionList[i][j]=1
		elif((CriteriaList[i][j]<=0.8) and (CriteriaList[i][j]>0.5)):
		   functionList[i][j]=0.5
		elif(CriteriaList[i][j]<=0.5):
		   functionList[i][j]=0
	return functionList

    def UShape(self,CriteriaList):
	
	row=len(CriteriaList)
	column=len(CriteriaList[0])
	functionList=[[0 for x in xrange(column)] for x in xrange(row)]
	for i in range (0,row):
	    for j in range (0,column):
	        if(CriteriaList[i][j]=='NaN'):
		   functionList[i][j]='NaN'
		elif(CriteriaList[i][j]>0.8):
		   functionList[i][j]=1
		elif((CriteriaList[i][j]<=0.8) or (CriteriaList[i][j]>0.5)):
		   functionList[i][j]=(CriteriaList[i][j]-0.5)/(0.8-0.5)
    		elif(CriteriaList[i][j]<=0.5):
		   functionList[i][j]=0

	return functionList
    def Gaussian(self,CriteriaList):
	
	row=len(CriteriaList)
	column=len(CriteriaList[0])
	functionList=[[0 for x in xrange(column)] for x in xrange(row)]
	for i in range (0,row):
	    for j in range (0,column):
	        if(CriteriaList[i][j]=='NaN'):
		   functionList[i][j]='NaN'
		elif(CriteriaList[i][j]<=0):
		   functionList[i][j]=0
		else:
		   d=CriteriaList[i][j]
		   #print "d is %f"%d
		   functionList[i][j]=1-math.exp(-math.pow(d,2)/(2*math.pow(0.1,2)))	
	#print "Gau fun "
	#print functionList
	#print "--------------"
	return functionList




	
        #Listlen=len(SpeedList)
#FuzzyControl()
#print "==========================================="
#MAC()
