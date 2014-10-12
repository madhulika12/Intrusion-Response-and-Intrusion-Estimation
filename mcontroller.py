import wx
import os,time
from threading import *
import socket
import os,re,sys
import time
import binascii
import signal
import pexpect
from shutdownhost import *
from legalflow import *
from disconnection import *
import thread
import datetime
from figure import *
import math
from processdata import *

from preprocessing import *

from disconnection import *

from shutdownhost import *

from legalflow import *
ip='3.0.0.1' #remote access router which ip is 3.0.0.1 for dynamically analyzing             
ip2='1.0.0.1'#attack packets and redirecting illegal flow from router to protected VM before forwarding packets to host 
user='root'  # router username password
passwd='000000'
udpranking=["",""]
tcpranking=["",""]
icmpranking=["",""]
podranking=["",""]

class MGlobe():
    routernew=""  
    def __init__(self,log):          
            self.log=log 
            self.udpbest=""
            self.tcpbest="" 
            
        
    def setLog(self, log):
        self.log = log
        
    def Initial(self):
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

        #-------Initial Weight Values for each attack/process-----
        AttackList=['UDP','TCP_SYN','ICMP','POD','SQL','Exhaustion']
        MethodList=['SpeedWeight','CPUWeight','PacketWeight','DataWeight','ConnectionWeight','LoginWeight','MemWeight','CostWeight']
        Directory='/home/MWrite/'
        for i in range (0, len(AttackList)):
            for j in range (0, len(MethodList)):
                TmpString=str(AttackList[i])+'_'+str(MethodList[j])
                #print TmpString
                FileString=Directory+TmpString+'.txt'
                TmpString=open(FileString,'w')
                TmpString.write('1')
                TmpString.close()

                
                #--------------Initial Criteria Function------------
        FileList=['Speed_MCriteria','CPU_MCriteria','Packet_MCriteria','Data_MCriteria','Connection_MCriteria','Login_MCriteria','Mem_MCriteria','Cost_MCriteria']
        Directory='/home/MTest/'
        for i in range (0, len(AttackList)):
            for j in range (0, len(FileList)):
                TmpString=str(AttackList[i])+'_'+str(FileList[j])
                print TmpString
                FileString=Directory+TmpString+'.txt'
                TmpString=open(FileString,'w')
                if(cmp(FileList[j],'Speed_MCriteria')==0):
                        TmpString.write('Gaussian')
                else:
                        TmpString.write('V-Shape')
                TmpString.close()

        
	

	#---------UDP IPS----------
	file_UDP_IPS_recovery=open('/home/MWrite/UDP_IPS_Mspeed.txt','w')
        file_UDP_IPS_availability=open('/home/MWrite/UDP_IPS_Mcpu.txt','w')
        file_UDP_IPS_latency=open('/home/MWrite/UDP_IPS_Mpacket.txt','w')
        file_UDP_IPS_mem=open('/home/MWrite/UDP_IPS_Mmem.txt','w')
        file_UDP_IPS_leg=open('/home/MWrite/UDP_IPS_Mlegitimate.txt','w')#Memory Utilization Recovery	
        file_UDP_IPS_resource=open('/home/MWrite/UDP_IPS_Mconnection.txt','w')        
        file_UDP_IPS_false=open('/home/MWrite/UDP_IPS_Mfalsevalue.txt','w')
	file_UDP_IPS_RCost=open('/home/MWrite/UDP_IPS_MCost.txt','w')
	file_UDP_IPS_recovery.write('0.3')
        file_UDP_IPS_availability.write('0.2')
        file_UDP_IPS_latency.write('0.2')
        file_UDP_IPS_cost.write('0')
	file_UDP_IPS_leg.write('0')
        file_UDP_IPS_resource.write('0.2')
	file_UDP_IPS_false.write('1')
	file_UDP_IPS_RCost.write('0.2')
       #--------UDP Disable port---------
        file_UDP_Filter_recovery=open('/home/MWrite/UDP_Filter_Mspeed.txt','w')
        file_UDP_Filter_availability=open('/home/MWrite/UDP_Filter_Mcpu.txt','w')
        file_UDP_Filter_latency=open('/home/MWrite/UDP_Filter_Mpacket.txt','w')
        file_UDP_Filter_mem=open('/home/MWrite/UDP_Filter_Mmem.txt','w')
	file_UDP_Filter_leg=open('/home/MWrite/UDP_Filter_Mlegitimate.txt','w')
        file_UDP_Filter_resource=open('/home/MWrite/UDP_Filter_Mconnection.txt','w')
        file_UDP_Filter_false=open('/home/MWrite/UDP_Filter_Mfalsevalue.txt','w')
	file_UDP_Filter_RCost=open('/home/MWrite/UDP_Filter_MCost.txt','w')

        file_UDP_Filter_recovery.write('0.3')
        file_UDP_Filter_availability.write('0')
        file_UDP_Filter_latency.write('1')
        file_UDP_Filter_cost.write('1')
	file_UDP_Filter_leg.write('0')
        file_UDP_Filter_resource.write('0')
	file_UDP_Filter_false.write('1')
	file_UDP_Filter_RCost.write('0.2')
        
        #---------UDP TrustPlatform----------
        file_UDP_Filtering_recovery=open('/home/MWrite/UDP_Trust Platform_Mspeed.txt','w')
        file_UDP_Filtering_availability=open('/home/MWrite/UDP_Trust Platform_Mcpu.txt','w')
        file_UDP_Filtering_latency=open('/home/MWrite/UDP_Trust Platform_Mpacket.txt','w')
        file_UDP_Filtering_mem=open('/home/MWrite/UDP_Trust Platform_Mmem.txt','w')
	file_UDP_Filtering_leg=open('/home/MWrite/UDP_Trust Platform_Mlegitimate.txt','w')
        file_UDP_Filtering_resource=open('/home/MWrite/UDP_Trust Platform_Mconnection.txt','w')
        file_UDP_Filtering_false=open('/home/MWrite/UDP_Trust Platform_Mfalsevalue.txt','w')
        file_UDP_Filtering_RCost=open('/home/MWrite/UDP_Trust Platform_MCost.txt','w')

	file_UDP_Filtering_recovery.write('0.2')
        file_UDP_Filtering_availability.write('1')
        file_UDP_Filtering_latency.write('1')
        file_UDP_Filtering_cost.write('1')
	file_UDP_Filtering_leg.write('1')
        file_UDP_Filtering_resource.write('1')
	file_UDP_Filtering_false.write('0')
	file_UDP_Filtering_RCost.write('0.2')       
  
 	#-------new added UDP Replica-----------
        file_UDP_Replica_recovery=open('/home/MWrite/UDP_Replica_Mspeed.txt','w')
        file_UDP_Replica_availability=open('/home/MWrite/UDP_Replica_Mcpu.txt','w')
        file_UDP_Replica_latency=open('/home/MWrite/UDP_Replica_Mpacket.txt','w')
        file_UDP_Replica_mem=open('/home/MWrite/UDP_Replica_Mmem.txt','w')
	file_UDP_Replica_leg=open('/home/MWrite/UDP_Replica_Mlegitimate.txt','w')
        file_UDP_Replica_resource=open('/home/MWrite/UDP_Replica_Mconnection.txt','w')
        file_UDP_Replica_false=open('/home/MWrite/UDP_Replica_Mfalsevalue.txt','w')
	file_UDP_Replica_RCost=open('/home/MWrite/UDP_Replica_MCost.txt','w')        

        file_UDP_Replica_recovery.write('0.5')
        file_UDP_Replica_availability.write('1')
        file_UDP_Replica_latency.write('1')
        file_UDP_Replica_cost.write('0')
	file_UDP_Replica_leg.write('0')
        file_UDP_Replica_resource.write('1')	
        file_UDP_Replica_false.write('1')
        file_UDP_Replica_RCost.write('1')

	file_UDP_Replica_recovery.close()
        file_UDP_Replica_availability.close()
        file_UDP_Replica_latency.close()
        file_UDP_Replica_cost.close()	
        file_UDP_Replica_resource.close()
	file_UDP_Replica_leg.close()
	file_UDP_Replica_false.close()
	file_UDP_Replica_RCost.close()
        #----------UDP Firewall--------
        file_UDP_Firewall_recovery=open('/home/MWrite/UDP_Firewall_Mspeed.txt','w')
        file_UDP_Firewall_availability=open('/home/MWrite/UDP_Firewall_Mcpu.txt','w')
        file_UDP_Firewall_latency=open('/home/MWrite/UDP_Firewall_Mpacket.txt','w')
        file_UDP_Firewall_mem=open('/home/MWrite/UDP_Firewall_Mmem.txt','w')
	file_UDP_Firewall_leg=open('/home/MWrite/UDP_Firewall_Mlegitimate.txt','w')
        file_UDP_Firewall_resource=open('/home/MWrite/UDP_Firewall_Mconnection.txt','w')
        file_UDP_Firewall_false=open('/home/MWrite/UDP_Firewall_Mfalsevalue.txt','w')
        file_UDP_Firewall_false=open('/home/MWrite/UDP_Firewall_Mfalsevalue.txt','w')

        file_UDP_Firewall_recovery.write('0')
        file_UDP_Firewall_availability.write('1')
        file_UDP_Firewall_latency.write('1')
        file_UDP_Firewall_cost.write('1')
        file_UDP_Firewall_resource.write('1')
	#-------UDP network------------
        file_UDP_Disconnection_recovery=open('/home/MWrite/UDP_Network Disconnection_Mspeed.txt','w')
        file_UDP_Disconnection_availability=open('/home/MWrite/UDP_Network Disconnection_Mcpu.txt','w')
        file_UDP_Disconnection_latency=open('/home/MWrite/UDP_Network Disconnection_Mpacket.txt','w')
        file_UDP_Disconnection_mem=open('/home/MWrite/UDP_Network Disconnection_Mmem.txt','w')
	file_UDP_Disconnection_leg=open('/home/MWrite/UDP_Network Disconnection_Mlegitimate.txt','w')
        file_UDP_Disconnection_resource=open('/home/MWrite/UDP_Network Disconnection_Mconnection.txt','w')
        file_UDP_Disconnection_false=open('/home/MWrite/UDP_Network Disconnection_Mfalsevalue.txt','w')
        file_UDP_Disconnection_RCost=open('/home/MWrite/UDP_Network Disconnection_MCost.txt','w')

        file_UDP_Disconnection_recovery.write('0.2')
        file_UDP_Disconnection_availability.write('0')
        file_UDP_Disconnection_latency.write('0')
        file_UDP_Disconnection_cost.write('1')
	file_UDP_Disconnection_leg.write('0')
        file_UDP_Disconnection_resource.write('0.5')
	file_UDP_Disconnection_false.write('0')
	file_UDP_Disconnection_RCost.write('0.5')
        
        #-----UDP Host shutdown-------
        file_UDP_Shutdown_recovery=open('/home/MWrite/UDP_Host Shutdown_Mspeed.txt','w')
        file_UDP_Shutdown_availability=open('/home/MWrite/UDP_Host Shutdown_Mcpu.txt','w')
        file_UDP_Shutdown_latency=open('/home/MWrite/UDP_Host Shutdown_Mpacket.txt','w')
        file_UDP_Shutdown_mem=open('/home/MWrite/UDP_Host Shutdown_Mmem.txt','w')
	file_UDP_Shutdown_leg=open('/home/MWrite/UDP_Host Shutdown_Mlegitimate.txt','w')
        file_UDP_Shutdown_resource=open('/home/MWrite/UDP_Host Shutdown_Mconnection.txt','w')
	file_UDP_Shutdown_false=open('/home/MWrite/UDP_Host Shutdown_Mfalsevalue.txt','w')
	file_UDP_Shutdown_RCost=open('/home/MWrite/UDP_Host Shutdown_MCost.txt','w')
        file_UDP_Shutdown_recovery.write('0.3')
        file_UDP_Shutdown_availability.write('0.2')
        file_UDP_Shutdown_latency.write('0.2')
        file_UDP_Shutdown_cost.write('0')
	file_UDP_Shutdown_leg.write('0')
        file_UDP_Shutdown_resource.write('0.2')
	file_UDP_Shutdown_false.write('1')
	file_UDP_Shutdown_RCost.write('0.2')
        
        #--UDP Process Termination----------
	file_UDP_Terminate_recovery=open('/home/MWrite/UDP_Host Terminate_Mspeed.txt','w')
        file_UDP_Terminate_availability=open('/home/MWrite/UDP_Host Terminate_Mcpu.txt','w')
        file_UDP_Terminate_latency=open('/home/MWrite/UDP_Host Terminate_Mpacket.txt','w')
        file_UDP_Terminate_mem=open('/home/MWrite/UDP_Host Terminate_Mmem.txt','w')
	file_UDP_Terminate_leg=open('/home/MWrite/UDP_Host Terminate_Mlegitimate.txt','w')
        file_UDP_Terminate_resource=open('/home/MWrite/UDP_Host Terminate_Mconnection.txt','w')
	file_UDP_Terminate_false=open('/home/MWrite/UDP_Host Terminate_Mfalsevalue.txt','w')
	file_UDP_Terminate_RCost=open('/home/MWrite/UDP_Host Terminate_MCost.txt','w')

        file_UDP_Terminate_recovery.write('0.3')
        file_UDP_Terminate_availability.write('0')
        file_UDP_Terminate_latency.write('1')
        file_UDP_Terminate_cost.write('1')
	file_UDP_Terminate_leg.write('0')
        file_UDP_Terminate_resource.write('0.5')
	file_UDP_Terminate_false.write('0')
	file_UDP_Terminate_RCost.write('0.5')
	file_UDP_Terminate_false.close()
	file_UDP_Terminate_RCost.close()
	file_UDP_Terminate_leg.close()
        file_UDP_Terminate_recovery.close()
        file_UDP_Terminate_availability.close()
        file_UDP_Terminate_latency.close()
        file_UDP_Terminate_cost.close()
        file_UDP_Terminate_resource.close()
	#-----------UDP ModSecurity-----------
        file_UDP_ModSecurity_recovery=open('/home/MWrite/UDP_Host ModSecurity_Mspeed.txt','w')
        file_UDP_ModSecurity_availability=open('/home/MWrite/UDP_Host ModSecurity_Mcpu.txt','w')
        file_UDP_ModSecurity_latency=open('/home/MWrite/UDP_Host ModSecurity_Mpacket.txt','w')
        file_UDP_ModSecurity_mem=open('/home/MWrite/UDP_Host ModSecurity_Mmem.txt','w')
	file_UDP_ModSecurity_leg=open('/home/MWrite/UDP_Host ModSecurity_Mlegitimate.txt','w')
        file_UDP_ModSecurity_resource=open('/home/MWrite/UDP_Host ModSecurity_Mconnection.txt','w')
	file_UDP_ModSecurity_false=open('/home/MWrite/UDP_Host ModSecurity_Mfalsevalue.txt','w')
	file_UDP_ModSecurity_RCost=open('/home/MWrite/UDP_Host ModSecurity_MCost.txt','w')

        file_UDP_ModSecurity_recovery.write('0.3')
        file_UDP_ModSecurity_availability.write('0')
        file_UDP_ModSecurity_latency.write('1')
        file_UDP_ModSecurity_cost.write('1')
	file_UDP_ModSecurity_leg.write('0')
        file_UDP_ModSecurity_resource.write('0.5')
	file_UDP_ModSecurity_false.write('0')
	file_UDP_ModSecurity_RCost.write('0.5')
	file_UDP_ModSecurity_false.close()
	file_UDP_ModSecurity_RCost.close()
	file_UDP_ModSecurity_leg.close()
        file_UDP_ModSecurity_recovery.close()
        file_UDP_ModSecurity_availability.close()
        file_UDP_ModSecurity_latency.close()
        file_UDP_ModSecurity_cost.close()
        file_UDP_ModSecurity_resource.close()
        
        
        file_UDP_Shutdown_recovery.close()
        file_UDP_Shutdown_availability.close()
        file_UDP_Shutdown_latency.close()
        file_UDP_Shutdown_cost.close()
        file_UDP_Shutdown_resource.close()
        file_UDP_Firewall_recovery.close()
        file_UDP_Firewall_availability.close()
        file_UDP_Firewall_latency.close()
        file_UDP_Firewall_cost.close()
        file_UDP_Firewall_resource.close()
        file_UDP_Filtering_recovery.close()
        file_UDP_Filtering_availability.close()
        file_UDP_Filtering_latency.close()
        file_UDP_Filtering_cost.close()
        file_UDP_Filtering_resource.close()
        file_UDP_Disconnection_recovery.close()
        file_UDP_Disconnection_availability.close()
        file_UDP_Disconnection_latency.close()
        file_UDP_Disconnection_cost.close()
        file_UDP_Disconnection_resource.close()
        file_UDP_Filter_recovery.close()
        file_UDP_Filter_availability.close()
        file_UDP_Filter_latency.close()
        file_UDP_Filter_cost.close()
        file_UDP_Filter_resource.close()
        file_UDP_IPS_recovery.close()
        file_UDP_IPS_availability.close()
        file_UDP_IPS_latency.close()
        file_UDP_IPS_cost.close()
        file_UDP_IPS_resource.close()

	file_UDP_IPS_false.close()
	file_UDP_IPS_leg.close()
	file_UDP_IPS_RCost.close()

	file_UDP_Filter_false.close()
	file_UDP_Filter_leg.close()
	file_UDP_Filter_RCost.close()

	file_UDP_Disconnection_false.close()
	file_UDP_Disconnection_leg.close()
	file_UDP_Disconnection_RCost.close()

	file_UDP_Filtering_false.close()
	file_UDP_Filtering_leg.close()
	file_UDP_Filtering_RCost.close()

	file_UDP_Firewall_false.close()
	file_UDP_Firewall_leg.close()
	file_UDP_Firewall_RCost.close()

	file_UDP_Shutdown_false.close()
	file_UDP_Shutdown_leg.close()
	file_UDP_Shutdown_RCost.close()

	#---------new added-------------
	
        #-------TCP-------
        file_TCP_SYN_IPS_recovery=open('/home/MWrite/TCP_SYN_IPS_Mspeed.txt','w')
        file_TCP_SYN_IPS_availability=open('/home/MWrite/TCP_SYN_IPS_Mcpu.txt','w')
        file_TCP_SYN_IPS_latency=open('/home/MWrite/TCP_SYN_IPS_Mpacket.txt','w')
        file_TCP_SYN_IPS_mem=open('/home/MWrite/TCP_SYN_IPS_Mmem.txt','w')
	file_TCP_SYN_IPS_leg=open('/home/MWrite/TCP_SYN_IPS_Mlegitimate.txt','w')
        file_TCP_SYN_IPS_resource=open('/home/MWrite/TCP_SYN_IPS_Mconnection.txt','w')
        file_TCP_SYN_IPS_false=open('/home/MWrite/TCP_SYN_IPS_Mfalsevalue.txt','w')
        file_TCP_SYN_IPS_RCost=open('/home/MWrite/TCP_SYN_IPS_MCost.txt','w')

        file_TCP_SYN_IPS_recovery.write('0.3')
        file_TCP_SYN_IPS_availability.write('0.2')
        file_TCP_SYN_IPS_latency.write('1')
        file_TCP_SYN_IPS_cost.write('1')
	file_TCP_SYN_IPS_leg.write('0')
        file_TCP_SYN_IPS_resource.write('0.2')
	file_TCP_SYN_IPS_false.write('1')
	file_TCP_SYN_IPS_RCost.write('0.2')

        file_TCP_SYN_IPS_recovery.close()
        file_TCP_SYN_IPS_availability.close()
        file_TCP_SYN_IPS_latency.close()
        file_TCP_SYN_IPS_cost.close()
        file_TCP_SYN_IPS_resource.close()
	file_TCP_SYN_IPS_false.close()
	file_TCP_SYN_IPS_RCost.close()
	file_TCP_SYN_IPS_leg.close()
	
        file_TCP_SYN_Filter_recovery=open('/home/MWrite/TCP_SYN_Filter_Mspeed.txt','w')
        file_TCP_SYN_Filter_availability=open('/home/MWrite/TCP_SYN_Filter_Mcpu.txt','w')
        file_TCP_SYN_Filter_latency=open('/home/MWrite/TCP_SYN_Filter_Mpacket.txt','w')
        file_TCP_SYN_Filter_mem=open('/home/MWrite/TCP_SYN_Filter_Mmem.txt','w')
        file_TCP_SYN_Filter_leg=open('/home/MWrite/TCP_SYN_Filter_Mlegitimate.txt','w')
        file_TCP_SYN_Filter_resource=open('/home/MWrite/TCP_SYN_Filter_Mconnection.txt','w')
        file_TCP_SYN_Filter_false=open('/home/MWrite/TCP_SYN_Filter_Mfalsevalue.txt','w')
        
        file_TCP_SYN_Filter_recovery.write('0.3')
        file_TCP_SYN_Filter_availability.write('0')
        file_TCP_SYN_Filter_latency.write('0')
        file_TCP_SYN_Filter_cost.write('0.5')
	file_TCP_SYN_Filter_leg.write('0')
        file_TCP_SYN_Filter_resource.write('0')
	file_TCP_SYN_Filter_false.write('1')
	file_TCP_SYN_Filter_RCost.write('0.2')

        file_TCP_SYN_Filter_recovery.close()
        file_TCP_SYN_Filter_availability.close()
        file_TCP_SYN_Filter_latency.close()
        file_TCP_SYN_Filter_cost.close()
        file_TCP_SYN_Filter_resource.close()
	file_TCP_SYN_Filter_false.close()
	file_TCP_SYN_Filter_RCost.close()
	file_TCP_SYN_Filter_leg.close()

        file_TCP_SYN_Filtering_recovery=open('/home/MWrite/TCP_SYN_Trust Platform_Mspeed.txt','w')
        file_TCP_SYN_Filtering_availability=open('/home/MWrite/TCP_SYN_Trust Platform_Mcpu.txt','w')
        file_TCP_SYN_Filtering_latency=open('/home/MWrite/TCP_SYN_Trust Platform_Mpacket.txt','w')
        file_TCP_SYN_Filtering_mem=open('/home/MWrite/TCP_SYN_Trust Platform_Mmem.txt','w')
	file_TCP_SYN_Filtering_leg=open('/home/MWrite/TCP_SYN_Trust Platform_Mlegitimate.txt','w')
        file_TCP_SYN_Filtering_resource=open('/home/MWrite/TCP_SYN_Trust Platform_Mconnection.txt','w')
        file_TCP_SYN_Filtering_false=open('/home/MWrite/TCP_SYN_Trust Platform_Mfalsevalue.txt','w')
        file_TCP_SYN_Filtering_RCost('/home/MWrite/TCP_SYN_Trust Platform_MCost.txt','w')
        
        file_TCP_SYN_Filtering_recovery.write('0.2')
        file_TCP_SYN_Filtering_availability.write('1')
        file_TCP_SYN_Filtering_latency.write('1')
        file_TCP_SYN_Filtering_cost.write('1')
	file_TCP_SYN_Filtering_leg.write('1')
        file_TCP_SYN_Filtering_resource.write('1')
	file_TCP_SYN_Filtering_false.write('0')
	file_TCP_SYN_Filtering_RCost.write('0.2')
	file_TCP_SYN_Filtering_false.close()
	file_TCP_SYN_Filtering_RCost.close()
	file_TCP_SYN_Filtering_leg.close()

        file_TCP_SYN_Filtering_recovery.close()
        file_TCP_SYN_Filtering_availability.close()
        file_TCP_SYN_Filtering_latency.close()
        file_TCP_SYN_Filtering_cost.close()
        file_TCP_SYN_Filtering_resource.close()
	
	#--------------Firewall---------
        file_TCP_SYN_Firewall_recovery=open('/home/MWrite/TCP_SYN_Firewall_Mspeed.txt','w')
        file_TCP_SYN_Firewall_availability=open('/home/MWrite/TCP_SYN_Firewall_Mcpu.txt','w')
        file_TCP_SYN_Firewall_latency=open('/home/MWrite/TCP_SYN_Firewall_Mpacket.txt','w')
        file_TCP_SYN_Firewall_mem=open('/home/MWrite/TCP_SYN_Firewall_Mmem.txt','w')
	file_TCP_SYN_Firewall_leg=open('/home/MWrite/TCP_SYN_Firewall_Mlegitimate.txt','w')
        file_TCP_SYN_Firewall_resource=open('/home/MWrite/TCP_SYN_Firewall_Mconnection.txt','w')
	file_TCP_SYN_Firewall_false=open('/home/MWrite/TCP_SYN_Firewall_Mfalsevalue.txt','w')
	file_TCP_SYN_Firewall_RCost=open('/home/MWrite/TCP_SYN_Firewall_MCost.txt','w')
        
	
        file_TCP_SYN_Firewall_recovery.close()
        file_TCP_SYN_Firewall_availability.close()
        file_TCP_SYN_Firewall_latency.close()
        file_TCP_SYN_Firewall_cost.close()
        file_TCP_SYN_Firewall_resource.close()
	#-------TCP_SYN Replica-----------
        file_TCP_SYN_Replica_recovery=open('/home/MWrite/TCP_SYN_Replica_Mspeed.txt','w')
        file_TCP_SYN_Replica_availability=open('/home/MWrite/TCP_SYN_Replica_Mcpu.txt','w')
        file_TCP_SYN_Replica_latency=open('/home/MWrite/TCP_SYN_Replica_Mpacket.txt','w')
        file_TCP_SYN_Replica_mem=open('/home/MWrite/TCP_SYN_Replica_Mmem.txt','w')
	file_TCP_SYN_Replica_leg=open('/home/MWrite/TCP_SYN_Replica_Mlegitimate.txt','w')
        file_TCP_SYN_Replica_resource=open('/home/MWrite/TCP_SYN_Replica_Mconnection.txt','w')
        file_TCP_SYN_Replica_false=open('/home/MWrite/TCP_SYN_Replica_Mfalsevalue.txt','w')
        file_TCP_SYN_Replica_RCost=open('/home/MWrite/TCP_SYN_Replica_MCost.txt','w')

        file_TCP_SYN_Replica_recovery.write('0.2')
        file_TCP_SYN_Replica_availability.write('1')
        file_TCP_SYN_Replica_latency.write('0')
        file_TCP_SYN_Replica_cost.write('0')
	file_TCP_SYN_Replica_leg.write('1')
        file_TCP_SYN_Replica_resource.write('1')
	file_TCP_SYN_Replica_false.write('1')
	file_TCP_SYN_Replica_RCost.write('0.8')
	
	file_TCP_SYN_Replica_RCost.close()
	file_TCP_SYN_Replica_recovery.close()
        file_TCP_SYN_Replica_availability.close()
        file_TCP_SYN_Replica_latency.close()
        file_TCP_SYN_Replica_cost.close()	
        file_TCP_SYN_Replica_resource.close()
	file_TCP_SYN_Replica_leg.close()
	file_TCP_SYN_Replica_false.close()
	#-------Disconnection--------
        file_TCP_SYN_Disconnection_recovery=open('/home/MWrite/TCP_SYN_Network Disconnection_Mspeed.txt','w')
        file_TCP_SYN_Disconnection_availability=open('/home/MWrite/TCP_SYN_Network Disconnection_Mcpu.txt','w')
        file_TCP_SYN_Disconnection_latency=open('/home/MWrite/TCP_SYN_Network Disconnection_Mpacket.txt','w')
        file_TCP_SYN_Disconnection_mem=open('/home/MWrite/TCP_SYN_Network Disconnection_Mmem.txt','w')
	file_TCP_SYN_Disconnection_leg=open('/home/MWrite/TCP_SYN_Network Disconnection_Mlegitimate.txt','w')
        file_TCP_SYN_Disconnection_resource=open('/home/MWrite/TCP_SYN_Network Disconnection_Mconnection.txt','w')
        file_TCP_SYN_Disconnection_false=open('/home/MWrite/TCP_SYN_Network Disconnection_Mfalsevalue.txt','w')
        file_TCP_SYN_Disconnection_RCost=open('/home/MWrite/TCP_SYN_Network Disconnection_MCost.txt','w')

        file_TCP_SYN_Disconnection_recovery.write('0.2')
        file_TCP_SYN_Disconnection_availability.write('0')
        file_TCP_SYN_Disconnection_latency.write('0')
        file_TCP_SYN_Disconnection_cost.write('1')
	file_TCP_SYN_Disconnection_leg.write('0')
        file_TCP_SYN_Disconnection_resource.write('0.5')
	file_TCP_SYN_Disconnection_false.write('0')
	file_TCP_SYN_Disconnection_RCost.write('0.5')
	file_TCP_SYN_Disconnection_false.close()
	file_TCP_SYN_Disconnection_RCost.close()
	file_TCP_SYN_Disconnection_leg.close()

        file_TCP_SYN_Disconnection_recovery.close()
        file_TCP_SYN_Disconnection_availability.close()
        file_TCP_SYN_Disconnection_latency.close()
        file_TCP_SYN_Disconnection_cost.close()
        file_TCP_SYN_Disconnection_resource.close()
	
	

        file_TCP_SYN_Shutdown_recovery=open('/home/MWrite/TCP_SYN_Host Shutdown_Mspeed.txt','w')
        file_TCP_SYN_Shutdown_availability=open('/home/MWrite/TCP_SYN_Host Shutdown_Mcpu.txt','w')
        file_TCP_SYN_Shutdown_latency=open('/home/MWrite/TCP_SYN_Host Shutdown_Mpacket.txt','w')
        file_TCP_SYN_Shutdown_mem=open('/home/MWrite/TCP_SYN_Host Shutdown_Mmem.txt','w')
	file_TCP_SYN_Shutdown_leg=open('/home/MWrite/TCP_SYN_Host Shutdown_Mlegitimate.txt','w')
        file_TCP_SYN_Shutdown_resource=open('/home/MWrite/TCP_SYN_Host Shutdown_Mconnection.txt','w')
	file_TCP_SYN_Shutdown_false=open('/home/MWrite/TCP_SYN_Host Shutdown_Mfalsevalue.txt','w')
	file_TCP_SYN_Shutdown_RCost=open('/home/MWrite/TCP_SYN_Host Shutdown_MCost.txt','w')

        file_TCP_SYN_Shutdown_recovery.write('0.3')
        file_TCP_SYN_Shutdown_availability.write('0')
        file_TCP_SYN_Shutdown_latency.write('1')
        file_TCP_SYN_Shutdown_cost.write('1')
	file_TCP_SYN_Shutdown_leg.write('0')
        file_TCP_SYN_Shutdown_resource.write('0.5')
	file_TCP_SYN_Shutdown_false.write('0')
	file_TCP_SYN_Shutdown_RCost.write('0.5')
	file_TCP_SYN_Shutdown_false.close()
	file_TCP_SYN_Shutdown_RCost.close()
	file_TCP_SYN_Shutdown_leg.close()
        file_TCP_SYN_Shutdown_recovery.close()
        file_TCP_SYN_Shutdown_availability.close()
        file_TCP_SYN_Shutdown_latency.close()
        file_TCP_SYN_Shutdown_cost.close()
        file_TCP_SYN_Shutdown_resource.close()
	#---------new added Process Termination-------------
	file_TCP_SYN_Terminate_recovery=open('/home/MWrite/TCP_SYN_Host Terminate_Mspeed.txt','w')
        file_TCP_SYN_Terminate_availability=open('/home/MWrite/TCP_SYN_Host Terminate_Mcpu.txt','w')
        file_TCP_SYN_Terminate_latency=open('/home/MWrite/TCP_SYN_Host Terminate_Mpacket.txt','w')
        file_TCP_SYN_Terminate_mem=open('/home/MWrite/TCP_SYN_Host Terminate_Mmem.txt','w')
	file_TCP_SYN_Terminate_leg=open('/home/MWrite/TCP_SYN_Host Terminate_Mlegitimate.txt','w')
        file_TCP_SYN_Terminate_resource=open('/home/MWrite/TCP_SYN_Host Terminate_Mconnection.txt','w')
	file_TCP_SYN_Terminate_false=open('/home/MWrite/TCP_SYN_Host Terminate_Mfalsevalue.txt','w')
	file_TCP_SYN_Terminate_RCost=open('/home/MWrite/TCP_SYN_Host Terminate_MCost.txt','w')

        file_TCP_SYN_Terminate_recovery.write('0.1')
        file_TCP_SYN_Terminate_availability.write('0.6')
        file_TCP_SYN_Terminate_latency.write('1')
        file_TCP_SYN_Terminate_cost.write('1')
	file_TCP_SYN_Terminate_leg.write('0.5')
        file_TCP_SYN_Terminate_resource.write('1')
	file_TCP_SYN_Terminate_false.write('1')
	file_TCP_SYN_Terminate_RCost.write('0.4')
	file_TCP_SYN_Terminate_false.close()
	file_TCP_SYN_Terminate_RCost.close()
	file_TCP_SYN_Terminate_leg.close()
        file_TCP_SYN_Terminate_recovery.close()
        file_TCP_SYN_Terminate_availability.close()
        file_TCP_SYN_Terminate_latency.close()
        file_TCP_SYN_Terminate_cost.close()
        file_TCP_SYN_Terminate_resource.close()

        #----------ModSecurity---------

        file_TCP_SYN_ModSecurity_recovery=open('/home/MWrite/TCP_SYN_Host ModSecurity_Mspeed.txt','w')
        file_TCP_SYN_ModSecurity_availability=open('/home/MWrite/TCP_SYN_Host ModSecurity_Mcpu.txt','w')
        file_TCP_SYN_ModSecurity_latency=open('/home/MWrite/TCP_SYN_Host ModSecurity_Mpacket.txt','w')
        file_TCP_SYN_ModSecurity_mem=open('/home/MWrite/TCP_SYN_Host ModSecurity_Mmem.txt','w')
	file_TCP_SYN_ModSecurity_leg=open('/home/MWrite/TCP_SYN_Host ModSecurity_Mlegitimate.txt','w')
        file_TCP_SYN_ModSecurity_resource=open('/home/MWrite/TCP_SYN_Host ModSecurity_Mconnection.txt','w')
	file_TCP_SYN_ModSecurity_false=open('/home/MWrite/TCP_SYN_Host ModSecurity_Mfalsevalue.txt','w')
	file_TCP_SYN_ModSecurity_RCost=open('/home/MWrite/TCP_SYN_Host ModSecurity_MCost.txt','w')

        file_TCP_SYN_ModSecurity_recovery.write('0.3')
        file_TCP_SYN_ModSecurity_availability.write('0')
        file_TCP_SYN_ModSecurity_latency.write('1')
        file_TCP_SYN_ModSecurity_cost.write('1')
	file_TCP_SYN_ModSecurity_leg.write('0')
        file_TCP_SYN_ModSecurity_resource.write('0.5')
	file_TCP_SYN_ModSecurity_false.write('0')
	file_TCP_SYN_ModSecurity_RCost.write('0.5')
	file_TCP_SYN_ModSecurity_false.close()
	file_TCP_SYN_ModSecurity_RCost.close()
	file_TCP_SYN_ModSecurity_leg.close()
        file_TCP_SYN_ModSecurity_recovery.close()
        file_TCP_SYN_ModSecurity_availability.close()
        file_TCP_SYN_ModSecurity_latency.close()
        file_TCP_SYN_ModSecurity_cost.close()
        file_TCP_SYN_ModSecurity_resource.close()
    #---------------ICMP------------------------
	

	#---------ICMP IPS----------
	file_ICMP_IPS_recovery=open('/home/MWrite/ICMP_IPS_Mspeed.txt','w')
        file_ICMP_IPS_availability=open('/home/MWrite/ICMP_IPS_Mcpu.txt','w')
        file_ICMP_IPS_latency=open('/home/MWrite/ICMP_IPS_Mpacket.txt','w')
        file_ICMP_IPS_mem=open('/home/MWrite/ICMP_IPS_Mmem.txt','w')
        file_ICMP_IPS_leg=open('/home/MWrite/ICMP_IPS_Mlegitimate.txt','w')#Memory Utilization Recovery	
        file_ICMP_IPS_resource=open('/home/MWrite/ICMP_IPS_Mconnection.txt','w')        
        file_ICMP_IPS_false=open('/home/MWrite/ICMP_IPS_Mfalsevalue.txt','w')
	file_ICMP_IPS_RCost=open('/home/MWrite/ICMP_IPS_MCost.txt','w')
	file_ICMP_IPS_recovery.write('0.3')
        file_ICMP_IPS_availability.write('0.2')
        file_ICMP_IPS_latency.write('0.2')
        file_ICMP_IPS_cost.write('0')
	file_ICMP_IPS_leg.write('0')
        file_ICMP_IPS_resource.write('0.2')
	file_ICMP_IPS_false.write('1')
	file_ICMP_IPS_RCost.write('0.2')
       #--------ICMP Disable port---------
        file_ICMP_Filter_recovery=open('/home/MWrite/ICMP_Filter_Mspeed.txt','w')
        file_ICMP_Filter_availability=open('/home/MWrite/ICMP_Filter_Mcpu.txt','w')
        file_ICMP_Filter_latency=open('/home/MWrite/ICMP_Filter_Mpacket.txt','w')
        file_ICMP_Filter_mem=open('/home/MWrite/ICMP_Filter_Mmem.txt','w')
	file_ICMP_Filter_leg=open('/home/MWrite/ICMP_Filter_Mlegitimate.txt','w')
        file_ICMP_Filter_resource=open('/home/MWrite/ICMP_Filter_Mconnection.txt','w')
        file_ICMP_Filter_false=open('/home/MWrite/ICMP_Filter_Mfalsevalue.txt','w')
	file_ICMP_Filter_RCost=open('/home/MWrite/ICMP_Filter_MCost.txt','w')

        file_ICMP_Filter_recovery.write('0.3')
        file_ICMP_Filter_availability.write('0')
        file_ICMP_Filter_latency.write('1')
        file_ICMP_Filter_cost.write('1')
	file_ICMP_Filter_leg.write('0')
        file_ICMP_Filter_resource.write('0')
	file_ICMP_Filter_false.write('1')
	file_ICMP_Filter_RCost.write('0.2')
        
        #---------ICMP TrustPlatform----------
        file_ICMP_Filtering_recovery=open('/home/MWrite/ICMP_Trust Platform_Mspeed.txt','w')
        file_ICMP_Filtering_availability=open('/home/MWrite/ICMP_Trust Platform_Mcpu.txt','w')
        file_ICMP_Filtering_latency=open('/home/MWrite/ICMP_Trust Platform_Mpacket.txt','w')
        file_ICMP_Filtering_mem=open('/home/MWrite/ICMP_Trust Platform_Mmem.txt','w')
	file_ICMP_Filtering_leg=open('/home/MWrite/ICMP_Trust Platform_Mlegitimate.txt','w')
        file_ICMP_Filtering_resource=open('/home/MWrite/ICMP_Trust Platform_Mconnection.txt','w')
        file_ICMP_Filtering_false=open('/home/MWrite/ICMP_Trust Platform_Mfalsevalue.txt','w')
        file_ICMP_Filtering_RCost=open('/home/MWrite/ICMP_Trust Platform_MCost.txt','w')

	file_ICMP_Filtering_recovery.write('0.2')
        file_ICMP_Filtering_availability.write('1')
        file_ICMP_Filtering_latency.write('1')
        file_ICMP_Filtering_cost.write('1')
	file_ICMP_Filtering_leg.write('1')
        file_ICMP_Filtering_resource.write('1')
	file_ICMP_Filtering_false.write('0')
	file_ICMP_Filtering_RCost.write('0.2')       
  
 	#-------new added ICMP Replica-----------
        file_ICMP_Replica_recovery=open('/home/MWrite/ICMP_Replica_Mspeed.txt','w')
        file_ICMP_Replica_availability=open('/home/MWrite/ICMP_Replica_Mcpu.txt','w')
        file_ICMP_Replica_latency=open('/home/MWrite/ICMP_Replica_Mpacket.txt','w')
        file_ICMP_Replica_mem=open('/home/MWrite/ICMP_Replica_Mmem.txt','w')
	file_ICMP_Replica_leg=open('/home/MWrite/ICMP_Replica_Mlegitimate.txt','w')
        file_ICMP_Replica_resource=open('/home/MWrite/ICMP_Replica_Mconnection.txt','w')
        file_ICMP_Replica_false=open('/home/MWrite/ICMP_Replica_Mfalsevalue.txt','w')
	file_ICMP_Replica_RCost=open('/home/MWrite/ICMP_Replica_MCost.txt','w')        

        file_ICMP_Replica_recovery.write('0.5')
        file_ICMP_Replica_availability.write('1')
        file_ICMP_Replica_latency.write('1')
        file_ICMP_Replica_cost.write('0')
	file_ICMP_Replica_leg.write('0')
        file_ICMP_Replica_resource.write('1')	
        file_ICMP_Replica_false.write('1')
        file_ICMP_Replica_RCost.write('1')

	file_ICMP_Replica_recovery.close()
        file_ICMP_Replica_availability.close()
        file_ICMP_Replica_latency.close()
        file_ICMP_Replica_cost.close()	
        file_ICMP_Replica_resource.close()
	file_ICMP_Replica_leg.close()
	file_ICMP_Replica_false.close()
	file_ICMP_Replica_RCost.close()
        #----------ICMP Firewall--------
        file_ICMP_Firewall_recovery=open('/home/MWrite/ICMP_Firewall_Mspeed.txt','w')
        file_ICMP_Firewall_availability=open('/home/MWrite/ICMP_Firewall_Mcpu.txt','w')
        file_ICMP_Firewall_latency=open('/home/MWrite/ICMP_Firewall_Mpacket.txt','w')
        file_ICMP_Firewall_mem=open('/home/MWrite/ICMP_Firewall_Mmem.txt','w')
	file_ICMP_Firewall_leg=open('/home/MWrite/ICMP_Firewall_Mlegitimate.txt','w')
        file_ICMP_Firewall_resource=open('/home/MWrite/ICMP_Firewall_Mconnection.txt','w')
        file_ICMP_Firewall_false=open('/home/MWrite/ICMP_Firewall_Mfalsevalue.txt','w')
        file_ICMP_Firewall_false=open('/home/MWrite/ICMP_Firewall_Mfalsevalue.txt','w')

        file_ICMP_Firewall_recovery.write('0')
        file_ICMP_Firewall_availability.write('1')
        file_ICMP_Firewall_latency.write('1')
        file_ICMP_Firewall_cost.write('1')
        file_ICMP_Firewall_resource.write('1')
	#-------ICMP network------------
        file_ICMP_Disconnection_recovery=open('/home/MWrite/ICMP_Network Disconnection_Mspeed.txt','w')
        file_ICMP_Disconnection_availability=open('/home/MWrite/ICMP_Network Disconnection_Mcpu.txt','w')
        file_ICMP_Disconnection_latency=open('/home/MWrite/ICMP_Network Disconnection_Mpacket.txt','w')
        file_ICMP_Disconnection_mem=open('/home/MWrite/ICMP_Network Disconnection_Mmem.txt','w')
	file_ICMP_Disconnection_leg=open('/home/MWrite/ICMP_Network Disconnection_Mlegitimate.txt','w')
        file_ICMP_Disconnection_resource=open('/home/MWrite/ICMP_Network Disconnection_Mconnection.txt','w')
        file_ICMP_Disconnection_false=open('/home/MWrite/ICMP_Network Disconnection_Mfalsevalue.txt','w')
        file_ICMP_Disconnection_RCost=open('/home/MWrite/ICMP_Network Disconnection_MCost.txt','w')

        file_ICMP_Disconnection_recovery.write('0.2')
        file_ICMP_Disconnection_availability.write('0')
        file_ICMP_Disconnection_latency.write('0')
        file_ICMP_Disconnection_cost.write('1')
	file_ICMP_Disconnection_leg.write('0')
        file_ICMP_Disconnection_resource.write('0.5')
	file_ICMP_Disconnection_false.write('0')
	file_ICMP_Disconnection_RCost.write('0.5')
        
        #-----ICMP Host shutdown-------
        file_ICMP_Shutdown_recovery=open('/home/MWrite/ICMP_Host Shutdown_Mspeed.txt','w')
        file_ICMP_Shutdown_availability=open('/home/MWrite/ICMP_Host Shutdown_Mcpu.txt','w')
        file_ICMP_Shutdown_latency=open('/home/MWrite/ICMP_Host Shutdown_Mpacket.txt','w')
        file_ICMP_Shutdown_mem=open('/home/MWrite/ICMP_Host Shutdown_Mmem.txt','w')
	file_ICMP_Shutdown_leg=open('/home/MWrite/ICMP_Host Shutdown_Mlegitimate.txt','w')
        file_ICMP_Shutdown_resource=open('/home/MWrite/ICMP_Host Shutdown_Mconnection.txt','w')
	file_ICMP_Shutdown_false=open('/home/MWrite/ICMP_Host Shutdown_Mfalsevalue.txt','w')
	file_ICMP_Shutdown_RCost=open('/home/MWrite/ICMP_Host Shutdown_MCost.txt','w')
        file_ICMP_Shutdown_recovery.write('0.3')
        file_ICMP_Shutdown_availability.write('0.2')
        file_ICMP_Shutdown_latency.write('0.2')
        file_ICMP_Shutdown_cost.write('0')
	file_ICMP_Shutdown_leg.write('0')
        file_ICMP_Shutdown_resource.write('0.2')
	file_ICMP_Shutdown_false.write('1')
	file_ICMP_Shutdown_RCost.write('0.2')
        
        #--ICMP Process Termination----------
	file_ICMP_Terminate_recovery=open('/home/MWrite/ICMP_Host Terminate_Mspeed.txt','w')
        file_ICMP_Terminate_availability=open('/home/MWrite/ICMP_Host Terminate_Mcpu.txt','w')
        file_ICMP_Terminate_latency=open('/home/MWrite/ICMP_Host Terminate_Mpacket.txt','w')
        file_ICMP_Terminate_mem=open('/home/MWrite/ICMP_Host Terminate_Mmem.txt','w')
	file_ICMP_Terminate_leg=open('/home/MWrite/ICMP_Host Terminate_Mlegitimate.txt','w')
        file_ICMP_Terminate_resource=open('/home/MWrite/ICMP_Host Terminate_Mconnection.txt','w')
	file_ICMP_Terminate_false=open('/home/MWrite/ICMP_Host Terminate_Mfalsevalue.txt','w')
	file_ICMP_Terminate_RCost=open('/home/MWrite/ICMP_Host Terminate_MCost.txt','w')

        file_ICMP_Terminate_recovery.write('0.3')
        file_ICMP_Terminate_availability.write('0')
        file_ICMP_Terminate_latency.write('1')
        file_ICMP_Terminate_cost.write('1')
	file_ICMP_Terminate_leg.write('0')
        file_ICMP_Terminate_resource.write('0.5')
	file_ICMP_Terminate_false.write('0')
	file_ICMP_Terminate_RCost.write('0.5')
	file_ICMP_Terminate_false.close()
	file_ICMP_Terminate_RCost.close()
	file_ICMP_Terminate_leg.close()
        file_ICMP_Terminate_recovery.close()
        file_ICMP_Terminate_availability.close()
        file_ICMP_Terminate_latency.close()
        file_ICMP_Terminate_cost.close()
        file_ICMP_Terminate_resource.close()
	#-----------ICMP ModSecurity-----------
        file_ICMP_ModSecurity_recovery=open('/home/MWrite/ICMP_Host ModSecurity_Mspeed.txt','w')
        file_ICMP_ModSecurity_availability=open('/home/MWrite/ICMP_Host ModSecurity_Mcpu.txt','w')
        file_ICMP_ModSecurity_latency=open('/home/MWrite/ICMP_Host ModSecurity_Mpacket.txt','w')
        file_ICMP_ModSecurity_mem=open('/home/MWrite/ICMP_Host ModSecurity_Mmem.txt','w')
	file_ICMP_ModSecurity_leg=open('/home/MWrite/ICMP_Host ModSecurity_Mlegitimate.txt','w')
        file_ICMP_ModSecurity_resource=open('/home/MWrite/ICMP_Host ModSecurity_Mconnection.txt','w')
	file_ICMP_ModSecurity_false=open('/home/MWrite/ICMP_Host ModSecurity_Mfalsevalue.txt','w')
	file_ICMP_ModSecurity_RCost=open('/home/MWrite/ICMP_Host ModSecurity_MCost.txt','w')

        file_ICMP_ModSecurity_recovery.write('0.3')
        file_ICMP_ModSecurity_availability.write('0')
        file_ICMP_ModSecurity_latency.write('1')
        file_ICMP_ModSecurity_cost.write('1')
	file_ICMP_ModSecurity_leg.write('0')
        file_ICMP_ModSecurity_resource.write('0.5')
	file_ICMP_ModSecurity_false.write('0')
	file_ICMP_ModSecurity_RCost.write('0.5')
	file_ICMP_ModSecurity_false.close()
	file_ICMP_ModSecurity_RCost.close()
	file_ICMP_ModSecurity_leg.close()
        file_ICMP_ModSecurity_recovery.close()
        file_ICMP_ModSecurity_availability.close()
        file_ICMP_ModSecurity_latency.close()
        file_ICMP_ModSecurity_cost.close()
        file_ICMP_ModSecurity_resource.close()
        
        
        file_ICMP_Shutdown_recovery.close()
        file_ICMP_Shutdown_availability.close()
        file_ICMP_Shutdown_latency.close()
        file_ICMP_Shutdown_cost.close()
        file_ICMP_Shutdown_resource.close()
        file_ICMP_Firewall_recovery.close()
        file_ICMP_Firewall_availability.close()
        file_ICMP_Firewall_latency.close()
        file_ICMP_Firewall_cost.close()
        file_ICMP_Firewall_resource.close()
        file_ICMP_Filtering_recovery.close()
        file_ICMP_Filtering_availability.close()
        file_ICMP_Filtering_latency.close()
        file_ICMP_Filtering_cost.close()
        file_ICMP_Filtering_resource.close()
        file_ICMP_Disconnection_recovery.close()
        file_ICMP_Disconnection_availability.close()
        file_ICMP_Disconnection_latency.close()
        file_ICMP_Disconnection_cost.close()
        file_ICMP_Disconnection_resource.close()
        file_ICMP_Filter_recovery.close()
        file_ICMP_Filter_availability.close()
        file_ICMP_Filter_latency.close()
        file_ICMP_Filter_cost.close()
        file_ICMP_Filter_resource.close()
        file_ICMP_IPS_recovery.close()
        file_ICMP_IPS_availability.close()
        file_ICMP_IPS_latency.close()
        file_ICMP_IPS_cost.close()
        file_ICMP_IPS_resource.close()

	file_ICMP_IPS_false.close()
	file_ICMP_IPS_leg.close()
	file_ICMP_IPS_RCost.close()

	file_ICMP_Filter_false.close()
	file_ICMP_Filter_leg.close()
	file_ICMP_Filter_RCost.close()

	file_ICMP_Disconnection_false.close()
	file_ICMP_Disconnection_leg.close()
	file_ICMP_Disconnection_RCost.close()

	file_ICMP_Filtering_false.close()
	file_ICMP_Filtering_leg.close()
	file_ICMP_Filtering_RCost.close()

	file_ICMP_Firewall_false.close()
	file_ICMP_Firewall_leg.close()
	file_ICMP_Firewall_RCost.close()

	file_ICMP_Shutdown_false.close()
	file_ICMP_Shutdown_leg.close()
	file_ICMP_Shutdown_RCost.close()
    #---------POD-----------
	

	#---------POD IPS----------
	file_POD_IPS_recovery=open('/home/MWrite/POD_IPS_Mspeed.txt','w')
        file_POD_IPS_availability=open('/home/MWrite/POD_IPS_Mcpu.txt','w')
        file_POD_IPS_latency=open('/home/MWrite/POD_IPS_Mpacket.txt','w')
        file_POD_IPS_mem=open('/home/MWrite/POD_IPS_Mmem.txt','w')
        file_POD_IPS_leg=open('/home/MWrite/POD_IPS_Mlegitimate.txt','w')#Memory Utilization Recovery	
        file_POD_IPS_resource=open('/home/MWrite/POD_IPS_Mconnection.txt','w')        
        file_POD_IPS_false=open('/home/MWrite/POD_IPS_Mfalsevalue.txt','w')
	file_POD_IPS_RCost=open('/home/MWrite/POD_IPS_MCost.txt','w')
	file_POD_IPS_recovery.write('0.3')
        file_POD_IPS_availability.write('0.2')
        file_POD_IPS_latency.write('0.2')
        file_POD_IPS_cost.write('0')
	file_POD_IPS_leg.write('0')
        file_POD_IPS_resource.write('0.2')
	file_POD_IPS_false.write('1')
	file_POD_IPS_RCost.write('0.2')
       #--------POD Disable port---------
        file_POD_Filter_recovery=open('/home/MWrite/POD_Filter_Mspeed.txt','w')
        file_POD_Filter_availability=open('/home/MWrite/POD_Filter_Mcpu.txt','w')
        file_POD_Filter_latency=open('/home/MWrite/POD_Filter_Mpacket.txt','w')
        file_POD_Filter_mem=open('/home/MWrite/POD_Filter_Mmem.txt','w')
	file_POD_Filter_leg=open('/home/MWrite/POD_Filter_Mlegitimate.txt','w')
        file_POD_Filter_resource=open('/home/MWrite/POD_Filter_Mconnection.txt','w')
        file_POD_Filter_false=open('/home/MWrite/POD_Filter_Mfalsevalue.txt','w')
	file_POD_Filter_RCost=open('/home/MWrite/POD_Filter_MCost.txt','w')

        file_POD_Filter_recovery.write('0.3')
        file_POD_Filter_availability.write('0')
        file_POD_Filter_latency.write('1')
        file_POD_Filter_cost.write('1')
	file_POD_Filter_leg.write('0')
        file_POD_Filter_resource.write('0')
	file_POD_Filter_false.write('1')
	file_POD_Filter_RCost.write('0.2')
        
        #---------POD TrustPlatform----------
        file_POD_Filtering_recovery=open('/home/MWrite/POD_Trust Platform_Mspeed.txt','w')
        file_POD_Filtering_availability=open('/home/MWrite/POD_Trust Platform_Mcpu.txt','w')
        file_POD_Filtering_latency=open('/home/MWrite/POD_Trust Platform_Mpacket.txt','w')
        file_POD_Filtering_mem=open('/home/MWrite/POD_Trust Platform_Mmem.txt','w')
	file_POD_Filtering_leg=open('/home/MWrite/POD_Trust Platform_Mlegitimate.txt','w')
        file_POD_Filtering_resource=open('/home/MWrite/POD_Trust Platform_Mconnection.txt','w')
        file_POD_Filtering_false=open('/home/MWrite/POD_Trust Platform_Mfalsevalue.txt','w')
        file_POD_Filtering_RCost=open('/home/MWrite/POD_Trust Platform_MCost.txt','w')

	file_POD_Filtering_recovery.write('0.2')
        file_POD_Filtering_availability.write('1')
        file_POD_Filtering_latency.write('1')
        file_POD_Filtering_cost.write('1')
	file_POD_Filtering_leg.write('1')
        file_POD_Filtering_resource.write('1')
	file_POD_Filtering_false.write('0')
	file_POD_Filtering_RCost.write('0.2')       
  
 	#-------new added POD Replica-----------
        file_POD_Replica_recovery=open('/home/MWrite/POD_Replica_Mspeed.txt','w')
        file_POD_Replica_availability=open('/home/MWrite/POD_Replica_Mcpu.txt','w')
        file_POD_Replica_latency=open('/home/MWrite/POD_Replica_Mpacket.txt','w')
        file_POD_Replica_mem=open('/home/MWrite/POD_Replica_Mmem.txt','w')
	file_POD_Replica_leg=open('/home/MWrite/POD_Replica_Mlegitimate.txt','w')
        file_POD_Replica_resource=open('/home/MWrite/POD_Replica_Mconnection.txt','w')
        file_POD_Replica_false=open('/home/MWrite/POD_Replica_Mfalsevalue.txt','w')
	file_POD_Replica_RCost=open('/home/MWrite/POD_Replica_MCost.txt','w')        

        file_POD_Replica_recovery.write('0.5')
        file_POD_Replica_availability.write('1')
        file_POD_Replica_latency.write('1')
        file_POD_Replica_cost.write('0')
	file_POD_Replica_leg.write('0')
        file_POD_Replica_resource.write('1')	
        file_POD_Replica_false.write('1')
        file_POD_Replica_RCost.write('1')

	file_POD_Replica_recovery.close()
        file_POD_Replica_availability.close()
        file_POD_Replica_latency.close()
        file_POD_Replica_cost.close()	
        file_POD_Replica_resource.close()
	file_POD_Replica_leg.close()
	file_POD_Replica_false.close()
	file_POD_Replica_RCost.close()
        #----------POD Firewall--------
        file_POD_Firewall_recovery=open('/home/MWrite/POD_Firewall_Mspeed.txt','w')
        file_POD_Firewall_availability=open('/home/MWrite/POD_Firewall_Mcpu.txt','w')
        file_POD_Firewall_latency=open('/home/MWrite/POD_Firewall_Mpacket.txt','w')
        file_POD_Firewall_mem=open('/home/MWrite/POD_Firewall_Mmem.txt','w')
	file_POD_Firewall_leg=open('/home/MWrite/POD_Firewall_Mlegitimate.txt','w')
        file_POD_Firewall_resource=open('/home/MWrite/POD_Firewall_Mconnection.txt','w')
        file_POD_Firewall_false=open('/home/MWrite/POD_Firewall_Mfalsevalue.txt','w')
        file_POD_Firewall_false=open('/home/MWrite/POD_Firewall_Mfalsevalue.txt','w')

        file_POD_Firewall_recovery.write('0')
        file_POD_Firewall_availability.write('1')
        file_POD_Firewall_latency.write('1')
        file_POD_Firewall_cost.write('1')
        file_POD_Firewall_resource.write('1')
	#-------POD network------------
        file_POD_Disconnection_recovery=open('/home/MWrite/POD_Network Disconnection_Mspeed.txt','w')
        file_POD_Disconnection_availability=open('/home/MWrite/POD_Network Disconnection_Mcpu.txt','w')
        file_POD_Disconnection_latency=open('/home/MWrite/POD_Network Disconnection_Mpacket.txt','w')
        file_POD_Disconnection_mem=open('/home/MWrite/POD_Network Disconnection_Mmem.txt','w')
	file_POD_Disconnection_leg=open('/home/MWrite/POD_Network Disconnection_Mlegitimate.txt','w')
        file_POD_Disconnection_resource=open('/home/MWrite/POD_Network Disconnection_Mconnection.txt','w')
        file_POD_Disconnection_false=open('/home/MWrite/POD_Network Disconnection_Mfalsevalue.txt','w')
        file_POD_Disconnection_RCost=open('/home/MWrite/POD_Network Disconnection_MCost.txt','w')

        file_POD_Disconnection_recovery.write('0.2')
        file_POD_Disconnection_availability.write('0')
        file_POD_Disconnection_latency.write('0')
        file_POD_Disconnection_cost.write('1')
	file_POD_Disconnection_leg.write('0')
        file_POD_Disconnection_resource.write('0.5')
	file_POD_Disconnection_false.write('0')
	file_POD_Disconnection_RCost.write('0.5')
        
        #-----POD Host shutdown-------
        file_POD_Shutdown_recovery=open('/home/MWrite/POD_Host Shutdown_Mspeed.txt','w')
        file_POD_Shutdown_availability=open('/home/MWrite/POD_Host Shutdown_Mcpu.txt','w')
        file_POD_Shutdown_latency=open('/home/MWrite/POD_Host Shutdown_Mpacket.txt','w')
        file_POD_Shutdown_mem=open('/home/MWrite/POD_Host Shutdown_Mmem.txt','w')
	file_POD_Shutdown_leg=open('/home/MWrite/POD_Host Shutdown_Mlegitimate.txt','w')
        file_POD_Shutdown_resource=open('/home/MWrite/POD_Host Shutdown_Mconnection.txt','w')
	file_POD_Shutdown_false=open('/home/MWrite/POD_Host Shutdown_Mfalsevalue.txt','w')
	file_POD_Shutdown_RCost=open('/home/MWrite/POD_Host Shutdown_MCost.txt','w')
        file_POD_Shutdown_recovery.write('0.3')
        file_POD_Shutdown_availability.write('0.2')
        file_POD_Shutdown_latency.write('0.2')
        file_POD_Shutdown_cost.write('0')
	file_POD_Shutdown_leg.write('0')
        file_POD_Shutdown_resource.write('0.2')
	file_POD_Shutdown_false.write('1')
	file_POD_Shutdown_RCost.write('0.2')
        
        #--POD Process Termination----------
	file_POD_Terminate_recovery=open('/home/MWrite/POD_Host Terminate_Mspeed.txt','w')
        file_POD_Terminate_availability=open('/home/MWrite/POD_Host Terminate_Mcpu.txt','w')
        file_POD_Terminate_latency=open('/home/MWrite/POD_Host Terminate_Mpacket.txt','w')
        file_POD_Terminate_mem=open('/home/MWrite/POD_Host Terminate_Mmem.txt','w')
	file_POD_Terminate_leg=open('/home/MWrite/POD_Host Terminate_Mlegitimate.txt','w')
        file_POD_Terminate_resource=open('/home/MWrite/POD_Host Terminate_Mconnection.txt','w')
	file_POD_Terminate_false=open('/home/MWrite/POD_Host Terminate_Mfalsevalue.txt','w')
	file_POD_Terminate_RCost=open('/home/MWrite/POD_Host Terminate_MCost.txt','w')

        file_POD_Terminate_recovery.write('0.3')
        file_POD_Terminate_availability.write('0')
        file_POD_Terminate_latency.write('1')
        file_POD_Terminate_cost.write('1')
	file_POD_Terminate_leg.write('0')
        file_POD_Terminate_resource.write('0.5')
	file_POD_Terminate_false.write('0')
	file_POD_Terminate_RCost.write('0.5')
	file_POD_Terminate_false.close()
	file_POD_Terminate_RCost.close()
	file_POD_Terminate_leg.close()
        file_POD_Terminate_recovery.close()
        file_POD_Terminate_availability.close()
        file_POD_Terminate_latency.close()
        file_POD_Terminate_cost.close()
        file_POD_Terminate_resource.close()
	#-----------POD ModSecurity-----------
        file_POD_ModSecurity_recovery=open('/home/MWrite/POD_Host ModSecurity_Mspeed.txt','w')
        file_POD_ModSecurity_availability=open('/home/MWrite/POD_Host ModSecurity_Mcpu.txt','w')
        file_POD_ModSecurity_latency=open('/home/MWrite/POD_Host ModSecurity_Mpacket.txt','w')
        file_POD_ModSecurity_mem=open('/home/MWrite/POD_Host ModSecurity_Mmem.txt','w')
	file_POD_ModSecurity_leg=open('/home/MWrite/POD_Host ModSecurity_Mlegitimate.txt','w')
        file_POD_ModSecurity_resource=open('/home/MWrite/POD_Host ModSecurity_Mconnection.txt','w')
	file_POD_ModSecurity_false=open('/home/MWrite/POD_Host ModSecurity_Mfalsevalue.txt','w')
	file_POD_ModSecurity_RCost=open('/home/MWrite/POD_Host ModSecurity_MCost.txt','w')

        file_POD_ModSecurity_recovery.write('0.3')
        file_POD_ModSecurity_availability.write('0')
        file_POD_ModSecurity_latency.write('1')
        file_POD_ModSecurity_cost.write('1')
	file_POD_ModSecurity_leg.write('0')
        file_POD_ModSecurity_resource.write('0.5')
	file_POD_ModSecurity_false.write('0')
	file_POD_ModSecurity_RCost.write('0.5')
	file_POD_ModSecurity_false.close()
	file_POD_ModSecurity_RCost.close()
	file_POD_ModSecurity_leg.close()
        file_POD_ModSecurity_recovery.close()
        file_POD_ModSecurity_availability.close()
        file_POD_ModSecurity_latency.close()
        file_POD_ModSecurity_cost.close()
        file_POD_ModSecurity_resource.close()
        
        
        file_POD_Shutdown_recovery.close()
        file_POD_Shutdown_availability.close()
        file_POD_Shutdown_latency.close()
        file_POD_Shutdown_cost.close()
        file_POD_Shutdown_resource.close()
        file_POD_Firewall_recovery.close()
        file_POD_Firewall_availability.close()
        file_POD_Firewall_latency.close()
        file_POD_Firewall_cost.close()
        file_POD_Firewall_resource.close()
        file_POD_Filtering_recovery.close()
        file_POD_Filtering_availability.close()
        file_POD_Filtering_latency.close()
        file_POD_Filtering_cost.close()
        file_POD_Filtering_resource.close()
        file_POD_Disconnection_recovery.close()
        file_POD_Disconnection_availability.close()
        file_POD_Disconnection_latency.close()
        file_POD_Disconnection_cost.close()
        file_POD_Disconnection_resource.close()
        file_POD_Filter_recovery.close()
        file_POD_Filter_availability.close()
        file_POD_Filter_latency.close()
        file_POD_Filter_cost.close()
        file_POD_Filter_resource.close()
        file_POD_IPS_recovery.close()
        file_POD_IPS_availability.close()
        file_POD_IPS_latency.close()
        file_POD_IPS_cost.close()
        file_POD_IPS_resource.close()

	file_POD_IPS_false.close()
	file_POD_IPS_leg.close()
	file_POD_IPS_RCost.close()

	file_POD_Filter_false.close()
	file_POD_Filter_leg.close()
	file_POD_Filter_RCost.close()

	file_POD_Disconnection_false.close()
	file_POD_Disconnection_leg.close()
	file_POD_Disconnection_RCost.close()

	file_POD_Filtering_false.close()
	file_POD_Filtering_leg.close()
	file_POD_Filtering_RCost.close()

	file_POD_Firewall_false.close()
	file_POD_Firewall_leg.close()
	file_POD_Firewall_RCost.close()

	file_POD_Shutdown_false.close()
	file_POD_Shutdown_leg.close()
	file_POD_Shutdown_RCost.close()
    #---------SQL---------------
	

	#---------SQL IPS----------
	file_SQL_IPS_recovery=open('/home/MWrite/SQL_IPS_Mspeed.txt','w')
        file_SQL_IPS_availability=open('/home/MWrite/SQL_IPS_Mcpu.txt','w')
        file_SQL_IPS_latency=open('/home/MWrite/SQL_IPS_Mpacket.txt','w')
        file_SQL_IPS_mem=open('/home/MWrite/SQL_IPS_Mmem.txt','w')
        file_SQL_IPS_leg=open('/home/MWrite/SQL_IPS_Mlegitimate.txt','w')#Memory Utilization Recovery	
        file_SQL_IPS_resource=open('/home/MWrite/SQL_IPS_Mconnection.txt','w')        
        file_SQL_IPS_false=open('/home/MWrite/SQL_IPS_Mfalsevalue.txt','w')
	file_SQL_IPS_RCost=open('/home/MWrite/SQL_IPS_MCost.txt','w')
	file_SQL_IPS_recovery.write('0.3')
        file_SQL_IPS_availability.write('0.2')
        file_SQL_IPS_latency.write('0.2')
        file_SQL_IPS_cost.write('1')
	file_SQL_IPS_leg.write('0')
        file_SQL_IPS_resource.write('0.2')
	file_SQL_IPS_false.write('1')
	file_SQL_IPS_RCost.write('0.2')
       #--------SQL Disable port---------
        file_SQL_Filter_recovery=open('/home/MWrite/SQL_Filter_Mspeed.txt','w')
        file_SQL_Filter_availability=open('/home/MWrite/SQL_Filter_Mcpu.txt','w')
        file_SQL_Filter_latency=open('/home/MWrite/SQL_Filter_Mpacket.txt','w')
        file_SQL_Filter_mem=open('/home/MWrite/SQL_Filter_Mmem.txt','w')
	file_SQL_Filter_leg=open('/home/MWrite/SQL_Filter_Mlegitimate.txt','w')
        file_SQL_Filter_resource=open('/home/MWrite/SQL_Filter_Mconnection.txt','w')
        file_SQL_Filter_false=open('/home/MWrite/SQL_Filter_Mfalsevalue.txt','w')
	file_SQL_Filter_RCost=open('/home/MWrite/SQL_Filter_MCost.txt','w')

        file_SQL_Filter_recovery.write('0.3')
        file_SQL_Filter_availability.write('0')
        file_SQL_Filter_latency.write('0')
        file_SQL_Filter_cost.write('1')
	file_SQL_Filter_leg.write('0')
        file_SQL_Filter_resource.write('0')
	file_SQL_Filter_false.write('0')
	file_SQL_Filter_RCost.write('0.2')
        
        #---------SQL TrustPlatform----------
        file_SQL_Filtering_recovery=open('/home/MWrite/SQL_Trust Platform_Mspeed.txt','w')
        file_SQL_Filtering_availability=open('/home/MWrite/SQL_Trust Platform_Mcpu.txt','w')
        file_SQL_Filtering_latency=open('/home/MWrite/SQL_Trust Platform_Mpacket.txt','w')
        file_SQL_Filtering_mem=open('/home/MWrite/SQL_Trust Platform_Mmem.txt','w')
	file_SQL_Filtering_leg=open('/home/MWrite/SQL_Trust Platform_Mlegitimate.txt','w')
        file_SQL_Filtering_resource=open('/home/MWrite/SQL_Trust Platform_Mconnection.txt','w')
        file_SQL_Filtering_false=open('/home/MWrite/SQL_Trust Platform_Mfalsevalue.txt','w')
        file_SQL_Filtering_RCost=open('/home/MWrite/SQL_Trust Platform_MCost.txt','w')

	file_SQL_Filtering_recovery.write('0.2')
        file_SQL_Filtering_availability.write('1')
        file_SQL_Filtering_latency.write('1')
        file_SQL_Filtering_cost.write('0.8')
	file_SQL_Filtering_leg.write('1')
        file_SQL_Filtering_resource.write('0')
	file_SQL_Filtering_false.write('1')
	file_SQL_Filtering_RCost.write('0.2')       
  
 	#-------new added SQL Replica-----------
        file_SQL_Replica_recovery=open('/home/MWrite/SQL_Replica_Mspeed.txt','w')
        file_SQL_Replica_availability=open('/home/MWrite/SQL_Replica_Mcpu.txt','w')
        file_SQL_Replica_latency=open('/home/MWrite/SQL_Replica_Mpacket.txt','w')
        file_SQL_Replica_mem=open('/home/MWrite/SQL_Replica_Mmem.txt','w')
	file_SQL_Replica_leg=open('/home/MWrite/SQL_Replica_Mlegitimate.txt','w')
        file_SQL_Replica_resource=open('/home/MWrite/SQL_Replica_Mconnection.txt','w')
        file_SQL_Replica_false=open('/home/MWrite/SQL_Replica_Mfalsevalue.txt','w')
	file_SQL_Replica_RCost=open('/home/MWrite/SQL_Replica_MCost.txt','w')        

        file_SQL_Replica_recovery.write('0.2')
        file_SQL_Replica_availability.write('1')
        file_SQL_Replica_latency.write('1')
        file_SQL_Replica_cost.write('0.8')
	file_SQL_Replica_leg.write('1')
        file_SQL_Replica_resource.write('0')	
        file_SQL_Replica_false.write('1')
        file_SQL_Replica_RCost.write('0.2')

	file_SQL_Replica_recovery.close()
        file_SQL_Replica_availability.close()
        file_SQL_Replica_latency.close()
        file_SQL_Replica_cost.close()	
        file_SQL_Replica_resource.close()
	file_SQL_Replica_leg.close()
	file_SQL_Replica_false.close()
	file_SQL_Replica_RCost.close()
        #----------SQL Firewall--------
        file_SQL_Firewall_recovery=open('/home/MWrite/SQL_Firewall_Mspeed.txt','w')
        file_SQL_Firewall_availability=open('/home/MWrite/SQL_Firewall_Mcpu.txt','w')
        file_SQL_Firewall_latency=open('/home/MWrite/SQL_Firewall_Mpacket.txt','w')
        file_SQL_Firewall_mem=open('/home/MWrite/SQL_Firewall_Mmem.txt','w')
	file_SQL_Firewall_leg=open('/home/MWrite/SQL_Firewall_Mlegitimate.txt','w')
        file_SQL_Firewall_resource=open('/home/MWrite/SQL_Firewall_Mconnection.txt','w')
        file_SQL_Firewall_false=open('/home/MWrite/SQL_Firewall_Mfalsevalue.txt','w')
        file_SQL_Firewall_false=open('/home/MWrite/SQL_Firewall_Mfalsevalue.txt','w')

        file_SQL_Firewall_recovery.write('0')
        file_SQL_Firewall_availability.write('1')
        file_SQL_Firewall_latency.write('1')
        file_SQL_Firewall_cost.write('1')
        file_SQL_Firewall_resource.write('1')
	#-------SQL network------------
        file_SQL_Disconnection_recovery=open('/home/MWrite/SQL_Network Disconnection_Mspeed.txt','w')
        file_SQL_Disconnection_availability=open('/home/MWrite/SQL_Network Disconnection_Mcpu.txt','w')
        file_SQL_Disconnection_latency=open('/home/MWrite/SQL_Network Disconnection_Mpacket.txt','w')
        file_SQL_Disconnection_mem=open('/home/MWrite/SQL_Network Disconnection_Mmem.txt','w')
	file_SQL_Disconnection_leg=open('/home/MWrite/SQL_Network Disconnection_Mlegitimate.txt','w')
        file_SQL_Disconnection_resource=open('/home/MWrite/SQL_Network Disconnection_Mconnection.txt','w')
        file_SQL_Disconnection_false=open('/home/MWrite/SQL_Network Disconnection_Mfalsevalue.txt','w')
        file_SQL_Disconnection_RCost=open('/home/MWrite/SQL_Network Disconnection_MCost.txt','w')

        file_SQL_Disconnection_recovery.write('0.2')
        file_SQL_Disconnection_availability.write('0')
        file_SQL_Disconnection_latency.write('0')
        file_SQL_Disconnection_cost.write('1')
	file_SQL_Disconnection_leg.write('0')
        file_SQL_Disconnection_resource.write('0.5')
	file_SQL_Disconnection_false.write('0')
	file_SQL_Disconnection_RCost.write('0.5')
        
        #-----SQL Host shutdown-------
        file_SQL_Shutdown_recovery=open('/home/MWrite/SQL_Host Shutdown_Mspeed.txt','w')
        file_SQL_Shutdown_availability=open('/home/MWrite/SQL_Host Shutdown_Mcpu.txt','w')
        file_SQL_Shutdown_latency=open('/home/MWrite/SQL_Host Shutdown_Mpacket.txt','w')
        file_SQL_Shutdown_mem=open('/home/MWrite/SQL_Host Shutdown_Mmem.txt','w')
	file_SQL_Shutdown_leg=open('/home/MWrite/SQL_Host Shutdown_Mlegitimate.txt','w')
        file_SQL_Shutdown_resource=open('/home/MWrite/SQL_Host Shutdown_Mconnection.txt','w')
	file_SQL_Shutdown_false=open('/home/MWrite/SQL_Host Shutdown_Mfalsevalue.txt','w')
	file_SQL_Shutdown_RCost=open('/home/MWrite/SQL_Host Shutdown_MCost.txt','w')
        file_SQL_Shutdown_recovery.write('0.3')
        file_SQL_Shutdown_availability.write('0')
        file_SQL_Shutdown_latency.write('0')
        file_SQL_Shutdown_cost.write('1')
	file_SQL_Shutdown_leg.write('0')
        file_SQL_Shutdown_resource.write('0.5')
	file_SQL_Shutdown_false.write('0')
	file_SQL_Shutdown_RCost.write('0.5')
        
        #--SQL Process Termination----------
	file_SQL_Terminate_recovery=open('/home/MWrite/SQL_Host Terminate_Mspeed.txt','w')
        file_SQL_Terminate_availability=open('/home/MWrite/SQL_Host Terminate_Mcpu.txt','w')
        file_SQL_Terminate_latency=open('/home/MWrite/SQL_Host Terminate_Mpacket.txt','w')
        file_SQL_Terminate_mem=open('/home/MWrite/SQL_Host Terminate_Mmem.txt','w')
	file_SQL_Terminate_leg=open('/home/MWrite/SQL_Host Terminate_Mlegitimate.txt','w')
        file_SQL_Terminate_resource=open('/home/MWrite/SQL_Host Terminate_Mconnection.txt','w')
	file_SQL_Terminate_false=open('/home/MWrite/SQL_Host Terminate_Mfalsevalue.txt','w')
	file_SQL_Terminate_RCost=open('/home/MWrite/SQL_Host Terminate_MCost.txt','w')

        file_SQL_Terminate_recovery.write('0.2')
        file_SQL_Terminate_availability.write('0.6')
        file_SQL_Terminate_latency.write('1')
        file_SQL_Terminate_cost.write('1')
	file_SQL_Terminate_leg.write('0.5')
        file_SQL_Terminate_resource.write('1')
	file_SQL_Terminate_false.write('1')
	file_SQL_Terminate_RCost.write('0.4')
	file_SQL_Terminate_false.close()
	file_SQL_Terminate_RCost.close()
	file_SQL_Terminate_leg.close()
        file_SQL_Terminate_recovery.close()
        file_SQL_Terminate_availability.close()
        file_SQL_Terminate_latency.close()
        file_SQL_Terminate_cost.close()
        file_SQL_Terminate_resource.close()
	#-----------SQL ModSecurity-----------
        file_SQL_ModSecurity_recovery=open('/home/MWrite/SQL_Host ModSecurity_Mspeed.txt','w')
        file_SQL_ModSecurity_availability=open('/home/MWrite/SQL_Host ModSecurity_Mcpu.txt','w')
        file_SQL_ModSecurity_latency=open('/home/MWrite/SQL_Host ModSecurity_Mpacket.txt','w')
        file_SQL_ModSecurity_mem=open('/home/MWrite/SQL_Host ModSecurity_Mmem.txt','w')
	file_SQL_ModSecurity_leg=open('/home/MWrite/SQL_Host ModSecurity_Mlegitimate.txt','w')
        file_SQL_ModSecurity_resource=open('/home/MWrite/SQL_Host ModSecurity_Mconnection.txt','w')
	file_SQL_ModSecurity_false=open('/home/MWrite/SQL_Host ModSecurity_Mfalsevalue.txt','w')
	file_SQL_ModSecurity_RCost=open('/home/MWrite/SQL_Host ModSecurity_MCost.txt','w')

        file_SQL_ModSecurity_recovery.write('0')
        file_SQL_ModSecurity_availability.write('0')
        file_SQL_ModSecurity_latency.write('1')
        file_SQL_ModSecurity_cost.write('0')
	file_SQL_ModSecurity_leg.write('0')
        file_SQL_ModSecurity_resource.write('0.5')
	file_SQL_ModSecurity_false.write('0')
	file_SQL_ModSecurity_RCost.write('0')
	file_SQL_ModSecurity_false.close()
	file_SQL_ModSecurity_RCost.close()
	file_SQL_ModSecurity_leg.close()
        file_SQL_ModSecurity_recovery.close()
        file_SQL_ModSecurity_availability.close()
        file_SQL_ModSecurity_latency.close()
        file_SQL_ModSecurity_cost.close()
        file_SQL_ModSecurity_resource.close()
        
        
        file_SQL_Shutdown_recovery.close()
        file_SQL_Shutdown_availability.close()
        file_SQL_Shutdown_latency.close()
        file_SQL_Shutdown_cost.close()
        file_SQL_Shutdown_resource.close()
        file_SQL_Firewall_recovery.close()
        file_SQL_Firewall_availability.close()
        file_SQL_Firewall_latency.close()
        file_SQL_Firewall_cost.close()
        file_SQL_Firewall_resource.close()
        file_SQL_Filtering_recovery.close()
        file_SQL_Filtering_availability.close()
        file_SQL_Filtering_latency.close()
        file_SQL_Filtering_cost.close()
        file_SQL_Filtering_resource.close()
        file_SQL_Disconnection_recovery.close()
        file_SQL_Disconnection_availability.close()
        file_SQL_Disconnection_latency.close()
        file_SQL_Disconnection_cost.close()
        file_SQL_Disconnection_resource.close()
        file_SQL_Filter_recovery.close()
        file_SQL_Filter_availability.close()
        file_SQL_Filter_latency.close()
        file_SQL_Filter_cost.close()
        file_SQL_Filter_resource.close()
        file_SQL_IPS_recovery.close()
        file_SQL_IPS_availability.close()
        file_SQL_IPS_latency.close()
        file_SQL_IPS_cost.close()
        file_SQL_IPS_resource.close()

	file_SQL_IPS_false.close()
	file_SQL_IPS_leg.close()
	file_SQL_IPS_RCost.close()

	file_SQL_Filter_false.close()
	file_SQL_Filter_leg.close()
	file_SQL_Filter_RCost.close()

	file_SQL_Disconnection_false.close()
	file_SQL_Disconnection_leg.close()
	file_SQL_Disconnection_RCost.close()

	file_SQL_Filtering_false.close()
	file_SQL_Filtering_leg.close()
	file_SQL_Filtering_RCost.close()

	file_SQL_Firewall_false.close()
	file_SQL_Firewall_leg.close()
	file_SQL_Firewall_RCost.close()

	file_SQL_Shutdown_false.close()
	file_SQL_Shutdown_leg.close()
	file_SQL_Shutdown_RCost.close()
	#---------Exhaustion------
	

	#---------Exhaustion IPS----------
	file_Exhaustion_IPS_recovery=open('/home/MWrite/Exhaustion_IPS_Mspeed.txt','w')
        file_Exhaustion_IPS_availability=open('/home/MWrite/Exhaustion_IPS_Mcpu.txt','w')
        file_Exhaustion_IPS_latency=open('/home/MWrite/Exhaustion_IPS_Mpacket.txt','w')
        file_Exhaustion_IPS_mem=open('/home/MWrite/Exhaustion_IPS_Mmem.txt','w')
        file_Exhaustion_IPS_leg=open('/home/MWrite/Exhaustion_IPS_Mlegitimate.txt','w')#Memory Utilization Recovery	
        file_Exhaustion_IPS_resource=open('/home/MWrite/Exhaustion_IPS_Mconnection.txt','w')        
        file_Exhaustion_IPS_false=open('/home/MWrite/Exhaustion_IPS_Mfalsevalue.txt','w')
	file_Exhaustion_IPS_RCost=open('/home/MWrite/Exhaustion_IPS_MCost.txt','w')
	file_Exhaustion_IPS_recovery.write('0.3')
        file_Exhaustion_IPS_availability.write('0.2')
        file_Exhaustion_IPS_latency.write('0.2')
        file_Exhaustion_IPS_cost.write('0')
	file_Exhaustion_IPS_leg.write('0')
        file_Exhaustion_IPS_resource.write('0.2')
	file_Exhaustion_IPS_false.write('1')
	file_Exhaustion_IPS_RCost.write('0.2')
       #--------Exhaustion Disable port---------
        file_Exhaustion_Filter_recovery=open('/home/MWrite/Exhaustion_Filter_Mspeed.txt','w')
        file_Exhaustion_Filter_availability=open('/home/MWrite/Exhaustion_Filter_Mcpu.txt','w')
        file_Exhaustion_Filter_latency=open('/home/MWrite/Exhaustion_Filter_Mpacket.txt','w')
        file_Exhaustion_Filter_mem=open('/home/MWrite/Exhaustion_Filter_Mmem.txt','w')
	file_Exhaustion_Filter_leg=open('/home/MWrite/Exhaustion_Filter_Mlegitimate.txt','w')
        file_Exhaustion_Filter_resource=open('/home/MWrite/Exhaustion_Filter_Mconnection.txt','w')
        file_Exhaustion_Filter_false=open('/home/MWrite/Exhaustion_Filter_Mfalsevalue.txt','w')
	file_Exhaustion_Filter_RCost=open('/home/MWrite/Exhaustion_Filter_MCost.txt','w')

        file_Exhaustion_Filter_recovery.write('0.3')
        file_Exhaustion_Filter_availability.write('0')
        file_Exhaustion_Filter_latency.write('1')
        file_Exhaustion_Filter_cost.write('1')
	file_Exhaustion_Filter_leg.write('0')
        file_Exhaustion_Filter_resource.write('0')
	file_Exhaustion_Filter_false.write('1')
	file_Exhaustion_Filter_RCost.write('0.2')
        
        #---------Exhaustion TrustPlatform----------
        file_Exhaustion_Filtering_recovery=open('/home/MWrite/Exhaustion_Trust Platform_Mspeed.txt','w')
        file_Exhaustion_Filtering_availability=open('/home/MWrite/Exhaustion_Trust Platform_Mcpu.txt','w')
        file_Exhaustion_Filtering_latency=open('/home/MWrite/Exhaustion_Trust Platform_Mpacket.txt','w')
        file_Exhaustion_Filtering_mem=open('/home/MWrite/Exhaustion_Trust Platform_Mmem.txt','w')
	file_Exhaustion_Filtering_leg=open('/home/MWrite/Exhaustion_Trust Platform_Mlegitimate.txt','w')
        file_Exhaustion_Filtering_resource=open('/home/MWrite/Exhaustion_Trust Platform_Mconnection.txt','w')
        file_Exhaustion_Filtering_false=open('/home/MWrite/Exhaustion_Trust Platform_Mfalsevalue.txt','w')
        file_Exhaustion_Filtering_RCost=open('/home/MWrite/Exhaustion_Trust Platform_MCost.txt','w')

	file_Exhaustion_Filtering_recovery.write('0.2')
        file_Exhaustion_Filtering_availability.write('1')
        file_Exhaustion_Filtering_latency.write('1')
        file_Exhaustion_Filtering_cost.write('1')
	file_Exhaustion_Filtering_leg.write('1')
        file_Exhaustion_Filtering_resource.write('1')
	file_Exhaustion_Filtering_false.write('0')
	file_Exhaustion_Filtering_RCost.write('0.2')       
  
 	#-------new added Exhaustion Replica-----------
        file_Exhaustion_Replica_recovery=open('/home/MWrite/Exhaustion_Replica_Mspeed.txt','w')
        file_Exhaustion_Replica_availability=open('/home/MWrite/Exhaustion_Replica_Mcpu.txt','w')
        file_Exhaustion_Replica_latency=open('/home/MWrite/Exhaustion_Replica_Mpacket.txt','w')
        file_Exhaustion_Replica_mem=open('/home/MWrite/Exhaustion_Replica_Mmem.txt','w')
	file_Exhaustion_Replica_leg=open('/home/MWrite/Exhaustion_Replica_Mlegitimate.txt','w')
        file_Exhaustion_Replica_resource=open('/home/MWrite/Exhaustion_Replica_Mconnection.txt','w')
        file_Exhaustion_Replica_false=open('/home/MWrite/Exhaustion_Replica_Mfalsevalue.txt','w')
	file_Exhaustion_Replica_RCost=open('/home/MWrite/Exhaustion_Replica_MCost.txt','w')        

        file_Exhaustion_Replica_recovery.write('0.5')
        file_Exhaustion_Replica_availability.write('1')
        file_Exhaustion_Replica_latency.write('1')
        file_Exhaustion_Replica_cost.write('0')
	file_Exhaustion_Replica_leg.write('0')
        file_Exhaustion_Replica_resource.write('1')	
        file_Exhaustion_Replica_false.write('1')
        file_Exhaustion_Replica_RCost.write('1')

	file_Exhaustion_Replica_recovery.close()
        file_Exhaustion_Replica_availability.close()
        file_Exhaustion_Replica_latency.close()
        file_Exhaustion_Replica_cost.close()	
        file_Exhaustion_Replica_resource.close()
	file_Exhaustion_Replica_leg.close()
	file_Exhaustion_Replica_false.close()
	file_Exhaustion_Replica_RCost.close()
        #----------Exhaustion Firewall--------
        file_Exhaustion_Firewall_recovery=open('/home/MWrite/Exhaustion_Firewall_Mspeed.txt','w')
        file_Exhaustion_Firewall_availability=open('/home/MWrite/Exhaustion_Firewall_Mcpu.txt','w')
        file_Exhaustion_Firewall_latency=open('/home/MWrite/Exhaustion_Firewall_Mpacket.txt','w')
        file_Exhaustion_Firewall_mem=open('/home/MWrite/Exhaustion_Firewall_Mmem.txt','w')
	file_Exhaustion_Firewall_leg=open('/home/MWrite/Exhaustion_Firewall_Mlegitimate.txt','w')
        file_Exhaustion_Firewall_resource=open('/home/MWrite/Exhaustion_Firewall_Mconnection.txt','w')
        file_Exhaustion_Firewall_false=open('/home/MWrite/Exhaustion_Firewall_Mfalsevalue.txt','w')
        file_Exhaustion_Firewall_false=open('/home/MWrite/Exhaustion_Firewall_Mfalsevalue.txt','w')

        file_Exhaustion_Firewall_recovery.write('0')
        file_Exhaustion_Firewall_availability.write('1')
        file_Exhaustion_Firewall_latency.write('1')
        file_Exhaustion_Firewall_cost.write('1')
        file_Exhaustion_Firewall_resource.write('1')
	#-------Exhaustion network------------
        file_Exhaustion_Disconnection_recovery=open('/home/MWrite/Exhaustion_Network Disconnection_Mspeed.txt','w')
        file_Exhaustion_Disconnection_availability=open('/home/MWrite/Exhaustion_Network Disconnection_Mcpu.txt','w')
        file_Exhaustion_Disconnection_latency=open('/home/MWrite/Exhaustion_Network Disconnection_Mpacket.txt','w')
        file_Exhaustion_Disconnection_mem=open('/home/MWrite/Exhaustion_Network Disconnection_Mmem.txt','w')
	file_Exhaustion_Disconnection_leg=open('/home/MWrite/Exhaustion_Network Disconnection_Mlegitimate.txt','w')
        file_Exhaustion_Disconnection_resource=open('/home/MWrite/Exhaustion_Network Disconnection_Mconnection.txt','w')
        file_Exhaustion_Disconnection_false=open('/home/MWrite/Exhaustion_Network Disconnection_Mfalsevalue.txt','w')
        file_Exhaustion_Disconnection_RCost=open('/home/MWrite/Exhaustion_Network Disconnection_MCost.txt','w')

        file_Exhaustion_Disconnection_recovery.write('0.2')
        file_Exhaustion_Disconnection_availability.write('0')
        file_Exhaustion_Disconnection_latency.write('0')
        file_Exhaustion_Disconnection_cost.write('1')
	file_Exhaustion_Disconnection_leg.write('0')
        file_Exhaustion_Disconnection_resource.write('0.5')
	file_Exhaustion_Disconnection_false.write('0')
	file_Exhaustion_Disconnection_RCost.write('0.5')
        
        #-----Exhaustion Host shutdown-------
        file_Exhaustion_Shutdown_recovery=open('/home/MWrite/Exhaustion_Host Shutdown_Mspeed.txt','w')
        file_Exhaustion_Shutdown_availability=open('/home/MWrite/Exhaustion_Host Shutdown_Mcpu.txt','w')
        file_Exhaustion_Shutdown_latency=open('/home/MWrite/Exhaustion_Host Shutdown_Mpacket.txt','w')
        file_Exhaustion_Shutdown_mem=open('/home/MWrite/Exhaustion_Host Shutdown_Mmem.txt','w')
	file_Exhaustion_Shutdown_leg=open('/home/MWrite/Exhaustion_Host Shutdown_Mlegitimate.txt','w')
        file_Exhaustion_Shutdown_resource=open('/home/MWrite/Exhaustion_Host Shutdown_Mconnection.txt','w')
	file_Exhaustion_Shutdown_false=open('/home/MWrite/Exhaustion_Host Shutdown_Mfalsevalue.txt','w')
	file_Exhaustion_Shutdown_RCost=open('/home/MWrite/Exhaustion_Host Shutdown_MCost.txt','w')
        file_Exhaustion_Shutdown_recovery.write('0.3')
        file_Exhaustion_Shutdown_availability.write('0.2')
        file_Exhaustion_Shutdown_latency.write('0.2')
        file_Exhaustion_Shutdown_cost.write('0')
	file_Exhaustion_Shutdown_leg.write('0')
        file_Exhaustion_Shutdown_resource.write('0.2')
	file_Exhaustion_Shutdown_false.write('1')
	file_Exhaustion_Shutdown_RCost.write('0.2')
        
        #--Exhaustion Process Termination----------
	file_Exhaustion_Terminate_recovery=open('/home/MWrite/Exhaustion_Host Terminate_Mspeed.txt','w')
        file_Exhaustion_Terminate_availability=open('/home/MWrite/Exhaustion_Host Terminate_Mcpu.txt','w')
        file_Exhaustion_Terminate_latency=open('/home/MWrite/Exhaustion_Host Terminate_Mpacket.txt','w')
        file_Exhaustion_Terminate_mem=open('/home/MWrite/Exhaustion_Host Terminate_Mmem.txt','w')
	file_Exhaustion_Terminate_leg=open('/home/MWrite/Exhaustion_Host Terminate_Mlegitimate.txt','w')
        file_Exhaustion_Terminate_resource=open('/home/MWrite/Exhaustion_Host Terminate_Mconnection.txt','w')
	file_Exhaustion_Terminate_false=open('/home/MWrite/Exhaustion_Host Terminate_Mfalsevalue.txt','w')
	file_Exhaustion_Terminate_RCost=open('/home/MWrite/Exhaustion_Host Terminate_MCost.txt','w')

        file_Exhaustion_Terminate_recovery.write('0.3')
        file_Exhaustion_Terminate_availability.write('0')
        file_Exhaustion_Terminate_latency.write('1')
        file_Exhaustion_Terminate_cost.write('1')
	file_Exhaustion_Terminate_leg.write('0')
        file_Exhaustion_Terminate_resource.write('0.5')
	file_Exhaustion_Terminate_false.write('0')
	file_Exhaustion_Terminate_RCost.write('0.5')
	file_Exhaustion_Terminate_false.close()
	file_Exhaustion_Terminate_RCost.close()
	file_Exhaustion_Terminate_leg.close()
        file_Exhaustion_Terminate_recovery.close()
        file_Exhaustion_Terminate_availability.close()
        file_Exhaustion_Terminate_latency.close()
        file_Exhaustion_Terminate_cost.close()
        file_Exhaustion_Terminate_resource.close()
	#-----------Exhaustion ModSecurity-----------
        file_Exhaustion_ModSecurity_recovery=open('/home/MWrite/Exhaustion_Host ModSecurity_Mspeed.txt','w')
        file_Exhaustion_ModSecurity_availability=open('/home/MWrite/Exhaustion_Host ModSecurity_Mcpu.txt','w')
        file_Exhaustion_ModSecurity_latency=open('/home/MWrite/Exhaustion_Host ModSecurity_Mpacket.txt','w')
        file_Exhaustion_ModSecurity_mem=open('/home/MWrite/Exhaustion_Host ModSecurity_Mmem.txt','w')
	file_Exhaustion_ModSecurity_leg=open('/home/MWrite/Exhaustion_Host ModSecurity_Mlegitimate.txt','w')
        file_Exhaustion_ModSecurity_resource=open('/home/MWrite/Exhaustion_Host ModSecurity_Mconnection.txt','w')
	file_Exhaustion_ModSecurity_false=open('/home/MWrite/Exhaustion_Host ModSecurity_Mfalsevalue.txt','w')
	file_Exhaustion_ModSecurity_RCost=open('/home/MWrite/Exhaustion_Host ModSecurity_MCost.txt','w')

        file_Exhaustion_ModSecurity_recovery.write('0.3')
        file_Exhaustion_ModSecurity_availability.write('0')
        file_Exhaustion_ModSecurity_latency.write('1')
        file_Exhaustion_ModSecurity_cost.write('1')
	file_Exhaustion_ModSecurity_leg.write('0')
        file_Exhaustion_ModSecurity_resource.write('0.5')
	file_Exhaustion_ModSecurity_false.write('0')
	file_Exhaustion_ModSecurity_RCost.write('0.5')
	file_Exhaustion_ModSecurity_false.close()
	file_Exhaustion_ModSecurity_RCost.close()
	file_Exhaustion_ModSecurity_leg.close()
        file_Exhaustion_ModSecurity_recovery.close()
        file_Exhaustion_ModSecurity_availability.close()
        file_Exhaustion_ModSecurity_latency.close()
        file_Exhaustion_ModSecurity_cost.close()
        file_Exhaustion_ModSecurity_resource.close()
        
        
        file_Exhaustion_Shutdown_recovery.close()
        file_Exhaustion_Shutdown_availability.close()
        file_Exhaustion_Shutdown_latency.close()
        file_Exhaustion_Shutdown_cost.close()
        file_Exhaustion_Shutdown_resource.close()
        file_Exhaustion_Firewall_recovery.close()
        file_Exhaustion_Firewall_availability.close()
        file_Exhaustion_Firewall_latency.close()
        file_Exhaustion_Firewall_cost.close()
        file_Exhaustion_Firewall_resource.close()
        file_Exhaustion_Filtering_recovery.close()
        file_Exhaustion_Filtering_availability.close()
        file_Exhaustion_Filtering_latency.close()
        file_Exhaustion_Filtering_cost.close()
        file_Exhaustion_Filtering_resource.close()
        file_Exhaustion_Disconnection_recovery.close()
        file_Exhaustion_Disconnection_availability.close()
        file_Exhaustion_Disconnection_latency.close()
        file_Exhaustion_Disconnection_cost.close()
        file_Exhaustion_Disconnection_resource.close()
        file_Exhaustion_Filter_recovery.close()
        file_Exhaustion_Filter_availability.close()
        file_Exhaustion_Filter_latency.close()
        file_Exhaustion_Filter_cost.close()
        file_Exhaustion_Filter_resource.close()
        file_Exhaustion_IPS_recovery.close()
        file_Exhaustion_IPS_availability.close()
        file_Exhaustion_IPS_latency.close()
        file_Exhaustion_IPS_cost.close()
        file_Exhaustion_IPS_resource.close()

	file_Exhaustion_IPS_false.close()
	file_Exhaustion_IPS_leg.close()
	file_Exhaustion_IPS_RCost.close()

	file_Exhaustion_Filter_false.close()
	file_Exhaustion_Filter_leg.close()
	file_Exhaustion_Filter_RCost.close()

	file_Exhaustion_Disconnection_false.close()
	file_Exhaustion_Disconnection_leg.close()
	file_Exhaustion_Disconnection_RCost.close()

	file_Exhaustion_Filtering_false.close()
	file_Exhaustion_Filtering_leg.close()
	file_Exhaustion_Filtering_RCost.close()

	file_Exhaustion_Firewall_false.close()
	file_Exhaustion_Firewall_leg.close()
	file_Exhaustion_Firewall_RCost.close()

	file_Exhaustion_Shutdown_false.close()
	file_Exhaustion_Shutdown_leg.close()
	file_Exhaustion_Shutdown_RCost.close()
    #---------Reset TOTALSCOR-----------------
        file_UDP_IPS_score=open('/home/MWrite/UDP_IPS_totalscore.txt','w')
        file_UDP_IPS_score.write('0.5')
        file_UDP_IPS_score.close()
        file_UDP_Filter_score=open('/home/MWrite/UDP_Filter_totalscore.txt','w')
        file_UDP_Filter_score.write('1.8')
        file_UDP_Filter_score.close()
        
        file_UDP_Filtering_score=open('/home/MWrite/UDP_Trust Platform_totalscore.txt','w')
        file_UDP_Filtering_score.write('3.3')
        file_UDP_Filtering_score.close()
        
        file_UDP_Disconnection_score=open('/home/MWrite/UDP_Network Disconnection_totalscore.txt','w')
        file_UDP_Disconnection_score.write('3.3')
        file_UDP_Disconnection_score.close()
        
        file_UDP_Firewall_score=open('/home/MWrite/UDP_Firewall_totalscore.txt','w')
        file_UDP_Firewall_score.write('2.1')
        file_UDP_Firewall_score.close()
        
        file_UDP_Shutdown_score=open('/home/MWrite/UDP_Host Shutdown_totalscore.txt','w')
        file_UDP_Shutdown_score.write('3.1')
        file_UDP_Shutdown_score.close()
        
        
        file_TCP_SYN_IPS_score=open('/home/MWrite/TCP_SYN_IPS_totalscore.txt','w')
        file_TCP_SYN_IPS_score.write('3.3')
        file_TCP_SYN_IPS_score.close()
        file_TCP_SYN_Filter_score=open('/home/MWrite/TCP_SYN_Filter_totalscore.txt','w')
        file_TCP_SYN_Filter_score.write('1.5')
        file_TCP_SYN_Filter_score.close()
        
        file_TCP_SYN_Filtering_score=open('/home/MWrite/TCP_SYN_Trust Platform_totalscore.txt','w')
        file_TCP_SYN_Filtering_score.write('3.3')
        file_TCP_SYN_Filtering_score.close()
        file_TCP_SYN_Disconnection_score=open('/home/MWrite/TCP_SYN_Network Disconnection_totalscore.txt','w')
        file_TCP_SYN_Disconnection_score.write('3.3')
        file_TCP_SYN_Disconnection_score.close()
        
        file_TCP_SYN_Firewall_score=open('/home/MWrite/TCP_SYN_Firewall_totalscore.txt','w')
        file_TCP_SYN_Firewall_score.write('3.1')
        file_TCP_SYN_Firewall_score.close()
        
        file_TCP_SYN_Shutdown_score=open('/home/MWrite/TCP_SYN_Host Shutdown_totalscore.txt','w')
        file_TCP_SYN_Shutdown_score.write('3.1')
        file_TCP_SYN_Shutdown_score.close()

        
        file_ICMP_IPS_score=open('/home/MWrite/ICMP_IPS_totalscore.txt','w')
        file_ICMP_IPS_score.write('0.5')
        file_ICMP_IPS_score.close()
        file_ICMP_Filter_score=open('/home/MWrite/ICMP_Filter_totalscore.txt','w')
        file_ICMP_Filter_score.write('1.8')
        file_ICMP_Filter_score.close()
        
        file_ICMP_Filtering_score=open('/home/MWrite/ICMP_Trust Platform_totalscore.txt','w')
        file_ICMP_Filtering_score.write('3.3')
        file_ICMP_Filtering_score.close()
        
        file_ICMP_Disconnection_score=open('/home/MWrite/ICMP_Network Disconnection_totalscore.txt','w')
        file_ICMP_Disconnection_score.write('3.3')
        file_ICMP_Disconnection_score.close()
        
        file_ICMP_Firewall_score=open('/home/MWrite/ICMP_Firewall_totalscore.txt','w')
        file_ICMP_Firewall_score.write('2.1')
        file_ICMP_Firewall_score.close()
        
        file_ICMP_Shutdown_score=open('/home/MWrite/ICMP_Host Shutdown_totalscore.txt','w')
        file_ICMP_Shutdown_score.write('3.1')
        file_ICMP_Shutdown_score.close()
        file_POD_IPS_score=open('/home/MWrite/POD_IPS_totalscore.txt','w')
        file_POD_IPS_score.write('0.5')
        file_POD_IPS_score.close()
        file_POD_Filter_score=open('/home/MWrite/POD_Filter_totalscore.txt','w')
        file_POD_Filter_score.write('1.8')
        file_POD_Filter_score.close()
        
        file_POD_Filtering_score=open('/home/MWrite/POD_Trust Platform_totalscore.txt','w')
        file_POD_Filtering_score.write('3.3')
        file_POD_Filtering_score.close()
        
        file_POD_Disconnection_score=open('/home/MWrite/POD_Network Disconnection_totalscore.txt','w')
        file_POD_Disconnection_score.write('3.3')
        file_POD_Disconnection_score.close()
        
        file_POD_Firewall_score=open('/home/MWrite/POD_Firewall_totalscore.txt','w')
        file_POD_Firewall_score.write('2.1')
        file_POD_Firewall_score.close()
        
        file_POD_Shutdown_score=open('/home/MWrite/POD_Host Shutdown_totalscore.txt','w')
        file_POD_Shutdown_score.write('3.1')
        file_POD_Shutdown_score.close()

	#----------Add some more Termination and Modsecurity-----------
	file_UDP_Termination_score=open('/home/MWrite/UDP_Host Termination_totalscore.txt','w')
        file_UDP_Termination_score.write('3.1')
        file_UDP_Termination_score.close()

	file_UDP_ModSecurity_score=open('/home/MWrite/UDP_Host ModSecurity_totalscore.txt','w')
        file_UDP_ModSecurity_score.write('3.1')
        file_UDP_ModSecurity_score.close()
	file_TCP_SYN_Termination_score=open('/home/MWrite/TCP_SYN_Host Termination_totalscore.txt','w')
        file_TCP_SYN_Termination_score.write('3.1')
        file_TCP_SYN_Termination_score.close()

	file_TCP_SYN_ModSecurity_score=open('/home/MWrite/TCP_SYN_Host ModSecurity_totalscore.txt','w')
        file_TCP_SYN_ModSecurity_score.write('3.1')
        file_TCP_SYN_ModSecurity_score.close()
	file_ICMP_Termination_score=open('/home/MWrite/ICMP_Host Termination_totalscore.txt','w')
        file_ICMP_Termination_score.write('3.1')
        file_ICMP_Termination_score.close()

	file_ICMP_ModSecurity_score=open('/home/MWrite/ICMP_Host ModSecurity_totalscore.txt','w')
        file_ICMP_ModSecurity_score.write('3.1')
        file_ICMP_ModSecurity_score.close()
	file_POD_Termination_score=open('/home/MWrite/POD_Host Termination_totalscore.txt','w')
        file_POD_Termination_score.write('3.1')
        file_POD_Termination_score.close()

	file_POD_ModSecurity_score=open('/home/MWrite/POD_Host ModSecurity_totalscore.txt','w')
        file_POD_ModSecurity_score.write('3.1')
        file_POD_ModSecurity_score.close()
	file_Exhaustion_Termination_score=open('/home/MWrite/Exhaustion_Host Termination_totalscore.txt','w')
        file_Exhaustion_Termination_score.write('3.1')
        file_Exhaustion_Termination_score.close()

	file_Exhaustion_ModSecurity_score=open('/home/MWrite/Exhaustion_Host ModSecurity_totalscore.txt','w')
        file_Exhaustion_ModSecurity_score.write('3.1')
        file_Exhaustion_ModSecurity_score.close()
	file_SQL_Termination_score=open('/home/MWrite/SQL_Host Termination_totalscore.txt','w')
        file_SQL_Termination_score.write('3.1')
        file_SQL_Termination_score.close()

	file_SQL_ModSecurity_score=open('/home/MWrite/SQL_Host ModSecurity_totalscore.txt','w')
        file_SQL_ModSecurity_score.write('3.1')
        file_SQL_ModSecurity_score.close()
    
    #-------------GUI -- Check which attack is selected,get Ranking of protected methods for the specific attack (right panel of Controller) 
    def Ranking(self):    
        fopen=open('/home/MWrite/Mattacktype.txt','r') #GUI for checking the selected attack and then set the values of 8 aspects for specific attack.
        attack=fopen.readline()
        #type (attack)
        return str(attack)
    
    #-------------Check which method is chosen--------------------
    def ProtectMethod(self):
            fopen=open('/home/MWrite/Mmethodtype.txt','r')
            ProtectM=fopen.readline()
        #type (ProtectM)
            return str(ProtectM)
    
    #-------------Calcultate the score for the attack (weight*value)-----------------
    
    def Multicriteria(self,attack):
		
        multi_file="/home/MWrite/"+attack
        
	Speed_function=multi_file+'_Speed_MCriteria.txt'
	CPU_function=multi_file+'_CPU_MCriteria.txt'
	Packet_function=multi_file+'_Packet_MCriteria.txt'
	Data_function=multi_file+'_Data_MCriteria.txt'
	#Loss_function=multi_file+'_Loss_MCriteria.txt'
	Connection_function=multi_file+'_Connection_MCriteria.txt'
	Login_function=multi_file+'_Login_MCriteria.txt'
	Mem_function=multi_file+'_Mem_MCriteria.txt'
	Cost_function=multi_file+'_Cost_MCriteria.txt'

	Speed_Weight=multi_file+'_SpeedWeight.txt'
        CPU_Weight=multi_file+'_CPUWeight.txt'
        Packet_Weight=multi_file+'_PacketWeight.txt'
        Data_Weight=multi_file+'_DataWeight.txt'
        Loss_Weight=multi_file+'_LossWeight.txt'
	Connection_Weight=multi_file+'_ConnectionWeight.txt'
	Login_Weight=multi_file+'_LoginWeight.txt'
	Cost_Weight=multi_file+'_CostWeight.txt'
        

        Criteria_path1=os.path.isfile(Speed_function)
	Criteria_path2=os.path.isfile(CPU_function)
	Criteria_path3=os.path.isfile(Packet_function)
	Criteria_path4=os.path.isfile(Data_function)
	Criteria_path5=os.path.isfile(Loss_function)
	Criteria_path6=os.path.isfile(Connection_function)
	Criteria_path7=os.path.isfile(Login_function)
	Criteria_path8=os.path.isfile(Cost_function)
	Weight_path1=os.path.isfile(Speed_Weight)
        Weight_path2=os.path.isfile(CPU_Weight)
        Weight_path3=os.path.isfile(Packet_Weight)
        Weight_path4=os.path.isfile(Data_Weight)
        Weight_path5=os.path.isfile(Loss_Weight)
	Weight_path6=os.path.isfile(Connection_Weight)
	Weight_path7=os.path.isfile(Login_Weight)
	Weight_path8=os.path.isfile(Cost_Weight)
        #----------Read Default/Initial Data from saved file for example: attack_IPS_Speed.txt  -----
	
        #AttackList=['UDP','TCP_SYN','ICMP','POD','SQL','Exhaustion']
        ProtectionList=['IPS','Filter','Trust Platform','Replica','Network Disconnection','Host Shutdown','Terminate','ModSecurity']
        #NewList=['SpeedList','CPUList','PacketList','DataList','ConnectionList','LoginList','MemList','CostList']
        SmallList=['Mspeed','Mpacket','Mcpu','Mconnection','Mfalsevalue','Mlegitimate','Mmem','MCost']  #Mfalsevalue LoginList /Mlegitimate lossList
        BoolTest=True
        #for attackname in range (0,len(AttackList)):
        #attack='UDP'
        #multi_file='/home/MWrite/'+attack
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
        DataList=OverallList[6] #Mmem
        CostList=OverallList[7]
        #print OverallList        
       #--------------------------------------------------------------
            
            
            
         
        SpeedPair=[[0 for x in xrange(8)] for x in xrange(8)]
        CPUPair=[[0 for x in xrange(8)] for x in xrange(8)]
        PacketPair=[[0 for x in xrange(8)] for x in xrange(8)]
	ConnectionPair=[[0 for x in xrange(8)] for x in xrange(8)]        #8 hai kyuki shayad wo 8 hai iske paas
	LoginPair=[[0 for x in xrange(8)] for x in xrange(8)]
        LossPair=[[0 for x in xrange(8)] for x in xrange(8)]
        DataPair=[[0 for x in xrange(8)] for x in xrange(8)]
        CostPair=[[0 for x in xrange(8)] for x in xrange(8)]

        Listlen=len(SpeedList)
        for i in range (0,Listlen):
            for j in range (0, Listlen):#shayad speedpair array hai
                if (i==j):
                    SpeedPair[i][j]='NaN'
                else:
                    subtraction=SpeedList[j]-SpeedList[i]
                    SpeedPair[i][j]=subtraction
        for i in range (0,Listlen):
            for j in range (0, Listlen):
                if (i==j):
                    CPUPair[i][j]='NaN'
                else:
                    CPUsubtraction=CPUList[j]-CPUList[i]
                    CPUPair[i][j]=CPUsubtraction  
	for i in range (0,Listlen):
            for j in range (0, Listlen):
                if (i==j):
                    PacketPair[i][j]='NaN'
                else:
                    Packetsubtraction=PacketList[j]-PacketList[i]
                    PacketPair[i][j]=Packetsubtraction
	for i in range (0,Listlen):
            for j in range (0, Listlen):
                if (i==j):
                    DataPair[i][j]='NaN'
                else:
                    Datasubtraction=DataList[j]-DataList[i]
                    DataPair[i][j]=Datasubtraction  
	for i in range (0,Listlen):
            for j in range (0, Listlen):
                if (i==j):
                    LossPair[i][j]='NaN'
                else:
                    Losssubtraction=LossList[j]-LossList[i]
                    LossPair[i][j]=Losssubtraction #sab mai j ko i se minus kar de rahe hai  
	for i in range (0,Listlen):
            for j in range (0, Listlen):
                if (i==j):
                    ConnectionPair[i][j]='NaN'
                else:
                    Connectionsubtraction=ConnectionList[j]-ConnectionList[i]
                    ConnectionPair[i][j]=Connectionsubtraction  
	for i in range (0,Listlen):
            for j in range (0, Listlen):
                if (i==j):
                    LoginPair[i][j]='NaN'
                else:
                    Loginsubtraction=LoginList[j]-LoginList[i]
                    LoginPair[i][j]=Loginsubtraction 
	for i in range (0,Listlen):
            for j in range (0, Listlen):
                if (i==j):
                    CostPair[i][j]='NaN'
                else:
                    Costsubtraction=CostList[j]-CostList[i]
                    CostPair[i][j]=Costsubtraction  
	         
        ##print "SpeedPair is "
##	print SpeedPair
####	print "-----------------------"
##	print CPUPair
##	print "-----------------------"
##	print PacketPair
##	print "-----------------------"
##	print DataPair
##	print "-----------------------"
##	print LossPair
##	print "-----------------------"
##	print ConnectionPair
##	print "-----------------------"
##	print LoginPair
	if((Criteria_path1==True) and (Criteria_path2==True) and (Criteria_path3==True) and (Criteria_path4==True) and (Criteria_path5==True) and (Criteria_path6==True) and (Criteria_path7==True)and (Criteria_path8==True)):
	    FileOpen1=open(Speed_function,'r')
            FileSpeed=FileOpen1.readline()
            FileOpen2=open(CPU_function,'r')
            FileCPU=FileOpen2.readline()
	    FileOpen3=open(Packet_function,'r')
            FilePacket=FileOpen3.readline()
	    FileOpen4=open(Data_function,'r')
            FileData=FileOpen4.readline()
	    FileOpen5=open(Loss_function,'r')
            FileLoss=FileOpen5.readline()
	    FileOpen6=open(Connection_function,'r')
            FileConnection=FileOpen6.readline()
            FileOpen7=open(Login_function,'r')
            FileLogin=FileOpen7.readline()
	    FileOpen8=open(Cost_function,'r')
            FileCost=FileOpen8.readline()
	    FileOpen1.close()
	    FileOpen2.close()
	    FileOpen3.close()
	    FileOpen4.close()
	    FileOpen5.close()
	    FileOpen6.close()
	    FileOpen7.close()
	    FileOpen8.close()
	
	    Cri_Function=[FileSpeed,FileCPU,FilePacket,FileData,FileLoss,FileConnection, FileLogin,FileCost] #jo files uppar knoli unhi ko neeche likh rahi hai
	    Pair_Matrix=[SpeedPair,CPUPair,PacketPair, DataPair, LossPair,ConnectionPair,LoginPair,CostPair] #fr repeat kar rahi hai
	    #print "Cri_Fun"
	    #print Cri_Function
	    #print "----------------"
	    #print "Pair_Fun"
	    #print Pair_Matrix
	    #print "----------------"
	    
	    #index=0
	    PairFunctionList=[]
            for index in range (0, len(Cri_Function)):
		function=Cri_Function[index] #sab kch criteria function ka save kar rahi hai function mai
		if(function=="Usual"):
			UsualList=self.Usual(Pair_Matrix[index])
			PairFunctionList.append(UsualList)
		elif(function=="Quasi"):
			QuasiList=self.Quasi(Pair_Matrix[index])
			PairFunctionList.append(QuasiList)
		elif(function=="V-Shape"):
			VShapeList=self.VShape(Pair_Matrix[index])
			PairFunctionList.append(VShapeList)
		elif(function=="Level"):
			LevelList=self.Level(Pair_Matrix[index])#ye promethee ke function hai
			PairFunctionList.append(LevelList)
		elif(function=="U-Shape"):
			UShapeList=self.UShape(Pair_Matrix[index])
			PairFunctionList.append(UShapeList)
		elif(function=="Gaussian"):
			GaussianList=self.Gaussian(Pair_Matrix[index])
			PairFunctionList.append(GaussianList)
		
           
	
	print "PairFunctionList is "
 	print PairFunctionList
	print "----------------"
	if((Weight_path1==True) and (Weight_path2==True) and (Weight_path3==True) and (Weight_path4==True) and (Weight_path5==True) and (Weight_path6==True) and (Weight_path7==True)and (Weight_path8==True)):
	    
            FileOpen1=open(Speed_Weight,'r')
            WeightSpeed=FileOpen1.readline()
            FileOpen2=open(CPU_Weight,'r')
            WeightCPU=FileOpen2.readline()
	    FileOpen3=open(Packet_Weight,'r')
            WeightPacket=FileOpen3.readline()
	    FileOpen4=open(Data_Weight,'r')
            WeightData=FileOpen4.readline()
	    FileOpen5=open(Loss_Weight,'r')
            WeightLoss=FileOpen5.readline()
	    FileOpen6=open(Connection_Weight,'r')
            WeightConnection=FileOpen6.readline()
            FileOpen7=open(Login_Weight,'r')
            WeightLogin=FileOpen7.readline()
	    FileOpen8=open(Cost_Weight,'r')
            WeightCost=FileOpen8.readline()
	    FileOpen1.close()
	    FileOpen2.close()
	    FileOpen3.close()
	    FileOpen4.close()
	    FileOpen5.close()
	    FileOpen6.close()
	    FileOpen7.close()
	    FileOpen8.close()
	    Cri_Weight=[WeightSpeed,WeightCPU,WeightPacket,WeightData,WeightLoss,WeightConnection, WeightLogin,WeightCost]	
	print Cri_Weight
	SumWeight=0
	for weightValue in Cri_Weight:
		SumWeight=SumWeight+int(weightValue)
	print "Sum Weight is", SumWeight	
    	PairLen=len(PairFunctionList)
	print "PairLen", PairLen
	row=len(PairFunctionList[0])
	column=len(PairFunctionList[0][0])
	PreferenceMatrix=[[0 for x in range(column)] for x in range(row)]
	for i in range (0,row):
	    for j in range (0, column):
		AddValue=0
		for k in range (0, PairLen):
                    PairValue=PairFunctionList[k]
            	    if (PairValue[i][j]=='NaN'):
                   	AddValue='NaN'
			PreferenceMatrix[i][j]='NaN'
            	    else:
                	#print AddValue

                	AddValue=AddValue+PairValue[i][j]*int(Cri_Weight[k])
                    	#print ", ", AddValue
                PreferenceMatrix[i][j]=AddValue
		
        	if(PreferenceMatrix[i][j]!='NaN'):
            		PreferenceMatrix[i][j]=PreferenceMatrix[i][j]/float(SumWeight)
		
	#print PreferenceMatrix
	Incoming=[]
	Outgoing=[]
	for i in range (0,row):
	    ValueTmp=0
	    TmpValue=0
	    for j in range (0, column):
		if(PreferenceMatrix[i][j]!='NaN'):
            		ValueTmp=ValueTmp+PreferenceMatrix[i][j]#kyu add kar rahi hai valuetmp ko
		if(PreferenceMatrix[j][i]!='NaN'):
            		TmpValue=TmpValue+PreferenceMatrix[j][i]
            Incoming.append(float(ValueTmp)/(column-1))
	    Outgoing.append(float(TmpValue)/(row-1))
	print "Incoming: "
	print Incoming
	print "Outgoing: "
	print Outgoing
	FinalValue=0
	FinalList=[]
	for i in range (0, row):
		FinalValue=Incoming[i]-Outgoing[i]  #Incoming-Outgoing phi=phi(+)-phi(-)
		FinalList.append(FinalValue)
	#print "Final Result is: ", FinalList
	SortedDic={}
	Alternative= ["IPS", "Filter", "Trust Platform","Replica","Network Disconnection","Host Shutdown","Process Termination", "ModSecurity"]
	for k in range (0, len(Alternative)):
		SortedDic[Alternative[k]]=FinalList[k]
	print "Dic is ", SortedDic
	sort=sorted(SortedDic.items(), key=lambda d: d[1])
	print sort



	#--------Ranking-----------
	if(len(sort)==0):
            newstring="Please set the values for various attacks, different Alternative before Submit Button"
            #self.udpbest='None'
            self.log.writeText(newstring,'RED')
        else:
            newstring=attack +" Alternative Ranking:\n"  
            self.log.writeText(newstring,'BLUE') #ye nahi dikh raha hai
            self.log.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'Red')     
            for i in range (0,len(sort)):
                attack=sort[len(sort)-i-1]
                largest=attack[0] #sabse pehle largest ko save kar rahi hai
                largestscore=str(attack[1])
                string=" No. %d  : %s (%s) \n"%(i+1,largest,largestscore)
                newstring=newstring+string
                self.log.writeText(string,'BLUE')
                
                #print " No. %d is : %s ------------------ %s \n"%(i+1,smallest,smallestscore)
            
            #att=sort[0]        
            #self.udpbest=att[0]            
        #udpranking[0]=newstring
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
		else: #har kisi ke diff logic hai
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
	

    
    #------------get the total score for one method of an Attack in 8 aspects--------------
    def allsum(self,attack,pmethod):
        filename="/home/MWrite/"+attack+"_"+pmethod
        cscore=filename+"_costscore.txt"
        rscore=filename+"_recoveryscore.txt"
        perfscore=filename+"_performancescore.txt"
        escore=filename+"_efficiencyscore.txt"
        ectscore=filename+"_effectscore.txt"
#        overscore=filename+"_overheadscore.txt"
#        falsescore=filename+"_falsescore.txt"
#        iscore=filename+"_impactscore.txt"
        f1=open(cscore,'r')
        f2=open(rscore,'r')
        f3=open(perfscore,'r')
        f4=open(escore,'r')
        f5=open(ectscore,'r')
#        f6=open(overscore,'r')
#        f7=open(falsescore,'r')
#        f8=open(iscore,'r')
        cost=f1.readline()
        rec=f2.readline()
        per=f3.readline()
        eff=f4.readline()
        ect=f5.readline()
#        over=f6.readline()
#        false=f7.readline()
#        impact=f8.readline()
        total=float(cost)+float(rec)+float(per)+float(eff)+float(ect) #float mai convert kar rahe ho
        #+float(over)+float(false)+float(impact) #total score for one method to protect against specific attacks.    
        f1.close()
        f2.close()
        f3.close()
        f4.close()
        f5.close()
#        f6.close()
#        f7.close()
#        f8.close()
        fall=filename+"_totalscore.txt"
        fileall=open(fall,'w')
        fileall.write(str(total))
        print "Total is %s" %str(total) 
        return total #sabko add kar diya
    
    def udprankfun(self):
        newlist={}
        filename="/home/MWrite/"
        udpips=filename+"UDP_IPS_totalscore.txt"
        udpdisable=filename+"UDP_Port Disablement_totalscore.txt"
        udpdisconnect=filename+"UDP_Legal Flow Filtering_totalscore.txt"
        udpfire=filename+"UDP_Network Disconnection_totalscore.txt"
        udpshut=filename+"UDP_Firewall_totalscore.txt"
        udponly=filename+"UDP_Host Shutdown_totalscore.txt"        #saare mehtods uske
        udpbool1=os.path.isfile(udpips)
        udpbool2=os.path.isfile(udpdisable)
        udpbool3=os.path.isfile(udpdisconnect)
        udpbool4=os.path.isfile(udpfire)
        udpbool5=os.path.isfile(udpshut)
        udpbool6=os.path.isfile(udponly)
        #-----------Get total value for each protected method for UDP Flood Attack----------    
        if(udpbool1==True):#check kar raha hai if d abov is true
            fnewopen1=open(udpips,'r')
            d1=fnewopen1.readline()
            data1=float(d1)
            newlist['IPS']=data1 #the score for IPS
        if(udpbool2==True):
            fnewopen2=open(udpdisable,'r')
            d2=fnewopen2.readline()
            data2=float(d2)
            newlist['Port Disablement']=data2 #the total score for disable port
        if(udpbool3==True):
            fnewopen3=open(udpdisconnect,'r')
            d3=fnewopen3.readline()
            data3=float(d3)
            newlist['Legal Flow Filtering']=data3
        if(udpbool4==True):
            fnewopen4=open(udpfire,'r')
            d4=fnewopen4.readline()
            data4=float(d4)
            newlist['Network Disconnection']=data4
        if(udpbool5==True):
            fnewopen5=open(udpshut,'r')
            d5=fnewopen5.readline()
            data5=float(d5)
            newlist['Firewall']=data5
        if(udpbool6==True):
            fnewopen6=open(udponly,'r')
            d6=fnewopen6.readline()
            data6=float(d6)
            newlist['Host Shutdown']=data6        
            #-----------Sort total score for each method, the lowest score is the best thus the method is chosen for protecting against UDP Flood Attack. 
        sort=sorted(newlist.items(), key=lambda d: d[1])        
        if(len(sort)==0):
            newstring="Please set the values for various attacks, different protected methods and press OK button before the Rank button"
            self.udpbest='None'
            self.log.writeText(newstring,'RED')
        else:
            newstring="UDP Protected Method Ranking:\n"  
            self.log.writeText(newstring,'BLUE') 
            self.log.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLACK')     
            for i in range (0,len(sort)):
                attack=sort[i]
                smallest=attack[0]
                smallestscore=str(attack[1])
                string=" No. %d  : %s (%s) \n"%(i+1,smallest,smallestscore)
                newstring=newstring+string
                self.log.writeText(string,'BLUE')
                
                #print " No. %d is : %s ------------------ %s \n"%(i+1,smallest,smallestscore)
            
            att=sort[0]        
            self.udpbest=att[0]            
        udpranking[0]=newstring
       # udpranking[1]=bestmethod
        #return udpranking   #include all "strlist[0] "ranking and [1] the best method, all ranking send to rankbutton to display, [1] send for code run the best method
        


#-------------------------Get Ranking of different methods of TCP Attack--------------

    def tcprankfun(self): 
            newlist={}
            filename="/home/MWrite/"
            tcpips=filename+"TCP_SYN_IPS_totalscore.txt"
            tcpdisable=filename+"TCP_SYN_Port Disablement_totalscore.txt"
            tcpdisconnect=filename+"TCP_SYN_Legal Flow Filtering_totalscore.txt"
            tcpfire=filename+"TCP_SYN_Network Disconnection_totalscore.txt"
            tcpshut=filename+"TCP_SYN_Firewall_totalscore.txt"
            tcponly=filename+"TCP_SYN_Host Shutdown_totalscore.txt"        
            tcpbool1=os.path.isfile(tcpips)
            tcpbool2=os.path.isfile(tcpdisable)
            tcpbool3=os.path.isfile(tcpdisconnect)
            tcpbool4=os.path.isfile(tcpfire)
            tcpbool5=os.path.isfile(tcpshut)
            tcpbool6=os.path.isfile(tcponly)        
            if(tcpbool1==True):
                fnewopen1=open(tcpips,'r')
                d1=fnewopen1.readline()
                data1=float(d1)
                newlist['IPS']=data1
            if(tcpbool2==True):
                fnewopen2=open(tcpdisable,'r')
                d2=fnewopen2.readline()
                data2=float(d2)
                newlist['Port Disablement']=data2
            if(tcpbool3==True):
                fnewopen3=open(tcpdisconnect,'r')
                d3=fnewopen3.readline()
                data3=float(d3)
                newlist['Legal Flow Filtering']=data3
            if(tcpbool4==True):
                fnewopen4=open(tcpfire,'r')
                d4=fnewopen4.readline()
                data4=float(d4)
                newlist['Network Disconnection']=data4
            if(tcpbool5==True):
                fnewopen5=open(tcpshut,'r')
                d5=fnewopen5.readline()
                data5=float(d5)
                newlist['Firewall']=data5
            if(tcpbool6==True):
                fnewopen6=open(tcponly,'r')
                d6=fnewopen6.readline()
                data6=float(d6)
                newlist['Host Shutdown']=data6        
        
            sort=sorted(newlist.items(), key=lambda d: d[1])
	    
            if(len(sort)==0):
                newstring="Please set the values for various attacks, different protected methods and press OK button before the Rank button"
                #bestmethod='None'
                self.tcpbest=""
                self.log.writeText(newstring,'RED')
            else:
                newstring="TCP_SYN Protected Method Ranking:\n" 
                self.log.writeText(newstring,'BLUE')  
                self.log.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLACK')     
                for i in range (0,len(sort)):
                    attack=sort[i]
                    smallest=attack[0]
                    smallestscore=str(attack[1])
                    string=" No. %d  : %s (%s) \n"%(i+1,smallest,smallestscore)
                    newstring=newstring+string                
                    self.log.writeText(string,'BLUE')
                #self.log.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLUE')
                att=sort[0]        
                #bestmethod=att[0]      
                self.tcpbest=att[0]      
            #tcpranking[0]=newstring
            #tcpranking[1]=bestmethod
            #return tcpranking   #include all "strlist[0] "ranking and [1] the best method, all ranking send to rankbutton to display, [1] send for code run the best method
    
    
    #---------------------------Get Ranking of different methods of ICMP Attack--------------
    def icmprankfun(self):
            newlist={}
            filename="/home/MWrite/"
            icmpips=filename+"ICMP_IPS_totalscore.txt"
            icmpdisable=filename+"ICMP_Port Disablement_totalscore.txt"
            icmpdisconnect=filename+"ICMP_Legal Flow Filtering_totalscore.txt"
            icmpfire=filename+"ICMP_Network Disconnection_totalscore.txt"
            icmpshut=filename+"ICMP_Firewall_totalscore.txt"
            icmponly=filename+"ICMP_Host Shutdown_totalscore.txt"        
            icmpbool1=os.path.isfile(icmpips)
            icmpbool2=os.path.isfile(icmpdisable)
            icmpbool3=os.path.isfile(icmpdisconnect)
            icmpbool4=os.path.isfile(icmpfire)
            icmpbool5=os.path.isfile(icmpshut)
            icmpbool6=os.path.isfile(icmponly)        
            if(icmpbool1==True):
                fnewopen1=open(icmpips,'r')
                d1=fnewopen1.readline()
                data1=float(d1)
                newlist['IPS']=data1
            if(icmpbool2==True):
                fnewopen2=open(icmpdisable,'r')
                d2=fnewopen2.readline()
                data2=float(d2)
                newlist['Port Disablement']=data2
            if(icmpbool3==True):
                fnewopen3=open(icmpdisconnect,'r')
                d3=fnewopen3.readline()
                data3=float(d3)
                newlist['Legal Flow Filtering']=data3
            if(icmpbool4==True):
                fnewopen4=open(icmpfire,'r')
                d4=fnewopen4.readline()
                data4=float(d4)
                newlist['Network Disconnection']=data4
            if(icmpbool5==True):
                fnewopen5=open(icmpshut,'r')
                d5=fnewopen5.readline()
                data5=float(d5)
                newlist['Firewall']=data5
            if(icmpbool6==True):
                fnewopen6=open(icmponly,'r')
                d6=fnewopen6.readline()
                data6=float(d6)
                newlist['Host Shutdown']=data6        
        
            sort=sorted(newlist.items(), key=lambda d: d[1])
            if(len(sort)==0):
                newstring="Please set the values for various attacks, different protected methods and press OK button before the Rank button\n"
                bestmethod='None'
                self.log.writeText(newstring,'RED')
            else:
                newstring="ICMP Protected Method Ranking:\n"   
                self.log.writeText(newstring,'BLUE') 
                self.log.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLACK')    
                for i in range (0,len(sort)):
                    attack=sort[i]
                    smallest=attack[0]
                    smallestscore=str(attack[1])
                    string=" No. %d  : %s (%s) \n"%(i+1,smallest,smallestscore)
                    newstring=newstring+string
                    self.log.writeText(string,'BLUE')
                #self.log.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLUE')
                att=sort[0]        
                bestmethod=att[0]            
            icmpranking[0]=newstring        
            icmpranking[1]=bestmethod
            return icmpranking   #include all "strlist[0] "ranking and [1] the best method, all ranking send to rankbutton to display, [1] send for code run the best method
    
    
    #----------------------------Get Ranking of different methods of POD Attack-------------------
    
    def podrankfun(self):
            newlist={}
            filename="/home/MWrite/"
            podips=filename+"POD_IPS_totalscore.txt"
            poddisable=filename+"POD_Port Disablement_totalscore.txt"
            poddisconnect=filename+"POD_Legal Flow Filtering_totalscore.txt"
            podfire=filename+"POD_Network Disconnection_totalscore.txt"
            podshut=filename+"POD_Firewall_totalscore.txt"
            podonly=filename+"POD_Host Shutdown_totalscore.txt"                
            podbool1=os.path.isfile(podips)
            podbool2=os.path.isfile(poddisable)
            podbool3=os.path.isfile(poddisconnect)
            podbool4=os.path.isfile(podfire)
            podbool5=os.path.isfile(podshut)
            podbool6=os.path.isfile(podonly)        
            if(podbool1==True):
                fnewopen1=open(podips,'r')
                d1=fnewopen1.readline()
                data1=float(d1)
                newlist['IPS']=data1
            if(podbool2==True):
                fnewopen2=open(poddisable,'r')
                d2=fnewopen2.readline()
                data2=float(d2)
                newlist['Port Disablement']=data2
            if(podbool3==True):
                fnewopen3=open(poddisconnect,'r')
                d3=fnewopen3.readline()
                data3=float(d3)
                newlist['Legal Flow Filtering']=data3
            if(podbool4==True):
                fnewopen4=open(podfire,'r')
                d4=fnewopen4.readline()
                data4=float(d4)
                newlist['Network Disconnection']=data4
            if(podbool5==True):
                fnewopen5=open(podshut,'r')
                d5=fnewopen5.readline()
                data5=float(d5)
                newlist['Firewall']=data5
            if(podbool6==True):
                fnewopen6=open(podonly,'r')
                d6=fnewopen6.readline()
                data6=float(d6)
                newlist['Host Shutdown']=data6        
        
            sort=sorted(newlist.items(), key=lambda d: d[1])
            if(len(sort)==0):
                newstring="Please set the values for various attacks, different protected methods and press OK button before the Rank button\n"
                bestmethod='None'
                self.log.writeText(newstring,'RED')
            else:
                newstring="POD Protected Method Ranking:\n"    
                self.log.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLACK')    
                for i in range (0,len(sort)):
                    attack=sort[i]
                    smallest=attack[0]
                    smallestscore=str(attack[1])
                    string=" No. %d  : %s (%s) \n"%(i+1,smallest,smallestscore)
                    newstring=newstring+string
                    self.log.writeText(string,'BLUE')
                #self.log.writeText("-------------%s-----------\n"%str(datetime.datetime.now()),'BLUE')
                att=sort[0]        
                bestmethod=att[0]            
            podranking[0]=newstring    
            podranking[1]=bestmethod
            return podranking   #include all "strlist[0] "ranking and [1] the best method, all ranking send to rankbutton to display, [1] send for code run the best method
