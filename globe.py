import wx
import os,time
from threading import *
import socket
import os,re,sys
import time
import binascii
import signal
import pexpect
import thread
import datetime
from figure import *
from ReplicaHost import *
from CPU_MeM_Priority_Kill import * #Protection Method for unknown attacks consume CPU and Mem.

from mcontroller import *

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
#from main import *
class TimeoutException(Exception): 
    pass 
class Globe():
    routernew=""  
    def __init__(self,log):          
            self.log=log 
            self.udpbest=""
            self.tcpbest="" 
            
        
    def setLog(self, log):
        self.log = log
        
    def Initial(self):
        message1="""UDP Default Protected Processes Ranking:\n
        No. 1  : IPS (0.5)\n
        No. 2  : Port Disablement (1.8)\n
        No. 3  : Firewall (2.1)\n
        No. 4 : Host Shutdown (3.1)\n
        No. 5  : Legal Flow Filtering (3.3)\n
        No. 6  : Networking Disconnection (3.3)\n"""
        
        message2="""TCP SYN Default Protected Processes Ranking:\n
        No. 1  : Port Disablement (1.5)\n        
        No. 2  : Firewall (3.1)\n
        No. 3 : Host Shutdown (3.1)\n
        No. 4  : IPS (3.3)\n
        No. 5  : Legal Flow Filtering (3.3)\n
        No. 6  : Networking Disconnection (3.3)\n      """
        
        
        message3="""ICMP Default Protected Processes Ranking:\n
        No. 1  : IPS (0.5)\n
        No. 2  : Port Disablement (1.8)\n
        No. 3  : Firewall (2.1)\n
        No. 4 : Host Shutdown (3.1)\n
        No. 5  : Legal Flow Filtering (3.3)\n
        No. 6  : Networking Disconnection (3.3)\n"""
        
        message4="""POD Default Protected Processes Ranking:\n
        No. 1  : IPS (0.5)\n
        No. 2  : Port Disablement (1.8)\n
        No. 3  : Firewall (2.1)\n
        No. 4 : Host Shutdown (3.1)\n
        No. 5  : Legal Flow Filtering (3.3)\n
        No. 6  : Networking Disconnection (3.3)\n"""

        #---------icmp---------
        file_cost=open('/home/Write/cost.txt','w')
        file_recovery=open('/home/Write/recovery.txt','w')
        file_availability=open('/home/Write/efficiency.txt','w')
        file_latency=open('/home/Write/performance.txt','w')
        file_resource=open('/home/Write/effect.txt','w')
        file_cost.write('1')
        file_recovery.write('2')
        file_availability.write('2')
        file_latency.write('1')
        file_resource.write('0.5')
        file_cost.close()
        file_recovery.close()
        file_availability.close()
        file_latency.close()
        file_resource.close()
        
        
        #-------Initial Weight Values for each attack/process-----
               
       
        file_UDP_IPS_recovery=open('/home/Write/UDP_IPS_recoveryvalue.txt','w')
        file_UDP_IPS_availability=open('/home/Write/UDP_IPS_efficiencyvalue.txt','w')
        file_UDP_IPS_latency=open('/home/Write/UDP_IPS_performancevalue.txt','w')
        file_UDP_IPS_cost=open('/home/Write/UDP_IPS_costvalue.txt','w')
        file_UDP_IPS_resource=open('/home/Write/UDP_IPS_effectvalue.txt','w')
        
        
        file_UDP_IPS_recovery.write('0')
        file_UDP_IPS_availability.write('0')
        file_UDP_IPS_latency.write('0.2')
        file_UDP_IPS_cost.write('0.2')
        file_UDP_IPS_resource.write('0.2')
       
       #--------UDP Disable port---------
        file_UDP_Disablement_recovery=open('/home/Write/UDP_Port Disablement_recoveryvalue.txt','w')
        file_UDP_Disablement_availability=open('/home/Write/UDP_Port Disablement_efficiencyvalue.txt','w')
        file_UDP_Disablement_latency=open('/home/Write/UDP_Port Disablement_performancevalue.txt','w')
        file_UDP_Disablement_cost=open('/home/Write/UDP_Port Disablement_costvalue.txt','w')
        file_UDP_Disablement_resource=open('/home/Write/UDP_Port Disablement_effectvalue.txt','w')
        
        file_UDP_Disablement_recovery.write('0')
        file_UDP_Disablement_availability.write('0.5')
        file_UDP_Disablement_latency.write('0.8')
        file_UDP_Disablement_cost.write('0')
        file_UDP_Disablement_resource.write('0')
        
        #---------UDP Legal Flow----------
        file_UDP_Filtering_recovery=open('/home/Write/UDP_Legal Flow Filtering_recoveryvalue.txt','w')
        file_UDP_Filtering_availability=open('/home/Write/UDP_Legal Flow Filtering_efficiencyvalue.txt','w')
        file_UDP_Filtering_latency=open('/home/Write/UDP_Legal Flow Filtering_performancevalue.txt','w')
        file_UDP_Filtering_cost=open('/home/Write/UDP_Legal Flow Filtering_costvalue.txt','w')
        file_UDP_Filtering_resource=open('/home/Write/UDP_Legal Flow Filtering_effectvalue.txt','w')
        
        file_UDP_Filtering_recovery.write('1')
        file_UDP_Filtering_availability.write('0.5')
        file_UDP_Filtering_latency.write('0')
        file_UDP_Filtering_cost.write('0.2')
        file_UDP_Filtering_resource.write('0.2')
        
        #-------UDP network------------
        file_UDP_Disconnection_recovery=open('/home/Write/UDP_Network Disconnection_recoveryvalue.txt','w')
        file_UDP_Disconnection_availability=open('/home/Write/UDP_Network Disconnection_efficiencyvalue.txt','w')
        file_UDP_Disconnection_latency=open('/home/Write/UDP_Network Disconnection_performancevalue.txt','w')
        file_UDP_Disconnection_cost=open('/home/Write/UDP_Network Disconnection_costvalue.txt','w')
        file_UDP_Disconnection_resource=open('/home/Write/UDP_Network Disconnection_effectvalue.txt','w')
        
        
        file_UDP_Disconnection_recovery.write('0')
        file_UDP_Disconnection_availability.write('1')
        file_UDP_Disconnection_latency.write('1')
        file_UDP_Disconnection_cost.write('0.2')
        file_UDP_Disconnection_resource.write('0.2')
        
        
        #----------UDP Firewall--------
        file_UDP_Firewall_recovery=open('/home/Write/UDP_Firewall_recoveryvalue.txt','w')
        file_UDP_Firewall_availability=open('/home/Write/UDP_Firewall_efficiencyvalue.txt','w')
        file_UDP_Firewall_latency=open('/home/Write/UDP_Firewall_performancevalue.txt','w')
        file_UDP_Firewall_cost=open('/home/Write/UDP_Firewall_costvalue.txt','w')
        file_UDP_Firewall_resource=open('/home/Write/UDP_Firewall_effectvalue.txt','w')
        
        
        file_UDP_Firewall_recovery.write('0.8')
        file_UDP_Firewall_availability.write('0')
        file_UDP_Firewall_latency.write('0.5')
        file_UDP_Firewall_cost.write('0')
        file_UDP_Firewall_resource.write('0')
        
        #-----UDP Host shutdown-------
        file_UDP_Shutdown_recovery=open('/home/Write/UDP_Host Shutdown_recoveryvalue.txt','w')
        file_UDP_Shutdown_availability=open('/home/Write/UDP_Host Shutdown_efficiencyvalue.txt','w')
        file_UDP_Shutdown_latency=open('/home/Write/UDP_Host Shutdown_performancevalue.txt','w')
        file_UDP_Shutdown_cost=open('/home/Write/UDP_Host Shutdown_costvalue.txt','w')
        file_UDP_Shutdown_resource=open('/home/Write/UDP_Host Shutdown_effectvalue.txt','w')
        file_UDP_Shutdown_recovery.write('0')
        file_UDP_Shutdown_availability.write('1')
        file_UDP_Shutdown_latency.write('1')
        file_UDP_Shutdown_cost.write('0')
        file_UDP_Shutdown_resource.write('0.2')
        
        
        
        
        
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
        file_UDP_Disablement_recovery.close()
        file_UDP_Disablement_availability.close()
        file_UDP_Disablement_latency.close()
        file_UDP_Disablement_cost.close()
        file_UDP_Disablement_resource.close()
        file_UDP_IPS_recovery.close()
        file_UDP_IPS_availability.close()
        file_UDP_IPS_latency.close()
        file_UDP_IPS_cost.close()
        file_UDP_IPS_resource.close()

        #-------TCP-------
        file_TCP_SYN_IPS_recovery=open('/home/Write/TCP_SYN_IPS_recoveryvalue.txt','w')
        file_TCP_SYN_IPS_availability=open('/home/Write/TCP_SYN_IPS_efficiencyvalue.txt','w')
        file_TCP_SYN_IPS_latency=open('/home/Write/TCP_SYN_IPS_performancevalue.txt','w')
        file_TCP_SYN_IPS_cost=open('/home/Write/TCP_SYN_IPS_costvalue.txt','w')
        file_TCP_SYN_IPS_resource=open('/home/Write/TCP_SYN_IPS_effectvalue.txt','w')
        
        
        file_TCP_SYN_IPS_recovery.write('1')
        file_TCP_SYN_IPS_availability.write('0')
        file_TCP_SYN_IPS_latency.write('1')
        file_TCP_SYN_IPS_cost.write('0.2')
        file_TCP_SYN_IPS_resource.write('0.2')

        file_TCP_SYN_IPS_recovery.close()
        file_TCP_SYN_IPS_availability.close()
        file_TCP_SYN_IPS_latency.close()
        file_TCP_SYN_IPS_cost.close()
        file_TCP_SYN_IPS_resource.close()
    
        file_TCP_SYN_Disablement_recovery=open('/home/Write/TCP_SYN_Port Disablement_recoveryvalue.txt','w')
        file_TCP_SYN_Disablement_availability=open('/home/Write/TCP_SYN_Port Disablement_efficiencyvalue.txt','w')
        file_TCP_SYN_Disablement_latency=open('/home/Write/TCP_SYN_Port Disablement_performancevalue.txt','w')
        file_TCP_SYN_Disablement_cost=open('/home/Write/TCP_SYN_Port Disablement_costvalue.txt','w')
        file_TCP_SYN_Disablement_resource=open('/home/Write/TCP_SYN_Port Disablement_effectvalue.txt','w')
        
        
        file_TCP_SYN_Disablement_recovery.write('0')
        file_TCP_SYN_Disablement_availability.write('0.5')
        file_TCP_SYN_Disablement_latency.write('0.5')
        file_TCP_SYN_Disablement_cost.write('0')
        file_TCP_SYN_Disablement_resource.write('0')

        file_TCP_SYN_Disablement_recovery.close()
        file_TCP_SYN_Disablement_availability.close()
        file_TCP_SYN_Disablement_latency.close()
        file_TCP_SYN_Disablement_cost.close()
        file_TCP_SYN_Disablement_resource.close()

        file_TCP_SYN_Filtering_recovery=open('/home/Write/TCP_SYN_Legal Flow Filtering_recoveryvalue.txt','w')
        file_TCP_SYN_Filtering_availability=open('/home/Write/TCP_SYN_Legal Flow Filtering_efficiencyvalue.txt','w')
        file_TCP_SYN_Filtering_latency=open('/home/Write/TCP_SYN_Legal Flow Filtering_performancevalue.txt','w')
        file_TCP_SYN_Filtering_cost=open('/home/Write/TCP_SYN_Legal Flow Filtering_costvalue.txt','w')
        file_TCP_SYN_Filtering_resource=open('/home/Write/TCP_SYN_Legal Flow Filtering_effectvalue.txt','w')
        
        
        file_TCP_SYN_Filtering_recovery.write('1')
        file_TCP_SYN_Filtering_availability.write('0.5')
        file_TCP_SYN_Filtering_latency.write('0')
        file_TCP_SYN_Filtering_cost.write('0.2')
        file_TCP_SYN_Filtering_resource.write('0.2')

        file_TCP_SYN_Filtering_recovery.close()
        file_TCP_SYN_Filtering_availability.close()
        file_TCP_SYN_Filtering_latency.close()
        file_TCP_SYN_Filtering_cost.close()
        file_TCP_SYN_Filtering_resource.close()

        file_TCP_SYN_Disconnection_recovery=open('/home/Write/TCP_SYN_Network Disconnection_recoveryvalue.txt.txt','w')
        file_TCP_SYN_Disconnection_availability=open('/home/Write/TCP_SYN_Network Disconnection_efficiencyvalue.txt.txt','w')
        file_TCP_SYN_Disconnection_latency=open('/home/Write/TCP_SYN_Network Disconnection_performancevalue.txt.txt','w')
        file_TCP_SYN_Disconnection_cost=open('/home/Write/TCP_SYN_Network Disconnection_costvalue.txt.txt','w')
        file_TCP_SYN_Disconnection_resource=open('/home/Write/TCP_SYN_Network Disconnection_effectvalue.txt.txt','w')
        
        
        file_TCP_SYN_Disconnection_recovery.write('0')
        file_TCP_SYN_Disconnection_availability.write('1')
        file_TCP_SYN_Disconnection_latency.write('1')
        file_TCP_SYN_Disconnection_cost.write('0.2')
        file_TCP_SYN_Disconnection_resource.write('0.2')

        file_TCP_SYN_Disconnection_recovery.close()
        file_TCP_SYN_Disconnection_availability.close()
        file_TCP_SYN_Disconnection_latency.close()
        file_TCP_SYN_Disconnection_cost.close()
        file_TCP_SYN_Disconnection_resource.close()


        file_TCP_SYN_Firewall_recovery=open('/home/Write/TCP_SYN_Firewall_recoveryvalue.txt','w')
        file_TCP_SYN_Firewall_availability=open('/home/Write/TCP_SYN_Firewall_efficiencyvalue.txt','w')
        file_TCP_SYN_Firewall_latency=open('/home/Write/TCP_SYN_Firewall_performancevalue.txt','w')
        file_TCP_SYN_Firewall_cost=open('/home/Write/TCP_SYN_Firewall_costvalue.txt','w')
        file_TCP_SYN_Firewall_resource=open('/home/Write/TCP_SYN_Firewall_effectvalue.txt','w')
        file_TCP_SYN_Firewall_recovery.write('0.8')
        file_TCP_SYN_Firewall_availability.write('0.5')
        file_TCP_SYN_Firewall_latency.write('0.5')
        file_TCP_SYN_Firewall_cost.write('0')
        file_TCP_SYN_Firewall_resource.write('0')

        file_TCP_SYN_Firewall_recovery.close()
        file_TCP_SYN_Firewall_availability.close()
        file_TCP_SYN_Firewall_latency.close()
        file_TCP_SYN_Firewall_cost.close()
        file_TCP_SYN_Firewall_resource.close()


        file_TCP_SYN_Shutdown_recovery=open('/home/Write/TCP_SYN_Host Shutdown_recoveryvalue.txt','w')
        file_TCP_SYN_Shutdown_availability=open('/home/Write/TCP_SYN_Host Shutdown_efficiencyvalue.txt','w')
        file_TCP_SYN_Shutdown_latency=open('/home/Write/TCP_SYN_Host Shutdown_performancevalue.txt','w')
        file_TCP_SYN_Shutdown_cost=open('/home/Write/TCP_SYN_Host Shutdown_costvalue.txt','w')
        file_TCP_SYN_Shutdown_resource=open('/home/Write/TCP_SYN_Host Shutdown_effectvalue.txt','w')
        file_TCP_SYN_Shutdown_recovery.write('0')
        file_TCP_SYN_Shutdown_availability.write('1')
        file_TCP_SYN_Shutdown_latency.write('1')
        file_TCP_SYN_Shutdown_cost.write('0')
        file_TCP_SYN_Shutdown_resource.write('0.2')


        file_TCP_SYN_Shutdown_recovery.close()
        file_TCP_SYN_Shutdown_availability.close()
        file_TCP_SYN_Shutdown_latency.close()
        file_TCP_SYN_Shutdown_cost.close()
        file_TCP_SYN_Shutdown_resource.close()
        #---------ICMP-------
        file_ICMP_IPS_recovery=open('/home/Write/ICMP_IPS_recoveryvalue.txt','w')
        file_ICMP_IPS_availability=open('/home/Write/ICMP_IPS_efficiencyvalue.txt','w')
        file_ICMP_IPS_latency=open('/home/Write/ICMP_IPS_performancevalue.txt','w')
        file_ICMP_IPS_cost=open('/home/Write/ICMP_IPS_costvalue.txt','w')
        file_ICMP_IPS_resource=open('/home/Write/ICMP_IPS_effectvalue.txt','w')
        
        
        file_ICMP_IPS_recovery.write('0')
        file_ICMP_IPS_availability.write('0')
        file_ICMP_IPS_latency.write('0.2')
        file_ICMP_IPS_cost.write('0.2')
        file_ICMP_IPS_resource.write('0.2')

        file_ICMP_IPS_recovery.close()
        file_ICMP_IPS_availability.close()
        file_ICMP_IPS_latency.close()
        file_ICMP_IPS_cost.close()
        file_ICMP_IPS_resource.close()
    
        file_ICMP_Disablement_recovery=open('/home/Write/ICMP_Port Disablement_recoveryvalue.txt','w')
        file_ICMP_Disablement_availability=open('/home/Write/ICMP_Port Disablement_efficiencyvalue.txt','w')
        file_ICMP_Disablement_latency=open('/home/Write/ICMP_Port Disablement_performancevalue.txt','w')
        file_ICMP_Disablement_cost=open('/home/Write/ICMP_Port Disablement_costvalue.txt','w')
        file_ICMP_Disablement_resource=open('/home/Write/ICMP_Port Disablement_effectvalue.txt','w')
        
        
        file_ICMP_Disablement_recovery.write('0')
        file_ICMP_Disablement_availability.write('0.5')
        file_ICMP_Disablement_latency.write('0.8')
        file_ICMP_Disablement_cost.write('0')
        file_ICMP_Disablement_resource.write('0')

        file_ICMP_Disablement_recovery.close()
        file_ICMP_Disablement_availability.close()
        file_ICMP_Disablement_latency.close()
        file_ICMP_Disablement_cost.close()
        file_ICMP_Disablement_resource.close()

        file_ICMP_Filtering_recovery=open('/home/Write/ICMP_Legal Flow Filtering_recoveryvalue.txt','w')
        file_ICMP_Filtering_availability=open('/home/Write/ICMP_Legal Flow Filtering_efficiencyvalue.txt','w')
        file_ICMP_Filtering_latency=open('/home/Write/ICMP_Legal Flow Filtering_performancevalue.txt','w')
        file_ICMP_Filtering_cost=open('/home/Write/ICMP_Legal Flow Filtering_costvalue.txt','w')
        file_ICMP_Filtering_resource=open('/home/Write/ICMP_Legal Flow Filtering_effectvalue.txt','w')
        
        
        file_ICMP_Filtering_recovery.write('1')
        file_ICMP_Filtering_availability.write('0.5')
        file_ICMP_Filtering_latency.write('0')
        file_ICMP_Filtering_cost.write('0.2')
        file_ICMP_Filtering_resource.write('0.2')

        file_ICMP_Filtering_recovery.close()
        file_ICMP_Filtering_availability.close()
        file_ICMP_Filtering_latency.close()
        file_ICMP_Filtering_cost.close()
        file_ICMP_Filtering_resource.close()

        file_ICMP_Disconnection_recovery=open('/home/Write/ICMP_Network Disconnection_recoveryvalue.txt','w')
        file_ICMP_Disconnection_availability=open('/home/Write/ICMP_Network Disconnection_efficiencyvalue.txt','w')
        file_ICMP_Disconnection_latency=open('/home/Write/ICMP_Network Disconnection_performancevalue.txt','w')
        file_ICMP_Disconnection_cost=open('/home/Write/ICMP_Network Disconnection_costvalue.txt','w')
        file_ICMP_Disconnection_resource=open('/home/Write/ICMP_Network Disconnection_effectvalue.txt','w')
        
        
        file_ICMP_Disconnection_recovery.write('0')
        file_ICMP_Disconnection_availability.write('1')
        file_ICMP_Disconnection_latency.write('1')
        file_ICMP_Disconnection_cost.write('0.2')
        file_ICMP_Disconnection_resource.write('0.2')

        file_ICMP_Disconnection_recovery.close()
        file_ICMP_Disconnection_availability.close()
        file_ICMP_Disconnection_latency.close()
        file_ICMP_Disconnection_cost.close()
        file_ICMP_Disconnection_resource.close()


        file_ICMP_Firewall_recovery=open('/home/Write/ICMP_Firewall_recoveryvalue.txt','w')
        file_ICMP_Firewall_availability=open('/home/Write/ICMP_Firewall_efficiencyvalue.txt','w')
        file_ICMP_Firewall_latency=open('/home/Write/ICMP_Firewall_performancevalue.txt','w')
        file_ICMP_Firewall_cost=open('/home/Write/ICMP_Firewall_costvalue.txt','w')
        file_ICMP_Firewall_resource=open('/home/Write/ICMP_Firewall_effectvalue.txt','w')
        file_ICMP_Firewall_recovery.write('0.8')
        file_ICMP_Firewall_availability.write('0')
        file_ICMP_Firewall_latency.write('0.5')
        file_ICMP_Firewall_cost.write('0')
        file_ICMP_Firewall_resource.write('0')

        file_ICMP_Firewall_recovery.close()
        file_ICMP_Firewall_availability.close()
        file_ICMP_Firewall_latency.close()
        file_ICMP_Firewall_cost.close()
        file_ICMP_Firewall_resource.close()


        file_ICMP_Shutdown_recovery=open('/home/Write/ICMP_Host Shutdown_recoveryvalue.txt','w')
        file_ICMP_Shutdown_availability=open('/home/Write/ICMP_Host Shutdown_efficiencyvalue.txt','w')
        file_ICMP_Shutdown_latency=open('/home/Write/ICMP_Host Shutdown_performancevalue.txt','w')
        file_ICMP_Shutdown_cost=open('/home/Write/ICMP_Host Shutdown_costvalue.txt','w')
        file_ICMP_Shutdown_resource=open('/home/Write/ICMP_Host Shutdown_effectvalue.txt','w')
        file_ICMP_Shutdown_recovery.write('0')
        file_ICMP_Shutdown_availability.write('1')
        file_ICMP_Shutdown_latency.write('1')
        file_ICMP_Shutdown_cost.write('0')
        file_ICMP_Shutdown_resource.write('0.2')


        file_ICMP_Shutdown_recovery.close()
        file_ICMP_Shutdown_availability.close()
        file_ICMP_Shutdown_latency.close()
        file_ICMP_Shutdown_cost.close()
        file_ICMP_Shutdown_resource.close()
        
        #------POD------
        file_POD_IPS_recovery=open('/home/Write/POD_IPS_recoveryvalue.txt','w')
        file_POD_IPS_availability=open('/home/Write/POD_IPS_efficiencyvalue.txt','w')
        file_POD_IPS_latency=open('/home/Write/POD_IPS_performancevalue.txt','w')
        file_POD_IPS_cost=open('/home/Write/POD_IPS_costvalue.txt','w')
        file_POD_IPS_resource=open('/home/Write/POD_IPS_effectvalue.txt','w')
        
        
        file_POD_IPS_recovery.write('0')
        file_POD_IPS_availability.write('0')
        file_POD_IPS_latency.write('0.2')
        file_POD_IPS_cost.write('0.2')
        file_POD_IPS_resource.write('0.2')

        file_POD_IPS_recovery.close()
        file_POD_IPS_availability.close()
        file_POD_IPS_latency.close()
        file_POD_IPS_cost.close()
        file_POD_IPS_resource.close()
    
        file_POD_Disablement_recovery=open('/home/Write/POD_Port Disablement_recoveryvalue.txt','w')
        file_POD_Disablement_availability=open('/home/Write/POD_Port Disablement_efficiencyvalue.txt','w')
        file_POD_Disablement_latency=open('/home/Write/POD_Port Disablement_performancevalue.txt','w')
        file_POD_Disablement_cost=open('/home/Write/POD_Port Disablement_costvalue.txt','w')
        file_POD_Disablement_resource=open('/home/Write/POD_Port Disablement_effectvalue.txt','w')
        
        
        file_POD_Disablement_recovery.write('0')
        file_POD_Disablement_availability.write('0.5')
        file_POD_Disablement_latency.write('0.8')
        file_POD_Disablement_cost.write('0')
        file_POD_Disablement_resource.write('0')

        file_POD_Disablement_recovery.close()
        file_POD_Disablement_availability.close()
        file_POD_Disablement_latency.close()
        file_POD_Disablement_cost.close()
        file_POD_Disablement_resource.close()

        file_POD_Filtering_recovery=open('/home/Write/POD_Legal Flow Filtering_recoveryvalue.txt','w')
        file_POD_Filtering_availability=open('/home/Write/POD_Legal Flow Filtering_efficiencyvalue.txt','w')
        file_POD_Filtering_latency=open('/home/Write/POD_Legal Flow Filtering_performancevalue.txt','w')
        file_POD_Filtering_cost=open('/home/Write/POD_Legal Flow Filtering_costvalue.txt','w')
        file_POD_Filtering_resource=open('/home/Write/POD_Legal Flow Filtering_effectvalue.txt','w')
        
        
        file_POD_Filtering_recovery.write('1')
        file_POD_Filtering_availability.write('0.5')
        file_POD_Filtering_latency.write('0')
        file_POD_Filtering_cost.write('0.2')
        file_POD_Filtering_resource.write('0.2')

        file_POD_Filtering_recovery.close()
        file_POD_Filtering_availability.close()
        file_POD_Filtering_latency.close()
        file_POD_Filtering_cost.close()
        file_POD_Filtering_resource.close()

        file_POD_Disconnection_recovery=open('/home/Write/POD_Network Disconnection_recoveryvalue.txt','w')
        file_POD_Disconnection_availability=open('/home/Write/POD_Network Disconnection_efficiencyvalue.txt','w')
        file_POD_Disconnection_latency=open('/home/Write/POD_Network Disconnection_performancevalue.txt','w')
        file_POD_Disconnection_cost=open('/home/Write/POD_Network Disconnection_costvalue.txt','w')
        file_POD_Disconnection_resource=open('/home/Write/POD_Network Disconnection_effectvalue.txt','w')
        
        
        file_POD_Disconnection_recovery.write('0')
        file_POD_Disconnection_availability.write('1')
        file_POD_Disconnection_latency.write('1')
        file_POD_Disconnection_cost.write('0.2')
        file_POD_Disconnection_resource.write('0.2')

        file_POD_Disconnection_recovery.close()
        file_POD_Disconnection_availability.close()
        file_POD_Disconnection_latency.close()
        file_POD_Disconnection_cost.close()
        file_POD_Disconnection_resource.close()


        file_POD_Firewall_recovery=open('/home/Write/POD_Firewall_recoveryvalue.txt','w')
        file_POD_Firewall_availability=open('/home/Write/POD_Firewall_efficiencyvalue.txt','w')
        file_POD_Firewall_latency=open('/home/Write/POD_Firewall_performancevalue.txt','w')
        file_POD_Firewall_cost=open('/home/Write/POD_Firewall_costvalue.txt','w')
        file_POD_Firewall_resource=open('/home/Write/POD_Firewall_effectvalue.txt','w')
        file_POD_Firewall_recovery.write('0.8')
        file_POD_Firewall_availability.write('0')
        file_POD_Firewall_latency.write('0.5')
        file_POD_Firewall_cost.write('0')
        file_POD_Firewall_resource.write('0')

        file_POD_Firewall_recovery.close()
        file_POD_Firewall_availability.close()
        file_POD_Firewall_latency.close()
        file_POD_Firewall_cost.close()
        file_POD_Firewall_resource.close()


        file_POD_Shutdown_recovery=open('/home/Write/POD_Host Shutdown_recoveryvalue.txt','w')
        file_POD_Shutdown_availability=open('/home/Write/POD_Host Shutdown_efficiencyvalue.txt','w')
        file_POD_Shutdown_latency=open('/home/Write/POD_Host Shutdown_performancevalue.txt','w')
        file_POD_Shutdown_cost=open('/home/Write/POD_Host Shutdown_costvalue.txt','w')
        file_POD_Shutdown_resource=open('/home/Write/POD_Host Shutdown_effectvalue.txt','w')
        file_POD_Shutdown_recovery.write('0')
        file_POD_Shutdown_availability.write('1')
        file_POD_Shutdown_latency.write('1')
        file_POD_Shutdown_cost.write('0')
        file_POD_Shutdown_resource.write('0.2')


        file_POD_Shutdown_recovery.close()
        file_POD_Shutdown_availability.close()
        file_POD_Shutdown_latency.close()
        file_POD_Shutdown_cost.close()
        
        
    #---------TOTALSCOR
        file_UDP_IPS_score=open('/home/Write/UDP_IPS_totalscore.txt','w')
        file_UDP_IPS_score.write('0.5')
        file_UDP_IPS_score.close()
        file_UDP_Disablement_score=open('/home/Write/UDP_Port Disablement_totalscore.txt','w')
        file_UDP_Disablement_score.write('1.8')
        file_UDP_Disablement_score.close()
        
        file_UDP_Filtering_score=open('/home/Write/UDP_Legal Flow Filtering_totalscore.txt','w')
        file_UDP_Filtering_score.write('3.3')
        file_UDP_Filtering_score.close()
        
        file_UDP_Disconnection_score=open('/home/Write/UDP_Network Disconnection_totalscore.txt','w')
        file_UDP_Disconnection_score.write('3.3')
        file_UDP_Disconnection_score.close()
        
        file_UDP_Firewall_score=open('/home/Write/UDP_Firewall_totalscore.txt','w')
        file_UDP_Firewall_score.write('2.1')
        file_UDP_Firewall_score.close()
        
        file_UDP_Shutdown_score=open('/home/Write/UDP_Host Shutdown_totalscore.txt','w')
        file_UDP_Shutdown_score.write('3.1')
        file_UDP_Shutdown_score.close()
        
        
        file_TCP_SYN_IPS_score=open('/home/Write/TCP_SYN_IPS_totalscore.txt','w')
        file_TCP_SYN_IPS_score.write('3.3')
        file_TCP_SYN_IPS_score.close()
        file_TCP_SYN_Disablement_score=open('/home/Write/TCP_SYN_Port Disablement_totalscore.txt','w')
        file_TCP_SYN_Disablement_score.write('1.5')
        file_TCP_SYN_Disablement_score.close()
        
        file_TCP_SYN_Filtering_score=open('/home/Write/TCP_SYN_Legal Flow Filtering_totalscore.txt','w')
        file_TCP_SYN_Filtering_score.write('3.3')
        file_TCP_SYN_Filtering_score.close()
        file_TCP_SYN_Disconnection_score=open('/home/Write/TCP_SYN_Network Disconnection_totalscore.txt','w')
        file_TCP_SYN_Disconnection_score.write('3.3')
        file_TCP_SYN_Disconnection_score.close()
        
        file_TCP_SYN_Firewall_score=open('/home/Write/TCP_SYN_Firewall_totalscore.txt','w')
        file_TCP_SYN_Firewall_score.write('3.1')
        file_TCP_SYN_Firewall_score.close()
        
        file_TCP_SYN_Shutdown_score=open('/home/Write/TCP_SYN_Host Shutdown_totalscore.txt','w')
        file_TCP_SYN_Shutdown_score.write('3.1')
        file_TCP_SYN_Shutdown_score.close()

        
        file_ICMP_IPS_score=open('/home/Write/ICMP_IPS_totalscore.txt','w')
        file_ICMP_IPS_score.write('0.5')
        file_ICMP_IPS_score.close()
        file_ICMP_Disablement_score=open('/home/Write/ICMP_Port Disablement_totalscore.txt','w')
        file_ICMP_Disablement_score.write('1.8')
        file_ICMP_Disablement_score.close()
        
        file_ICMP_Filtering_score=open('/home/Write/ICMP_Legal Flow Filtering_totalscore.txt','w')
        file_ICMP_Filtering_score.write('3.3')
        file_ICMP_Filtering_score.close()
        
        file_ICMP_Disconnection_score=open('/home/Write/ICMP_Network Disconnection_totalscore.txt','w')
        file_ICMP_Disconnection_score.write('3.3')
        file_ICMP_Disconnection_score.close()
        
        file_ICMP_Firewall_score=open('/home/Write/ICMP_Firewall_totalscore.txt','w')
        file_ICMP_Firewall_score.write('2.1')
        file_ICMP_Firewall_score.close()
        
        file_ICMP_Shutdown_score=open('/home/Write/ICMP_Host Shutdown_totalscore.txt','w')
        file_ICMP_Shutdown_score.write('3.1')
        file_ICMP_Shutdown_score.close()
        file_POD_IPS_score=open('/home/Write/POD_IPS_totalscore.txt','w')
        file_POD_IPS_score.write('0.5')
        file_POD_IPS_score.close()
        file_POD_Disablement_score=open('/home/Write/POD_Port Disablement_totalscore.txt','w')
        file_POD_Disablement_score.write('1.8')
        file_POD_Disablement_score.close()
        
        file_POD_Filtering_score=open('/home/Write/POD_Legal Flow Filtering_totalscore.txt','w')
        file_POD_Filtering_score.write('3.3')
        file_POD_Filtering_score.close()
        
        file_POD_Disconnection_score=open('/home/Write/POD_Network Disconnection_totalscore.txt','w')
        file_POD_Disconnection_score.write('3.3')
        file_POD_Disconnection_score.close()
        
        file_POD_Firewall_score=open('/home/Write/POD_Firewall_totalscore.txt','w')
        file_POD_Firewall_score.write('2.1')
        file_POD_Firewall_score.close()
        
        file_POD_Shutdown_score=open('/home/Write/POD_Host Shutdown_totalscore.txt','w')
        file_POD_Shutdown_score.write('3.1')
        file_POD_Shutdown_score.close()
    
    def UDP(self):# run IPS for UDP attack        
                
            os.system("iptables -I FORWARD -d 1.0.0.9 -p udp --dport 5009 -j QUEUE") #packets put into ip_queue for snort_inline to analyze        
            os.system("killall -9 snort_inline") #multiple processes for snort_inline are not allowed, kill all processes if they are running in background
            os.system("snort_inline -c /etc/snort_inline/snort_inline.conf -Q -N -l /var/log/snort_inline/ \-t /var/log/snort_inline/ -v -D") # run IPS
            
    def UDP2(self):# Disable 5009
            
            os.system('iptables -A FORWARD -p udp -d 1.0.0.2 --dport 5009 -j DROP') # disable port
            #print "define udp2 finish"
    
    
    
    #---------------------Disable TCP Port-------------------------
    
    def TCP2(self):
            
            os.system('iptables -A FORWARD -p tcp -d 1.0.0.2 --dport 135 -j DROP') # to protect TCP SYN attack by "Disable Port" method
            #print "define tcp2 finish"
    
    #-------------------------POD IPS----------------------------
    def POD(self):        
            podid=True        
            os.system("iptables -I FORWARD -p icmp -d 1.0.0.2 -j QUEUE") #Ping of death attack runs snort_inline to protect        
            os.system("killall -9 snort_inline")
            os.system("snort_inline -c /etc/snort_inline/snort_inline.conf -Q -N -l /var/log/snort_inline/ \-t /var/log/snort_inline/ -v -D")
    
    #-----------------------dport rop all packets-----------------
    def POD2(self):
            
            os.system('iptables -A FORWARD -p icmp -d 1.0.0.2  -j DROP') # drop all ICMP packets
            
    
    
    #------------------------------Receive from host, Abnormal, normal or timeout------------------------ # communicate with host,check the host is under attack or not
    def receive(self):
        def timeout_handler(signum, frame):
            raise TimeoutException()
     
        old_handler = signal.signal(signal.SIGALRM,timeout_handler) 
        signal.alarm(50) # triger alarm in 50 seconds 
        try: 
            
            s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            s.bind(('1.0.0.9',666)) #this script run on 1.0.0.9 which is the protected VM
    
            data,addr = s.recvfrom(1024)
            if not data:
                print 'client has exited!'
                return 0
            
            s.close()
       
        except TimeoutException:
            return "Timeout"
        finally:
            signal.signal(signal.SIGALRM, old_handler)  
        signal.alarm(0)
        return data
    #--------------------------Communication Send--------
    def communication_send(self):
        s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        
        #s.bind(('1.0.0.9',295))
        s.sendto('send',('1.0.0.2',295))
        s.close()
    #--------------------------Unknown Communication Receive----------
    def communication_receive(self):
        #def timeout_handler(signum, frame):
          #  raise TimeoutException()
     
        #old_handler = signal.signal(signal.SIGALRM,timeout_handler) 
        #signal.alarm(50) # triger alarm in 50 seconds 
        #try: 
            
            s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            s.bind(('',244)) #this script run on 1.0.0.9 which is the protected VM
    
            packet_data,addr = s.recvfrom(102400000)
           # if not data:
           #     print 'client has exited!'
           #     return 0
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
	    #print "data is %s"%new
	    #print len(new)
	    string_new=new.split('$$$$')
            #print string_new
	    packetinfo=string_new[0]
	    #print "packet info%s"%packetinfo
	    packetdata=string_new[1]
	    #print "packet data%s"%packetdata
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
	
            
	    
            
       
        #except TimeoutException:
          #  return "Timeout"
        #finally:
        #    signal.signal(signal.SIGALRM, old_handler)  
        #signal.alarm(0)
        #return data
    
    #-------------GUI -- Check which attack is selected,get Ranking of protected methods for the specific attack (right panel of Controller) 
    def Ranking(self):    
        fopen=open('/home/Write/attacktype.txt','r') #GUI for checking the selected attack and then set the values of 8 aspects for specific attack.
        attack=fopen.readline()
        #type (attack)
        return str(attack)
    
    #-------------Check which method is chosen--------------------
    def ProtectMethod(self):
            fopen=open('/home/Write/methodtype.txt','r')
            ProtectM=fopen.readline()
        #type (ProtectM)
            return str(ProtectM)
    
    #-------------Calcultate the score for the attack (weight*value)-----------------
    
    def cScore(self,weight,costvalue):
        value=float(weight)*float(costvalue)
        return value
        
    #------------get the total score for one method of an Attack in 8 aspects--------------
    def allsum(self,attack,pmethod):
        filename="/home/Write/"+attack+"_"+pmethod
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
        total=float(cost)+float(rec)+float(per)+float(eff)+float(ect)
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
        return total
    
    def udprankfun(self):
        newlist={}
        filename="/home/Write/"
        udpips=filename+"UDP_IPS_totalscore.txt"
        udpdisable=filename+"UDP_Port Disablement_totalscore.txt"
        udpdisconnect=filename+"UDP_Legal Flow Filtering_totalscore.txt"
        udpfire=filename+"UDP_Network Disconnection_totalscore.txt"
        udpshut=filename+"UDP_Firewall_totalscore.txt"
        udponly=filename+"UDP_Host Shutdown_totalscore.txt"        
        udpbool1=os.path.isfile(udpips)
        udpbool2=os.path.isfile(udpdisable)
        udpbool3=os.path.isfile(udpdisconnect)
        udpbool4=os.path.isfile(udpfire)
        udpbool5=os.path.isfile(udpshut)
        udpbool6=os.path.isfile(udponly)
        #-----------Get total value for each protected method for UDP Flood Attack----------    
        if(udpbool1==True):
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
            filename="/home/Write/"
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
            filename="/home/Write/"
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
            filename="/home/Write/"
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
        
    #----------------send shutdown signal to host----------

    def Shutdown(self):
    
        print "The host is shutted down \n"
        """os.system("python shutdownsend.py") # run shutdown script"""
        Shut=ShutDown()
    #----------------send disconnection signal to host----------
    
    def disconnection(self):
        print "The host is disconnect to network \n"
        """os.system("python disconnection.py") # run disconnection script"""
        Disconnect()
    #----------------send disconnection signal to host----------
    
    def Legalflow(self):
        print "The host only allow registered user to access resources \n"
        """os.system("python legalflowsignal.py")"""
        Legal=LegalFlow()
    #----------------send Replica signal to Replica host----------
    def Replica(self):
	print "The host is under attacked, the Process/Thread which consumes the most CPU and Mem will be terminated or the priority of certain Process/Thread will be adjusted   \n"
        """os.system("python Priority.py")"""
        ChangeHost()
    #----------------send Kill/Adjust Process Priority signal to host----------
    def Priority(self):
	print "The host is under attacked, the Process/Thread which consumes the most CPU and Mem will be terminated or the priority of certain Process/Thread will be adjusted   \n"
        """os.system("python Priority.py")"""
        KillPriority()
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
            return r
        #-----------------Dynamic Module to analyze novel attack packets---------------
    def unknown(self,router):
        if(os.path.isfile('/home/file/capunknown.txt')==True):
            os.system("rm /home/file/capunknown.txt ")
  	    if(os.path.isfile('/home/file/capunknowncontent.txt')==True): 
              os.system("rm /home/file/capunknowncontent.txt ")
        self.router=router
        self.router.hlabel.SetLabel('')
        vmnew="Dynamically Detect Unknown Attack \n"
        self.log.writeText(vmnew,'BLUE')
        hostnew=""    
        point=0 
        point1=0    
        ipdest="-> 1.0.0.2"
        su="UDP Source port:"
        su1="TCP"
        su2="ICMP"
        #os.system('tshark -i eth0 -c 20  -R "ip.dst==1.0.0.2"  > /home/file/capunknown.txt')  #wireshark
        #os.system('tshark -i eth0 -c 20 -e data -T fields -R "ip.dst==1.0.0.2"  > /home/file/capunknowncontent.txt')   #collect data part  """
        
        thread.start_new_thread(self.communication_send,())
        thread.start_new_thread(self.communication_receive,())
        #funknown=open('/home/file/capunknown.txt','r')#save in file for 
        #flength=funknown.readlines()
        #fnumber=len(flength)
        #funknown.close()    
        #string=[]   
        #routernew=""
        #if (fnumber==0):
        #  print "empty"
        #  os.system('tshark -i eth0 -c 700 -R "tcp and ip.dst==1.0.0.2"  > /home/capunknown.txt')                #else:
        time.sleep(40)
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
                    #print routernew
		    
		          
                    #RouterPanel.icon=wx.StaticBitmap(self, bitmap=wx.Bitmap('connect.png'),pos=(250,50))
                    self.ssh_cmd(ip, user, passwd, cmd)
                    self.ssh_cmd(ip, user, passwd, cmd3)
                    self.ssh_cmd(ip, user, passwd, cmd4)
                    #self.router.hlable=wx.StaticText(self.router,-1,label=con4,pos=(200,80))
                    self.router.hlabel.SetLabel(con4)
                    self.router.hlabel.SetForegroundColour('Blue')
                    self.log.writeText(con4,'BLACK')
                    #----------------Set Iptables for the VM mirroring-------------
                    cmd1="iptables -t nat -A PREROUTING -d 1.0.0.9 -p udp --dport %d -j DNAT --to 1.0.0.2:%d"%(dstport,dstport)
                    cmd2="iptables -A FORWARD -d 1.0.0.2 -p udp --dport %d -j ACCEPT"%dstport
                    cmd5='iptables -I FORWARD -d 1.0.0.2 -p udp --dport %d -j QUEUE'%dstport
                    cont5= "The protected VM forwards the legal packets (IPS) to the attacked Host\n"
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
                    #--------------default method to protect against UDP zero day attack is to use IPS------------------
                    fsnort.write('drop udp %s any -> 1.0.0.2 %d (msg:"drop more udp";content:%s;sid:100;)'%(src,dstport,newcontent)) #dynamically add new rules in Snort_inline my.rules file for filtering attacks.
                    fsnort.write('\n')
                    fcontent.close()
                    fsnort.close()      
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
                    vmnew=vmnew+'\n'+con1
                    print con1
                    self.log.writeText(con1,'BLUE')
                    tmp=l2.split(' ')
                    leng=len(tmp)
                    for i in range (0,leng):
                        if(cmp(tmp[i],'')!=0):
                            string.append(tmp[i])        
                    src=string[1] #analyze NO.
                    ds=string[7]          
                    if (cmp(ds,"netbios-ssn")==0): #example if it is TCP 139
                        dstport='139' 
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
                    cmd3="iptables -A FORWARD -d 1.0.0.2 -p tcp --dport %s -j ACCEPT"%dstport
                    cmd4="iptables -A FORWARD -d 1.0.0.9 -p tcp --dport %s -j ACCEPT"%dstport     
                    con3= "TCP packets are redirected to the protected VM from the router\n"
                    routernew=con3
                    print con3
                    
                    self.ssh_cmd(ip, user, passwd, cmd)
                    self.ssh_cmd(ip, user, passwd, cmd3)
                    #self.ssh_cmd(ip, user, passwd, cmd4)
                    #self.router.hlable=wx.StaticText(self.router,-1,label=con3,pos=(200,80)
                    self.router.hlabel.SetLabel(con3)
                    self.router.hlabel.SetForegroundColour('Blue')
                    self.log.writeText(con3,'BLACK')
                    #------------VM commands for mirroring------------
                    cmd1="iptables -t nat -A PREROUTING -d 1.0.0.9 -p udp --dport %s -j DNAT --to 1.0.0.2:%s"%(dstport,dstport)
                    cmd2="iptables -A FORWARD -d 1.0.0.2 -p tcp --dport %s -j ACCEPT"%dstport 
                    #cmd3='iptables -I FORWARD -d 1.0.0.2 -p udp --dport %d -j QUEUE'%dstport    
                    con4= "Drop the TCP SYN Attack packtes\n"
                    vmnew=vmnew+'\n'+con4
                    print con4
                    self.log.writeText(con4,'BLUE')
                    os.system(cmd1)
                    os.system(cmd2) 
                    os.system('iptables -A FORWARD -p tcp -d 1.0.0.2 --dport %s -j DROP'%dstport)                     
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
                        os.system("snort_inline -c /etc/snort_inline/snort_inline.conf -Q -N -l /var/log/snort_inline/ \-t /var/log/snort_inline/ -v -D")#run snort_inline """
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
                    
                    #HostButton.icon = wx.StaticBitmap(self, bitmap=wx.Bitmap('disconnect.png'),pos=(200,50))
                    fhostnew.write(hostnew)
                    fhostnew.close()

    def Defaultfun(self,vm,host,router,previous):
       
                self.vm=vm
                self.router=router
                self.host=host      
    	        #GlobeFun=Globe(self.log)
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
                    
                print "Collecting current measurements of the system\n"
                #self.log.Clear()
                self.log.writeText('Collecting current measurements of the system','BLUE')
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
                pre_icmp=icmp*100/number2    
                pre_udp=udp*100/number2
                pre_tcp=tcp*100/number2
                pre_pod=pod*100/number2
                pre_normal=normal*100/number2    
                List={'ICMP':pre_icmp,'UDP':pre_udp,'TCPSYN':pre_tcp,'POD':pre_pod,'Normal':pre_normal} #list check largest probability    
                sort=sorted(List.items(), key=lambda d: d[1])
                large=sort[len(sort)-1]  #predicted attack     
                preattack=large[0]
                preattack2=sort[2]    
                preattack3=sort[1]    
                preattack4=sort[0]
                print "IDS module is running and the flow is defined as: %s\n"% preattack
                connection1="The suspicious flow is defined as %s "%preattack
                print preattack
                #self.log.writeText(connection1,'BLUE')
                if(cmp(preattack,'Normal')!=0):
                    
                    
                    self.vm.icon.SetLabel('Current flow on VM is attack %s'%preattack)
                    
                    self.vm.icon.SetForegroundColour('Red')
                    
                    #print "works"
                if(cmp(preattack,'Normal')==0):
                    
                    #VPanel=Vmpanel()
                    #self.rlabel = wx.StaticText(self,-1,label=u' ',pos=(0,80))  
                    self.vm.icon.SetLabel('Current flow on VM is Normal')
                    self.vm.icon.SetForegroundColour('Green')
                    #print "Normal works"
                  
                self.log.writeText(connection1,'BLUE')
               
                
                #----host state----
                hostabnormal=self.receive() # call receive function to get the state of the host, is it under attack or not.
                connection2="The anomaly-based IDS on Host detected the victim host(Before Protected Method implemented) is: %s\n"%hostabnormal
                print connection2
                self.log.writeText(connection2,'GREEN')
                hostconnection=connection2
                if(cmp(hostabnormal,'Normal')!=0):
                    self.host.hlabel.SetLabel(hostabnormal)
                    self.host.hlabel.SetForegroundColour('Red')
                elif(cmp(hostabnormal,'Normal')==0):                       
                    self.host.hlabel.SetLabel(hostabnormal)
                    self.host.hlabel.SetForegroundColour('Green')
                #------------------Implement IPS for Attacks---------------------
                if(cmp(preattack,'UDP')==0 or cmp(preattack,'ICMP')==0 or cmp(preattack,'POD')==0): 
              
                    connection3="The controller selects IPS to protect against attack\n" 
                    self.log.writeText(connection3,'BLUE')       
                    connection1=connection1+'\n'+connection3        
                    self.UDP() #run snort_inline        
                    connection4="IPS is running in the background\n"    
                    self.log.writeText(connection4,'BLUE')    
                    connection1=connection1+'\n'+connection4
                    if (cmp(previous,'Network Disconnection')==0 ): #Remind System Administrator, if last loop implemented method is 'Network Disconnection adapter' or 'shutdown host',
                                                                         # Please make sure the host is connected to network properly
            
                        Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                        self.log.writeText(Connectionsp,'RED')
                        connection1=connection1+'\n'+Connectionsp
                    
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                        self.log.writeText(Connectionsp,'RED')
                        connection1=connection1+'\n'+Connectionsp
                if(cmp(preattack,'TCPSYN')==0):
                    connection5="The controller selects Port Disablement to protect against TCPSYN attack \n"
                    connection1=connection1+'\n'+connection5
                    self.log.writeText(connection5,'BLUE')   
                    print connection5
                    self.TCP2() #TCP Port Disablement
                    connection6="TCPSYN packets pasing through port 135 are considered as TCPSYN attack and is dropped\n"
                    self.log.writeText(connection6,'BLUE')   
                    
                    connection1=connection1+'\n'+connection6
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="Last State the host was shut down, please make sure the host is turned on."
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                    
                if (cmp(preattack,'Normal')==0):    #No attack
                    Connectionx="No attack. The controller does not need to take a preventive action.\n"  
                    self.log.writeText(Connectionx,'BLUE')          
                    connection1=connection1+'\n'+Connectionx
                    print "Normal connection1,%s " %connection1
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                        self.log.writeText(Connectionsp,'RED')
                        connection1=connection1+'\n'+Connectionsp        
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="Last State the host was shut down, please make sure the host is turned on."
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
            
                host2=self.receive()      
                connection14="The anomaly-based IDS on Host detected the state of the host (after running protection method) as: %s\n"%host2
                self.log.writeText(connection14,'GREEN')
                if(cmp(host2,'Normal')!=0):
                    #self.host.llabel=wx.StaticText(self.host,-1,label=host2,pos=(520,80))
                    self.host.llabel.SetLabel(host2)
                    self.host.llabel.SetForegroundColour('Red')
                elif(cmp(host2,'Normal')==0):
                    #self.host.llabel=wx.StaticText(self.host,-1,label=host2,pos=(520,80)
                    self.host.llabel.SetLabel(host2)
                    self.host.llabel.SetForegroundColour('Green')
            
                print connection14
                hostnew=""
                connectnew=""
                hostnew=hostnew+'\n'+connection14
                fvm3=open('/home/Write/vmstring.txt','a')    
                #-- Dynamic module run unknow() function if the previous method cannot protect the host (novel attack) or the host is under heavy load (cannot communicate with host) --------------------
                if(((cmp(hostabnormal,'Abnormal')==0) and (cmp(host2,'Abnormal')==0))or ((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'Abnormal')==0))):
                    connection15= "The attack is not in database or it is misclassified. The wireshark is analyzing attack packets\n"
                    self.log.writeText(connection15,'RED')
                    connectnew=connectnew+'\n'+connection15
                    fvm3.write(connectnew)
                    fvm3.close()            
                    self.unknown(self.router)
            
                    
                if(((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'Timeout')==0)) or ((cmp(hostabnormal,'Abnormal')==0) and (cmp(host2,'Timeout')==0))):
                        if (cmp(previous,'Network Disconnection')==0 ):  # 'Timeout' state of host means heavy load or the host is not in the network (disabled network adapter or shut down),check whether the
                                                                              # host is under heavy load or needed to be connected to network or not.
                
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            self.log.writeText(Connectionsp,'RED')
                            fvm3.write(Connectionsp)
                            fvm3.close()            
                            
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"      
                            self.log.writeText(Connectionsp,'RED')      
                            fvm3.write(connectnew)
                            fvm3.close()
                
                        else:            
                            connection18="Host is under heavy load because of unknown attacking\n"
                            self.log.writeText(connection18,'BLUE')
                            connectnew=connectnew+'\n'+connection18            
                            fvm3.write(connectnew)
                            fvm3.close()        
                            self.unknown(self.router)
                        
                if((cmp(hostabnormal,'SQL Injection Attack')==0) or (cmp(host2,'SQL Injection Attack')==0) ):
			connectionsql="Host suffers SQL Injection Attack though VM and Host behave like Normal\nMod_Security in Host drops malicious http requests."
			      
                        self.log.writeText(connectionsql,'RED')     
                print "--------------------------------"    
                fhost3=open('/home/Write/hoststring.txt','a')
                fhost3.write(hostnew)
                fhost3.close()
                return previous
    
     #================================================
     #---------------Port Disablement----------------
     #================================================
    def Disablefun(self,vm,host,router,previous):
                self.vm=vm
                self.host=host
                self.router=router
                #GlobeFun=Globe(self.log)
                if(os.path.isfile('/home/Write/vmstring.txt')==True):
                    os.system("rm /home/Write/vmstring.txt ")
                if(os.path.isfile('/home/Write/hoststring.txt')==True):
                    os.system("rm /home/Write/hoststring.txt ")
                if(os.path.isfile('/home/Write/routerstring.txt')==True):
                    os.system("rm /home/Write/routerstring.txt ")
                #i=i+1        
                print "Collecting current measurements of the system\n"
                #self.log.Clear()
                self.log.writeText('Collecting current measurements of the system','BLUE')
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
                
                pre_icmp=icmp*100/number2    
                pre_udp=udp*100/number2
                pre_tcp=tcp*100/number2
                pre_pod=pod*100/number2
                pre_normal=normal*100/number2
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
                if(cmp(preattack,'Normal')!=0):                   
                    #self.vm.icon=wx.StaticText(self.vm, label=u'Current flow on VM is attack %s'%preattack,pos=(520,40))
                    self.vm.icon.SetLabel('Current flow on VM is attack %s'%preattack)
                    self.vm.icon.SetForegroundColour('Red')                   
                    print "works"
                if(cmp(preattack,'Normal')==0):                  
                  
                    #self.vm.icon=wx.StaticText(self.vm, label=u'Current flow on VM is Normal',pos=(520,40))
                    self.vm.icon.SetLabel('Current flow on VM is Normal')
                    self.vm.icon.SetForegroundColour('Green')
                    print "Normal works"


              
                hostabnormal=self.receive()
                connection2="The anomaly-based IDS on host identified host (before protection method implemeted) as : %s\n"%hostabnormal    
                hostconnection=connection2 
                self.log.writeText(connection2,'GREEN')
                print connection2
                if(cmp(hostabnormal,'Normal')!=0):
                    self.host.hlabel.SetLabel(hostabnormal)
                    self.host.hlabel.SetForegroundColour('Red')
                elif(cmp(hostabnormal,'Normal')==0):
                    self.host.hlabel.SetLabel(hostabnormal)
                    self.host.hlabel.SetForegroundColour('Green')
                #-------------------UDP Port Disablement--------------
                if(cmp(preattack,'UDP')==0):
                    connection5="The controller selects Port Disablement to protect against UDP flood attack \n"
                    connection1=connection1+'\n'+connection5
                    self.log.writeText(connection5,'BLUE')   
                    print connection5
                    connection6="The UDP packets pass through port 5009 are considered as UDP flood which and is dropped\n"
                    self.UDP2() #UDP Port Disablement
                    self.log.writeText(connection6,'BLUE')   
                   
                    connection1=connection1+'\n'+connection6
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                    
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                #----------------TCP Disable-----------
                if(cmp(preattack,'TCPSYN')==0):
                    connection5="The controller selects Port Disablement to protect against TCPSYN attack \n"
                    connection1=connection1+'\n'+connection5
                    self.log.writeText(connection5,'BLUE')   
                    print connection5
                    self.TCP2() #TCP Port Disablement
                    connection6="TCPSYN packets pasing through port 135 are considered as TCPSYN attack and is dropped\n"
                   
                    self.log.writeText(connection6,'BLUE')   
                    
                    connection1=connection1+'\n'+connection6
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                     
                 
                #-------------------ICMP POD-------------
                if(cmp(preattack,'ICMP')==0 or cmp(preattack,'POD')==0 ):
                    connection5="The controller selects Port Disablement to protect against ICMP protocal attacks,\n but no port is used in ICMP protocal transmission,\n drop the ICMP packets instead\n"
                    connection1=connection1+'\n'+connection5
                    self.log.writeText(connection5,'BLUE')
                    print connection5
                    self.POD2() #disable all icmp packets
                    connection6="ICMP Packets to the host are dropped\n"   
                    self.log.writeText(connection6,'BLUE')     
                    connection1=connection1+'\n'+connection6
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                if (cmp(preattack,'Normal')==0):    
                        Connectionx="No attack. The controller does not need to take a preventive action.\n"    
                        self.log.writeText(Connectionx,'BLUE')        
                        connection1=connection1+'\n'+Connectionx
                        print "Normal connection1,%s " %connection1
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                fvm=open('/home/Write/vmstring.txt','w')    
                fvm.write(connection1)
                fvm.close()
                fhost=open('/home/Write/hoststring.txt','w')
                fhost.write(hostconnection)
                fhost.close()
                #-------------------------receive state from host-------------------------------
                host2=self.receive()      
                connection14="The anomaly-based IDS on host identified host (after protection method implemented) as: %s\n"%host2
                print connection14    
                self.log.writeText(connection14,'GREEN')
                if(cmp(host2,'Normal')!=0):
                    self.host.llabel.SetLabel(host2)
                    self.host.llabel.SetForegroundColour('Red')
                elif(cmp(host2,'Normal')==0):
                    self.host.llabel.SetLabel(host2)
                    self.host.llabel.SetForegroundColour('Green')
                
                hostnew=""
                connectnew=""
                hostnew=hostnew+'\n'+connection14
                fvm3=open('/home/Write/vmstring.txt','a')    
                if(((cmp(hostabnormal,'Abnormal')==0) and (cmp(host2,'Abnormal')==0))or ((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'Abnormal')==0))):
                    connection15= "The attack is not in database or it is misclassified. The wireshark is analyzing attack packets\n"
                    self.log.writeText(connection15,'BLUE')
                    connectnew=connectnew+'\n'+connection15
                    fvm3.write(connectnew) #message print on VM panel
                    fvm3.close()    
                    self.unknown(self.router)        
                
                if(((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'Timeout')==0)) or ((cmp(hostabnormal,'Abnormal')==0) and (cmp(host2,'Timeout')==0))):
                    if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            fvm3.write(Connectionsp)#message print on VM panel
                            fvm3.close()    
                            self.log.writeText(Connectionsp,'RED')
                    elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"            
                            fvm3.write(connectnew)
                            fvm3.close()
                            self.log.writeText(Connectionsp,'RED')
                    else:
                            connection18="Host is under heavy load because of unknown attacking\n"
                            self.log.writeText(connection18,'BLUE')
                            connectnew=connectnew+'\n'+connection18
                            print connectnew
                            fvm3.write(connectnew)
                            fvm3.close()        
                            self.unknown(self.router)            
                if((cmp(hostabnormal,'SQL Injection Attack')==0) or (cmp(host2,'SQL Injection Attack')==0) ):
			connectionsql="Host suffers SQL Injection Attack though VM and Host behave like Normal\nMod_Security in Host drops malicious http requests."
			      
                        self.log.writeText(connectionsql,'RED')   
                print "--------------------------------"        
                fhost3=open('/home/Write/hoststring.txt','a')
                fhost3.write(hostnew)
                fhost3.close()
                return previous

   
    #==============================================================================
    #--------------Choose "Ranking" to protect the host-------------------------- 
    #----------------(Based on method rankings)----------------------------------
    #==============================================================================
    def OnStart(self,vm,host,router,previous):
                self.vm=vm
                self.host=host
                self.router=router
                #GlobeFun=Globe(self.log)
                if(os.path.isfile('/home/Write/vmstring.txt')==True):
                    os.system("rm /home/Write/vmstring.txt ")
                if(os.path.isfile('/home/Write/hoststring.txt')==True):
                    os.system("rm /home/Write/hoststring.txt ")
                if(os.path.isfile('/home/Write/routerstring.txt')==True):
                    os.system("rm /home/Write/routerstring.txt ")
                #i=i+1  
                print "on start"
                print "Collecting current measurements of the system\n"
                self.log.writeText('Collecting current measurements of the system','BLUE')
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
                pre_icmp=icmp*100/number2
                pre_udp=udp*100/number2
                pre_tcp=tcp*100/number2
                pre_pod=pod*100/number2
                pre_normal=normal*100/number2
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
                if(cmp(preattack,'Normal')!=0):
                    
                    
                    self.vm.icon.SetLabel('Current flow on VM is attack %s'%preattack)
                    
                    self.vm.icon.SetForegroundColour('Red')
                    
                    #print "works"
                elif(cmp(preattack,'Normal')==0):
                    
                    #VPanel=Vmpanel()
                    #self.rlabel = wx.StaticText(self,-1,label=u' ',pos=(0,80))  
                    self.vm.icon.SetLabel('Current flow on VM is Normal')
                    self.vm.icon.SetForegroundColour('Green')
                    #print "Normal works"              
                hostabnormal=self.receive()                
                connection2="The anomaly-based IDS on host identified host (before protection method implemeted) as : %s\n"%hostabnormal
                hostconnection=connection2  #hostconnection print on host panel    
                self.log.writeText(connection2,'GREEN')
                print connection2 
                if(cmp(hostabnormal,'Normal')!=0):
                    self.host.hlabel.SetLabel(hostabnormal)
                    self.host.hlabel.SetForegroundColour('Red')
                elif(cmp(hostabnormal,'Normal')==0):
                    self.host.hlabel.SetLabel(hostabnormal)
                    self.host.hlabel.SetForegroundColour('Green')               
                if (cmp(preattack,'UDP')==0): # if the suspcious flow is UDP attack
                                       
                    udplist=self.udprankfun()
                    udpbest=self.udpbest
                    #udpbest=udplist[1]
                    if(cmp(udpbest,'IPS')==0):  # if the best method to solve UDP attack is IPS
                        connection3="The controller selects IPS to protect against UDP flood attack\n"        
                        connection1=connection1+'\n'+connection3       
                        self.log.writeText(connection3,'BLUE') 
                        print connection1
                        self.UDP() #IPS        
                        connection4="IPS is running in the background\n"
                        self.log.writeText(connection4,'BLUE')
                        print connection4
                        connection1=connection1+'\n'+connection4
                        
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                    elif (cmp(udpbest,'Port Disablement')==0):#if 'Port Disablement' is the best method    
                        connection5="The controller selects Port Disablement to protect against UDP flood attack\n"
                        connection1=connection1+'\n'+connection5
                        self.log.writeText(connection5,'BLUE')
                        print connection5
                        self.UDP2()   #UDP disable certain port
                        connection6="The UDP packets passing through port 5009 are considered as UDP flood and is dropped\n"
                        
                        self.log.writeText(connection6,'BLUE')
                        connection1=connection1+'\n'+connection6
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                            connection1=connection1+'\n'+Connectionsp     
                            self.log.writeText(Connectionsp,'RED')
                               
                    elif(cmp(udpbest,'Network Disconnection')==0): #if 'Network Disconnection ' is the best method
                            connection7= "The controller selects Network Disconnection to protect against attack\n"
                            print connection7      
                            self.log.writeText(connection7,'BLUE')  
                            connection1=connection1+'\n'+connection7        
                            self.disconnection() #call function
                            connection8="Host network is disabeled.\n"
                            self.log.writeText(connection8,'GREEN')
                            
                            hostconnection = hostconnection+connection8
                            print hostconnection        
                            if (cmp(previous,'Network Disconnection')==0 ):
                                Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                                connection1=connection1+'\n'+Connectionsp 
                                self.log.writeText(Connectionsp,'RED')
                                       
                            elif( cmp(previous,'Host Shutdown')==0  ):
                                Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
                            previous="Network Disconnection"
                    
                    elif (cmp(udpbest,'Firewall')==0): #if 'Firewall' is the best option
                            connection9= "The OS default firewall is the best method which has already runned\n"
                            self.log.writeText(connection9,'BLUE')
                            connection1=connection1+'\n'+connection9        
                            if (cmp(previous,'Network Disconnection')==0 ):
                                Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
                                
                            elif( cmp(previous,'Host Shutdown')==0  ):
                                    Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                                    connection1=connection1+'\n'+Connectionsp   
                                    self.log.writeText(Connectionsp,'RED')     
                    
                    elif(cmp(udpbest,'Legal Flow Filtering')==0):        #if only let legal user access attacks
                            connection10="Only legal users can access resources"
                            self.log.writeText(connection1,'GREEN')
                            connection1=connection1+'\n'+connection10
                            self.Legalflow()
                            connection11="Registered user can access confidential data"
                            self.log.writeText(connection11,'BLUE')
                            hostconnection = hostconnection+'\n'+connection10+'\n'+connection11
                            print hostconnection    
                            if (cmp(previous,'Network Disconnection')==0 ):
                                Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
                            
                            elif( cmp(previous,'Host Shutdown')==0  ):
                                Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
            
            
                    elif (cmp(udpbest,'Host Shutdown')==0):        
                            connection12="Shut Down the Host is the best method."
                            self.log.writeText(connection12,'BLUE')
                            connection1=connection1+'\n'+connection12
                            self.Shutdown()
                            connection13="The host is shutted"
                            hostconnection = hostconnection+'\n'+connection13
                            self.log.writeText(connection13,'GREEN')
                            if (cmp(previous,'Network Disconnection')==0 ):
                                Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
                            
                            elif( cmp(previous,'Host Shutdown')==0  ):
                                Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
                            previous="Host Shutdown"
            
            #---------------TCP SYN ATTACK protected method----------------
            
                if (cmp(preattack,'TCPSYN')==0):  # If the suspicious flow is TCP_SYN attack
                   
                    self.tcprankfun()
                    tcpbest=self.tcpbest
                    #tcpbest=tcplist[1]
                    #print tcpbest
                    #self.log.Clear()
                    if(cmp(tcpbest,'IPS')==0):
                            connection3="The controller selects Network Disconnection to protect against attack\n"        
                            connection1=connection1+'\n'+connection3          
                            self.log.writeText(connection3,'BLUE')
                            self.UDP() #IPS        
                            connection4="IPS is running in the background\n"        
                            connection1=connection1+'\n'+connection4
                            self.log.writeText(connection4,'BLUE')
                            if (cmp(previous,'Port Disablement')==0 ): #Network Disconnection.
                                    Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                                    connection1=connection1+'\n'+Connectionsp
                                    self.log.writeText(Connectionsp,'RED')
                            
                            elif( cmp(previous,'Host Shutdown')==0  ): #shutdown host
                                    Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                                    connection1=connection1+'\n'+Connectionsp
                                    self.log.writeText(Connectionsp,'RED')
                        
                    elif (cmp(tcpbest,'Port Disablement')==0): # Port Disablement
                            connection5="The controller selects Port Disablement to protect against TCPSYN attack \n"
                            connection1=connection1+'\n'+connection5
                            self.log.writeText(connection5,'BLUE')
                            
                            self.TCP2()
                            connection6="The TCPSYN packets pass through port 135 are considered as TCPSYN attack which are dropped\n"
                            self.log.writeText(connection6,'BLUE')
                            connection1=connection1+'\n'+connection6
                            if (cmp(previous,'Network Disconnection')==0 ):
                                Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
                            
                            elif( cmp(previous,'Host Shutdown')==0  ):
                                Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
            
                    elif(cmp(tcpbest,'Network Disconnection')==0): #Network Disconnection
                                connection7= "The controller selects Network Disconnection to protect against attack\n"
                                print connection7        
                                self.log.writeText(connection7,'BLUE')
                                connection1=connection1+'\n'+connection7        
                                self.disconnection()
                                connection8="Host network is disabeled.\n"
                                self.log.writeText(connection8,'GREEN')
                                hostconnection = hostconnection+connection8
                                print hostconnection        
                        
                                if (cmp(previous,'Network Disconnection')==0 ):
                                    Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                                    connection1=connection1+'\n'+Connectionsp
                                    self.log.writeText(Connectionsp,'RED')
                            
                                elif( cmp(previous,'Host Shutdown')==0  ):
                                    Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                                    connection1=connection1+'\n'+Connectionsp
                                    self.log.writeText(Connectionsp,'RED')
                                previous="Network Disconnection"
                                
                    elif (cmp(tcpbest,'Firewall')==0): #firewall
                        connection9= "The OS default firewall is the best method which has already runned\n"
                        self.log.writeText(connection9,'BLUE')
                        connection1=connection1+'\n'+connection9        
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif(cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                            connection1=connection1+'\n'+Connectionsp   
                            self.log.writeText(Connectionsp,'RED')     
                    
                    elif(cmp(tcpbest,'Legal Flow Filtering')==0):        
                            connection10="Only legal users can access resources"
                            self.log.writeText(connection10,'BLUE')
                            connection1=connection1+'\n'+connection10
                            self.Legalflow()#call function
                            connection11="Registered user can access confidential data"
                            hostconnection = hostconnection+connection11
                            self.log.writeText(connection11,'GREEN')
                            print hostconnection    
            
                            if (cmp(previous,'Network Disconnection')==0 ): #Network Disconnection
                                Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
                            
                            elif( cmp(previous,'Host Shutdown')==0  ):
                                Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
            
                    elif (cmp(tcpbest,'Host Shutdown')==0): #shutdown
                    
                            connection12="Shut Down the Host is the best method."
                            connection1=connection1+'\n'+connection12
                            self.log.writeText(connection12,'BLUE')
                            self.Shutdown()
                            connection13="The host is shutted"
                            self.log.writeText(connection13,'GREEN')
                            if (cmp(previous,'Network Disconnection')==0 ):
                                Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                                connection1=connection1+'\n'+Connectionsp  
                                self.log.writeText(Connectionsp,'RED')
                                      
                            elif( cmp(previous,'Host Shutdown')==0  ):
                                Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                                connection1=connection1+'\n'+Connectionsp
                                self.log.writeText(Connectionsp,'RED')
                            previous="Host Shutdown"
            
            #--------------------POD protected method--------------------------------
            
                if (cmp(preattack,'POD')==0):
                    
                    
                    podlist=self.podrankfun()
                    podbest=podlist[1]
                    if(cmp(podbest,'IPS')==0):
                        connection3="The controller selects IPS to protect against POD attack\n"        
                        connection1=connection1+'\n'+connection3   
                        self.log.writeText(connection3,'BLUE')     
                        print connection1
                        self.POD() #POD snort_inline        
                        connection4="IPS is running in the background\n"
                        self.log.writeText(connection4,'BLUE')
                        print connection4
                        connection1=connection1+'\n'+connection4
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                    
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                    elif (cmp(podbest,'Port Disablement')==0):        
                        connection5="The controller selects Port Disablement to protect against ICMP protocal attacks,\n but no port is used in ICMP protocal transmission,\n drop the ICMP packets instead\n"
                        connection1=connection1+'\n'+connection5
                        self.log.writeText(connection5,'BLUE')
                        print connection5
                        self.POD2()
                        connection6="ICMP Packets to the host are dropped\n"   
                        self.log.writeText(connection6,'BLUE')     
                        connection1=connection1+'\n'+connection6
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
            
                    elif(cmp(podbest,'Network Disconnection')==0):
                        connection7= "The controller selects Network Disconnection to protect against attack\n"
                        print connection7        
                        self.log.writeText(connection7,'BLUE')
                        connection1=connection1+'\n'+connection7
                        self.disconnection()
                        connection8="Host network is disabeled.\n"
                        self.log.writeText(connection8,'GREEN')
                        hostconnection = hostconnection+connection8
                        print hostconnection
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                    
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        previous="Network Disconnection"
                    elif (cmp(podbest,'Firewall')==0):
                        connection9= "The OS default firewall is the best method which has already runned\n"
                        self.log.writeText(connection9,'BLUE')
                        connection1=connection1+'\n'+connection9
                    
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                    
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                            connection1=connection1+'\n'+Connectionsp   
                            self.log.writeText(Connectionsp,'RED')     
                    
                    elif(cmp(podbest,'Legal Flow Filtering')==0):        
                        connection10="Only legal users can access resources"
                        self.log.writeText(connection10,'BLUE')
                        connection1=connection1+'\n'+connection10
                        self.Legalflow()
                        connection11="Registered user can access confidential data"
                        hostconnection = hostconnection+connection10
                        print hostconnection        
                
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif(cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                
                    elif (cmp(podbest,'Host Shutdown')==0):        
                        connection12="Shut Down the Host is the best method."
                        self.log.writeText(connection12,'BLUE')
                        connection1=connection1+'\n'+connection12
                        self.Shutdown()
                        connection13="The host is shutted"
                        self.log.writeText(connection13,'GREEN')
                        
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        previous="Host Shutdown"
                
            #----------------------Normal--------------
                if (cmp(preattack,'Normal')==0): 
                        #self.vm.icon.SetLabel('Current flow on VM is Normal')
                        #self.vm.icon.SetForegroundColour('Green')   
                        Connectionx="No attack. The controller does not need to take a preventive action.\n"            
                        connection1=connection1+'\n'+Connectionx
                        self.log.writeText(Connectionx,'BLUE')
                        print "flow is normal"
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
            
            #---------------------ICMP------------------------------------------------
                if (cmp(preattack,'ICMP')==0): #ICMP Attack
                   
                    icmplist=self.icmprankfun()
                    icmpbest=icmplist[1]
                    if(cmp(icmpbest,'IPS')==0):
                        connection3="The controller selects IPS to protect against ICMP flood attack\n"        
                        connection1=connection1+'\n'+connection3   
                        self.log.writeText(connection3,'BLUE')     
                        print connection1
                        self.POD() #ICMP Protocol attack, same method as POD attack        
                        connection4="IPS is running in the background\n"
                        self.log.writeText(connection4,'BLUE')
                        print connection4
                        connection1=connection1+'\n'+connection4
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            connection1=connection1+'\n'+Connectionsp     
                            self.log.writeText(Connectionsp,'RED')
                               
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                                
                    elif (cmp(icmpbest,'Port Disablement')==0):        
                        connection5="The controller selects Port Disablement to protect against ICMP protocal attacks,\n but no port is used in ICMP protocal transmission,\n drop the ICMP packets instead\n"
                        connection1=connection1+'\n'+connection5
                        self.log.writeText(connection5,'BLUE')
                        print connection5
                        self.POD2()
                        connection6="ICMP Packets to the host are dropped\n"    
                        self.log.writeText(connection6,'BLUE')    
                        connection1=connection1+'\n'+connection6
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            connection1=connection1+'\n'+Connectionsp     
                            self.log.writeText(Connectionsp,'RED')
                               
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                    
                    elif(cmp(icmpbest,'Network Disconnection')==0):
                        connection7= "The controller selects Network Disconnection to protect against attack\n"
                        print connection7    
                        self.log.writeText(connection7,'BLUE')
                        connection1=connection1+'\n'+connection7
                        self.disconnection()
                        connection8="Host network is disabeled.\n"
                        hostconnection = hostconnection+connection8
                        self.log.writeText(connection8,'GREEN')
                        print hostconnection
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                
                        previous="Network Disconnection"
                    elif (cmp(icmpbest,'Firewall')==0):
                        connection9= "The OS default firewall is the best method which has already runned\n"
                        self.log.writeText(connection9,'BLUE')
                        connection1=connection1+'\n'+connection9
                        
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                            connection1=connection1+'\n'+Connectionsp   
                            self.log.writeText(Connectionsp,'RED') 
                    
                    elif(cmp(icmpbest,'Legal Flow Filtering')==0):        
                        connection10="Only legal users can access resources"
                        connection1=connection1+'\n'+connection10
                        self.log.writeText(connection10,'BLUE')
                        self.Legalflow()
                        connection11="Registered user can access confidential data"
                        self.log.writeText(connection11,'GREEN')
                        hostconnection = hostconnection+connection10
                        print hostconnection    
                
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                            
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                            connection1=connection1+'\n'+Connectionsp 
                            self.log.writeText(Connectionsp,'RED')
                            
                    elif (cmp(icmpbest,'Host Shutdown')==0):        
                        connection12="Shut Down the Host is the best method."
                        connection1=connection1+'\n'+connection12
                        self.log.writeText(connection12,'BLUE')
                        self.Shutdown()
                        connection13="The host is shutted"
                        self.log.writeText(connection13,'GREEN')
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            connection1=connection1+'\n'+Connectionsp
                            self.log.writeText(Connectionsp,'RED')
                        
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"
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
            
                host2=self.receive()  #attack or not
                connection14="The anomaly-based IDS on host identified host (after protection method implemented) as: %s\n"%host2
                print connection14
                self.log.writeText(connection14,'GREEN')
                if(cmp(host2,'Normal')!=0):
                    self.host.llabel.SetLabel(host2)
                    self.host.llabel.SetForegroundColour('Red')
                elif(cmp(host2,'Normal')==0):
                    self.host.llabel.SetLabel(host2)
                    self.host.llabel.SetForegroundColour('Green')
                hostnew=""
                connectnew=""
                hostnew=hostnew+'\n'+connection14
                fvm3=open('/home/Write/vmstring.txt','a')    
                if(((cmp(hostabnormal,'Abnormal')==0) and (cmp(host2,'Abnormal')==0))or ((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'Abnormal')==0))):
                    connection15= "The attack is not in database or it is misclassified. The wireshark is analyzing attack packets\n"
                    connectnew=connectnew+'\n'+connection15
                    self.log.writeText(connection15,'BLUE')
                    fvm3.write(connectnew)
                    fvm3.close()        
                    self.unknown(self.router) #if protected method does not work, dynamic module runs to check for zero day attacks.
                    
            
                if(((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'Timeout')==0)) or ((cmp(hostabnormal,'Abnormal')==0) and (cmp(host2,'Timeout')==0))):
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                        fvm3.write(Connectionsp)
                        fvm3.close()       
                        self.log.writeText(Connectionsp,'RED')     
                        
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="The last State the host was shutted down. Check if the host is turned on"            
                        fvm3.write(connectnew)
                        fvm3.close()
                        self.log.writeText(Connectionsp,'RED')
                    else:            
                        connection18="Host is under heavy load because of unknown attacking\n"
                        self.log.writeText(connection18,'BLUE')
                        connectnew=connectnew+'\n'+connection18
                        print connectnew
                        fvm3.write(connectnew)
                        fvm3.close()        
                        self.unknown(self.router)
                        
                        
                if((cmp(hostabnormal,'SQL Injection Attack')==0) or (cmp(host2,'SQL Injection Attack')==0) ):
			connectionsql="Host suffers SQL Injection Attack though VM and Host behave like Normal\nMod_Security in Host drops malicious http requests."
			      
                        self.log.writeText(connectionsql,'RED')      
                print "--------------------------------"
                #time.sleep(10)    
                fhost3=open('/home/Write/hoststring.txt','a')
                fhost3.write(hostnew)
                fhost3.close()    
                return previous
    def Replica_Priorityfun(self,vm,host,router,previous,connection10,function,connection11):
                self.vm=vm
                self.host=host
                self.router=router
                #GlobeFun=Globe(self.log)
                if(os.path.isfile('/home/Write/vmstring.txt')==True):
                    os.system("rm /home/Write/vmstring.txt ")
                if(os.path.isfile('/home/Write/hoststring.txt')==True):
                    os.system("rm /home/Write/hoststring.txt ")
                if(os.path.isfile('/home/Write/routerstring.txt')==True):
                    os.system("rm /home/Write/routerstring.txt ")
                #i=i+1        
                print "Collecting current measurements of the system\n"
                #self.log.Clear()
                self.log.writeText('Collecting current measurements of the system','BLUE')
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
            
                pre_icmp=icmp*100/number2    
                pre_udp=udp*100/number2
                pre_tcp=tcp*100/number2
                pre_pod=pod*100/number2
                pre_normal=normal*100/number2
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
                #previous=""
                if(cmp(preattack,'Normal')!=0):
                    
                    
                    
                    self.vm.icon.SetLabel('Current flow on VM is attack %s'%preattack)
                    self.vm.icon.SetForegroundColour('Red')
                    
                    #print "works"
                if(cmp(preattack,'Normal')==0):
                    self.vm.icon.SetLabel('Current flow on VM is Normal')
                    self.vm.icon.SetForegroundColour('Green')
                    #print "Normal works"
                hostabnormal=self.receive()
                connection2="The anomaly-based IDS on host identified host (before protection method implemeted) as : %s\n"%hostabnormal
                hostconnection=connection2 
                print connection2
                self.log.writeText(connection2,'GREEN')
                
                if(cmp(hostabnormal,'Normal')!=0):
                    self.host.hlabel.SetLabel(hostabnormal)
                    self.host.hlabel.SetForegroundColour('Red')
                elif(cmp(hostabnormal,'Normal')==0):
                    self.host.hlabel.SetLabel(hostabnormal)
                    self.host.hlabel.SetForegroundColour('Green')
                #---------------UDP,TCP, ICMP,pod------------
                if(cmp(preattack,'UDP')==0 or cmp(preattack,'TCPSYN')==0 or cmp(preattack,'ICMP')==0 or cmp(preattack,'POD')==0):
                    #connection10="The host is attacked, Legistimate Requests are sent to the Replica Server."
		    connection10
                    connection1=connection1+'\n'+connection10
                    self.log.writeText(connection10,'BLUE')
                    #self.Replica() #run Replica/Priority function
                    function
                    connection11
                    hostconnection = hostconnection+connection11
                    self.log.writeText(connection11,'BLUE')
                    print hostconnection
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                        
                if (cmp(preattack,'Normal')==0):    
                    Connectionx="No attack. The controller does not need to take a preventive action.\n"   
                    self.log.writeText(Connectionx,'BLUE')         
                    connection1=connection1+'\n'+Connectionx
                    print "Normal connection1,%s " %connection1
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                        
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="The last State the host was shutted down. Check if the host is turned on"
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
            
                host2=self.receive()      
                connection14="The anomaly-based IDS on host identified host (after protection method implemented) as: %s\n"%host2
                print connection14
                self.log.writeText(connection14,'GREEN')
                if(cmp(host2,'Normal')!=0):
                    self.host.llabel.SetLabel(host2)
                    self.host.llabel.SetForegroundColour('Red')
                elif(cmp(host2,'Normal')==0):
                    self.host.llabel.SetLabel(host2)
                    self.host.llabel.SetForegroundColour('Green')
                hostnew=""
                connectnew=""
                hostnew=hostnew+'\n'+connection14
                fvm3=open('/home/Write/vmstring.txt','a')
                
                if(((cmp(hostabnormal,'Abnormal')==0) and (cmp(host2,'Abnormal')==0))or ((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'Abnormal')==0))):
                    connection15= "The attack is not in database or it is misclassified. The Replica is running\n"
                    connectnew=connectnew+'\n'+connection15
                    self.log.writeText(connection15,'BLUE')
                    fvm3.write(connectnew)
                    fvm3.close()            
                    #self.unknown(self.router)
                    function
                    
                if(((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'Timeout')==0)) or ((cmp(hostabnormal,'Abnormal')==0) and (cmp(host2,'Timeout')==0))):
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            fvm3.write(Connectionsp)
                            fvm3.close()         
                            self.log.writeText(Connectionsp,'RED')   
                            
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"            
                            fvm3.write(connectnew)
                            fvm3.close()
                            self.log.writeText(Connectionsp,'RED')
                
                        else:            
                            connection18="Host is under heavy load because of unknown attack.\n"
                            connectnew=connectnew+'\n'+connection18
                            self.log.writeText(connection18,'BLUE')
                            print connectnew
                            fvm3.write(connectnew)
                            fvm3.close()        
                            #self.unknown(self.router) 
			    function           
                if((cmp(hostabnormal,'SQL Injection Attack')==0) or (cmp(host2,'SQL Injection Attack')==0) ):
			connectionsql="Host suffers SQL Injection Attack though VM and Host behave like Normal\nMod_Security in Host drops malicious http requests."
			      
                        self.log.writeText(connectionsql,'RED')      
                print "--------------------------------"
                fhost3=open('/home/Write/hoststring.txt','a')
                fhost3.write(hostnew)
                fhost3.close()
                return previous
#====================================================================
#-------------Combine IPS, Network Disconnection, Firewall,----------
#-------------Legal Flow Filtering, Host shutdown in one function----
#====================================================================
    def Combinefun(self,vm,host,router,previous,connection10,function,connection11):
                self.vm=vm
                self.host=host
                self.router=router
                #GlobeFun=Globe(self.log)
                if(os.path.isfile('/home/Write/vmstring.txt')==True):
                    os.system("rm /home/Write/vmstring.txt ")
                if(os.path.isfile('/home/Write/hoststring.txt')==True):
                    os.system("rm /home/Write/hoststring.txt ")
                if(os.path.isfile('/home/Write/routerstring.txt')==True):
                    os.system("rm /home/Write/routerstring.txt ")
                #i=i+1        
                print "Collecting current measurements of the system\n"
                #self.log.Clear()
                self.log.writeText('Collecting current measurements of the system','BLUE')
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
            
                pre_icmp=icmp*100/number2    
                pre_udp=udp*100/number2
                pre_tcp=tcp*100/number2
                pre_pod=pod*100/number2
                pre_normal=normal*100/number2
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
                #previous=""
                if(cmp(preattack,'Normal')!=0):
                    
                    
                    
                    self.vm.icon.SetLabel('Current flow on VM is attack %s'%preattack)
                    self.vm.icon.SetForegroundColour('Red')
                    
                    #print "works"
                if(cmp(preattack,'Normal')==0):
                    self.vm.icon.SetLabel('Current flow on VM is Normal')
                    self.vm.icon.SetForegroundColour('Green')
                    #print "Normal works"
                hostabnormal=self.receive()
                connection2="The anomaly-based IDS on host identified host (before protection method implemeted) as : %s\n"%hostabnormal
                hostconnection=connection2 
                print connection2
                self.log.writeText(connection2,'GREEN')
                
                if(cmp(hostabnormal,'Normal')!=0):
                    self.host.hlabel.SetLabel(hostabnormal)
                    self.host.hlabel.SetForegroundColour('Red')
                elif(cmp(hostabnormal,'Normal')==0):
                    self.host.hlabel.SetLabel(hostabnormal)
                    self.host.hlabel.SetForegroundColour('Green')
                #---------------UDP,TCP, ICMP,pod------------
                if(cmp(preattack,'UDP')==0 or cmp(preattack,'TCPSYN')==0 or cmp(preattack,'ICMP')==0 or cmp(preattack,'POD')==0):
                    #connection10="Only legal users can access host's resources"
                    connection1=connection1+'\n'+connection10
                    self.log.writeText(connection10,'BLUE')
	            function
                    #self.Legalflow() #run legal function
                    #connection11="Registered user can access confidential data"
                    hostconnection = hostconnection+connection11
                    self.log.writeText(connection11,'BLUE')
                    print hostconnection
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="The last State the host was shutted down. Check if the host is turned on"
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                        
                if (cmp(preattack,'Normal')==0):    
                    Connectionx="No attack. The controller does not need to take a preventive action.\n"   
                    self.log.writeText(Connectionx,'BLUE')         
                    connection1=connection1+'\n'+Connectionx
                    print "Normal connection1,%s " %connection1
                    if (cmp(previous,'Network Disconnection')==0 ):
                        Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                        connection1=connection1+'\n'+Connectionsp
                        self.log.writeText(Connectionsp,'RED')
                        
                    elif( cmp(previous,'Host Shutdown')==0  ):
                        Connectionsp="The last State the host was shutted down. Check if the host is turned on"
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
            
                host2=self.receive()      
                connection14="The anomaly-based IDS on host identified host (after protection method implemented) as: %s\n"%host2
                print connection14
                self.log.writeText(connection14,'GREEN')
                if(cmp(host2,'Normal')!=0):
                    self.host.llabel.SetLabel(host2)
                    self.host.llabel.SetForegroundColour('Red')
                elif(cmp(host2,'Normal')==0):
                    self.host.llabel.SetLabel(host2)
                    self.host.llabel.SetForegroundColour('Green')
                hostnew=""
                connectnew=""
                hostnew=hostnew+'\n'+connection14
                fvm3=open('/home/Write/vmstring.txt','a')
                
                if(((cmp(hostabnormal,'Abnormal')==0) and (cmp(host2,'Abnormal')==0))or ((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'Abnormal')==0))):
                    connection15= "The attack is not in database or it is misclassified. The wireshark is analyzing attack packets\n"
                    connectnew=connectnew+'\n'+connection15
                    self.log.writeText(connection15,'BLUE')
                    fvm3.write(connectnew)
                    fvm3.close()            
                    self.unknown(self.router)
                
                    
                if(((cmp(hostabnormal,'Timeout')==0) and (cmp(host2,'Timeout')==0)) or ((cmp(hostabnormal,'Abnormal')==0) and (cmp(host2,'Timeout')==0))):
                        if (cmp(previous,'Network Disconnection')==0 ):
                            Connectionsp="The last state the host network was disabled by the controller. Check if the network is reconnected. Protection methods cannot work if the network is disconnected"
                            fvm3.write(Connectionsp)
                            fvm3.close()         
                            self.log.writeText(Connectionsp,'RED')   
                            
                        elif( cmp(previous,'Host Shutdown')==0  ):
                            Connectionsp="The last State the host was shutted down. Check if the host is turned on"            
                            fvm3.write(connectnew)
                            fvm3.close()
                            self.log.writeText(Connectionsp,'RED')
                
                        else:            
                            connection18="Host is under heavy load because of unknown attacking\n"
                            connectnew=connectnew+'\n'+connection18
                            self.log.writeText(connection18,'BLUE')
                            print connectnew
                            fvm3.write(connectnew)
                            fvm3.close()        
                            self.unknown(self.router)            
                if((cmp(hostabnormal,'SQL Injection Attack')==0) or (cmp(host2,'SQL Injection Attack')==0) ):
			connectionsql="Host suffers SQL Injection Attack though VM and Host behave like Normal\nMod_Security in Host drops malicious http requests."
			      
                        self.log.writeText(connectionsql,'RED')      
                print "--------------------------------"
                fhost3=open('/home/Write/hoststring.txt','a')
                fhost3.write(hostnew)
                fhost3.close()
                return previous
