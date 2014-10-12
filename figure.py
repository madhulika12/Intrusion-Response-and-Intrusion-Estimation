# ---------------------------------------------------------------------
# The Graph shows current system and network resource utilization of VM 
# ------------------------------------------------------------------
import matplotlib.pyplot as plt #just like matlab hai ye.. numpy ko generally input dete hai isme
from matplotlib.font_manager import FontProperties
class graph():
    def __init__(self):
        
    #def main(self):
        DataFile = open("/home/file/test.csv", 'r')#which has data for 10 parameters
        lines=DataFile.readlines()
        List=[] 
        number=len(lines)
        l_list = lines[1:number]
        x=[]
        mem=[]
        BR=[]
        BS=[]
        PR=[]
        PS=[]
        IOR=[]
        IOW=[]
        Id=[]
        Pro=[]
        US=[]

        #------Process data in test.csv----------

        for i in range (0, number-1):
            x.append(i)
        for li in l_list:
            data=li.split(',')    
            a=data[0]   
            b=data[1]
            c=data[2]
            d=data[3]
            e=data[4]
            f=data[5]
            g=data[6]
            h=data[7]
            i=data[8]
    #length=len(data[9])
            j=data[9]
            mem.append(float(a))
            BR.append(float(b))
            BS.append(float(c))
            PR.append(float(d))
            PS.append(float(e))
            IOR.append(float(f))
            IOW.append(float(g))
            Id.append(float(h))
            Pro.append(float(i))
            US.append(float(j))
    
        fig = plt.figure(figsize=(14,9))
        fig.suptitle('Current Parameters Values of Protected VM', fontsize=14, fontweight='bold')

        plt.subplots_adjust(hspace=.5) 
        ax1 = fig.add_subplot(3,1,1)
        ax1.set_title('CPU Utilization')
        ax1.set_xlabel("Number of Samples") # plt.xlabel() 
        ax1.set_ylabel("Utilization Percentage")
        ax1.plot(x,Id,'ro-',label="CPU Idle percentage") #draw CPU Idle figure
        ax1.plot(x,Pro,'b*-',label="CPU System Utilization percentage")
        ax1.plot(x,US,'y+-',label="CPU User Utilization percentage")

        leg1 = ax1.legend(loc='best',prop=FontProperties(size='small'))

        leg1.get_frame().set_alpha(.5)
#------------------Byte Receive/Sent-----------------------
        ax2 = fig.add_subplot(3,2,3)  
        ax2.set_title('Byte Received/Sent Utilization')
        ax2.set_xlabel("Number of Samples") # plt.xlabel() 
        ax2.set_ylabel("Byte")
        ax2.plot(x,BR,'ro-',label="Byte Received")
        ax2.plot(x, BS,'b*-',label="Byte Sent")
        leg2 = ax2.legend(loc='best',prop=FontProperties(size='small'))
        leg2.get_frame().set_alpha(0.5)
    
    #-----------------Packet Receive/Sent------------------
        ax3 = fig.add_subplot(3,2,4)
        ax3.set_title('Packet Received/Sent')
        ax3.set_xlabel("Number of Samples") # plt.xlabel() 
        ax3.set_ylabel("Number of Packets")
        ax3.plot(x,PR,'ro-',label="Packet Received") #plot packet receive figures
        ax3.plot(x,PS,'b*-',label="Packet Sent")
        leg3 = ax3.legend(loc='best',prop=FontProperties(size='small'))
        leg3.get_frame().set_alpha(0.5)
    
    #---------------IOR/W----------------
    
        ax4 = fig.add_subplot(3,2,5)
        ax4.set_title('I/O Read/Write Requests')
        ax4.set_xlabel("Number of Samples") # plt.xlabel() 
        ax4.set_ylabel("Number of Requests")
        ax4.plot(x,IOR,'ro-',label="I/O Read Request") #plot figure for IO 
        ax4.plot(x, IOW,'b*-',label="I/O Write Request")
        leg4 = ax4.legend(loc='best',prop=FontProperties(size='small'))
        leg4.get_frame().set_alpha(0.5)
        #---------------Mem-----------
        ax5 = fig.add_subplot(3,2,6)
        ax5.set_title('Avaliable Memory')
        ax5.set_xlabel("Number of Samples") # plt.xlabel() 
        ax5.set_ylabel("Memory Utilization (KB)")
        ax5.plot(x,mem,color='r',linestyle='-',marker='o',label="Memory (KB)") #Memory
        leg5 = ax5.legend(loc='best',prop=FontProperties(size='small'))
        leg5.get_frame().set_alpha(0.5)
        plt.savefig("/home/file/test.png") #save as test.png
        DataFile.close()
