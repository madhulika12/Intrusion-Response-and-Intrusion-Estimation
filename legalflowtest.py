import socket
def fun():
        client = socket.socket (socket.AF_INET,socket.SOCK_DGRAM)
        username=raw_input("Please enter username and password eg:Bob,1234\n")
        #password=raw_input("Please enter password:")
        
        #command="devcon disable PCI\VEN_1022"  #send signal/command to Host from VM
        client.sendto(username,("1.0.0.2",888))
        client.close()
	print "Disconnection Signal is sent"
        server = socket.socket (socket.AF_INET,socket.SOCK_DGRAM)
        server.bind(('',999))
        data,(add,port)=server.recvfrom (65530)
        print data
        server.close()
fun()
