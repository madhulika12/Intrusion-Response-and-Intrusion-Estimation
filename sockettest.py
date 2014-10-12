import socket
def sock():
	s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('',256)) #this script run on 1.0.0.9 which is the protected VM
    
        data,addr = s.recvfrom(1024)
        if not data:
               print 'The responses from the Host Forecaster has exited!'
               return 0
            
        s.close()
sock()
