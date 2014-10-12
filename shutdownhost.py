# ---------------------------------------------------------------------
# Implement Shutdown method to protect host against attackand network resource utilization of VM 
# ------------------------------------------------------------------

import socket
class ShutDown():
    def __init__(self):
        client = socket.socket (socket.AF_INET,socket.SOCK_DGRAM)
        #while True:
        command="shutdown /s"   
        client.sendto(command,("1.0.0.2",777)) #send command and will be implemented on host
