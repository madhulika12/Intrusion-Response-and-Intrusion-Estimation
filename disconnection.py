# ---------------------------------------------------------------------
# Send signal/command to Host from VM to disconnect network adapter
# ------------------------------------------------------------------

import socket
class Disconnect():
    def __init__(self):
        client = socket.socket (socket.AF_INET,socket.SOCK_DGRAM)
        #while True:
        command="devcon disable PCI\VEN_1022"  #send signal/command to Host from VM
        client.sendto(command,("1.0.0.2",777))
	print "Disconnection Signal is sent"
        client.close()
