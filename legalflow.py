# ---------------------------------------------------------------------
# Implement only legal flow access host resources when host is attacked
# ------------------------------------------------------------------


import socket
class LegalFlow():
    def __init__(self):
        client = socket.socket (socket.AF_INET,socket.SOCK_DGRAM)
        #while True: #can change to loop
        command="python legalflow.py"  #implement legalflow.py file in Host, protected VM send command to Host
        client.sendto(command,("1.0.0.2",777))