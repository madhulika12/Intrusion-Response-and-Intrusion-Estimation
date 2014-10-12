# ---------------------------------------------------------------------
# Implement only legal flow access host resources when host is attacked
# ------------------------------------------------------------------


import socket
class ChangeHost():
    def __init__(self):
        client = socket.socket (socket.AF_INET,socket.SOCK_DGRAM)
        #while True: #can change to loop
        command="Replica"  #implement Replica.py file in client, terminated previous httperf that request sent to 1.0.0.2, instead, sent it to 1.0.0.3 (Replica Server) 
        client.sendto(command,("3.0.0.11",777))# Client sent httperf
