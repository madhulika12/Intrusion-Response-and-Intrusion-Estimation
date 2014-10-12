Forecaster
==========

Intrusion Estimation and Response 

-I also added "wireshark", "wireshark-gnome", and "gcc-c++" to the init script cause we need them.

-modified the tcpwater config file to start in AUTO. this is because, no matter the mode, the water is always draining from the tank at a set rate. This is fine, but it keeps draining past 0%, and the sim starts at 0%, so we get negative numbers. It's a temp fix.

-added "gnome-terminal", "git", "gedit", had the scripts pull the repo, install snort, change the folder permissions, and add firewall exceptions

I fixed the draining issue. The minimum level was set at -15% in the config file. I moved that to 0% and put the startup mode back to OFF. So it just sits empty.

I modified the addresses of the tcpwater simulation to match the real ground water PLC. I adjusted it in the HMI as well.

OBSERVATIONS:

-The simulator runs on the same machine as the master. According to Bill. Le weird.

-For the tcppipe simulation, in AUTO - PUMP control, PSI higher than 7.28 cannot be acheived. In AUTO - SOLENOID control, SP lower than 7.28 cannot be achieved.

-The master PLC is not currently written to be a MODBUS server. In order to accomplish Dr. Morris's goal, that will have to be modified. It is also noteworthy that the slave PLC is not written to be a MODBUS client. I don't think that mattters right now.

-In order to facilitate having each VirtualPLC being a MODBUS server, I think each virtualPLC needs to be on it's own VM.
