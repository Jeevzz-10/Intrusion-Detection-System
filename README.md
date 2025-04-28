# Intrusion-Detection-System
Intrusion Detection System using raw packets and with DoS attack alerting 
note: both files should be run on two different linux
Steps to execute:
1. install the required dependicies (python3, scapy)
2. Note down the IP address of the server using '-ifconfig' or '-ip addr' command
   note: if using virtual box or VMware, Go to the network settings->change the network from NAT to Bridged adapter
3. Go to the current file directory on terminal and run the server code using sudo python3 DoS_server.py
4. On the other linux terminal run the host file using sudo python3 DoS_attack_host.py
5. enter the IP of server and any open port number and number of SYN packets to flood and boom!, your running server gets DoS attack by SYN flood
