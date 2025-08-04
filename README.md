# Covert_Channels
Shared repo for JHU Summer 2025 Covert Channels Class

# Setup 
To setup the covert channel, we'd recommend using Virtual Machines. We attempted at setting up a docker network but found the interfaces for the malicious sender and receiver were unpredictable. 

## Virtual Machine Settings
We setup the channel using 4 VMS:

    client:
        Network interfaces:
            - "intnet-client" with IP 10.0.2.2
        IP Routes:
            - A route to the server subnet goes through the malicious server. 
            - To install such a route run `sudo ip route add 10.0.4.0/24 via 10.0.2.1`

    malicious server: 
        Network interfaces:
            - "intnet-client" with IP 10.0.2.1 (Acts as a gateway for intnet-client)
            - "intnet-external" with IP 10.0.3.1
        IP Routes:
            - A route to the server subnet goes through the malicious receiver. 
            - To install such a route run `sudo ip route add 10.0.4.0/24 via 10.0.3.2`

    malicious receiver: 
        Network interfaces:
            - "intnet-external" with IP 10.0.3.2
            - "intnet-server" with IP 10.0.4.1 (Acts as a gateway for intnet-server)
        IP Routes:
            - A route to the client subnet goes through the malicious sender. 
            - To install such a route run `sudo ip route add 10.0.2.0/24 via 10.0.3.1`
            
    server: 
        Network interfaces:
            - "intnet-server" with IP 10.0.4.10
        IP Routes:
            - A route to the client subnet goes through the malicious sender. 
            - To install such a route run `sudo ip route add 10.0.2.0/24 via 10.0.3.2`

## Routing
In order to properly route traffic, we put in ip routes to avoid the traffic being sent to the internet or the wrong location. Additionally, adding in iptables rules allowed for more fine tuned configuration and prevented duplicated packets from being observed.

The client sends requests that get forwarder to the malicious server. The malicious server in a real world example would be a compromised network device such as a router or firewall that allows the malicious server to intercept and inspect packets. The malicious server then forwards it onto the malicious receiver who checks the payload for covert data. If covert data is found, the receiver takes it off the packet, prints it and forwards the packet on to the server. 

This network topology would be common for any internal network or external facing network which relies on multiple hops to tranmit packets.