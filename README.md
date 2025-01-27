# POLITECNICO DI MILANO - NETWORK AUTOMATION 2022/2023

Raquel Vila and Jorge Olivera Pinies

This is a switch controller application built using the Ryu framework. It provides functionalities for monitoring and controlling OpenFlow switches in a network. The application supports the following features:

- STP configuration for switches using the `stplib.Stp` module.
- Monitoring of switch statistics including flow statistics and port statistics.
- Generation of packet evolution charts based on collected statistics.

STRUCTURE OF THE CODE:
The code is divided into several main sections and functions:

SimpleSwitch13 class.
	
	The SimpleSwitch13 class extends the functionality of the simple_switch_13.SimpleSwitch13 class provided by 		the Ryu framework. This class initializes the necessary attributes and configures STP (Spanning Tree 		Protocol) for switches using the stplib.Stp module.

Main methods:

_monitor():

	This method is responsible for monitoring the switches in the network. It waits 80 seconds to ensure that 	the STP configuration is complete and then sends periodic requests for statistics to the switches.

_graphicator1():
	
	This method generates a packet evolution chart by calling the generate_time_chart() function if self.times 		is greater than 4.

_graphicator2(): 

	This method generates a graph of packets received and errors received on each port by calling the 		show_graphic() function if self.times is greater than 4.

_request_stats(datapath): 

	This method sends statistics requests to a specific switch (datapath).

_flow_stats_reply_handler(ev): 

	This method handles the flow statistics response received from the switch and saves the statistics to a CSV 	file.

_port_stats_reply_handler(ev): 

	This method handles the port statistics response received from the switch and stores the statistics in a CSV 	file. In addition, it calls the show_graphic() and generate_time_chart() functions to generate graphs based 	on the statistics.

delete_flow(datapath): 

	This method deletes the flow rules (flows) of a switch controlled by OpenFlow based on the destination MAC 	addresses stored in the mac_to_port dictionary of the object containing this method.

_packet_in_handler(ev): 

	This method handles incoming packets on the OpenFlow-controlled switch. It processes the packet and makes 		decisions based on the information contained in it.

Additional functions

show_graphic(self, file): 
	
	This function loads data from a CSV file and generates two bar graphs. 
	The first graph shows the number of packets received and errors received on each port, while the second 		shows the number of packets transmitted and errors transmitted on each port

generate_time_chart(self, file_name, num): 
	
	This function takes a CSV file name and a switch number as input.
	It reads the data from the CSV file, processes it and generates a packet evolution chart.


