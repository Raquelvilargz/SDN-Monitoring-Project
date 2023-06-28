from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.app import simple_switch_13
from ryu.lib import hub
from operator import attrgetter
import pandas as pd
import matplotlib as plt
import matplotlib.pyplot as plt
import glob
from datetime import datetime
from csv import writer
import matplotlib.dates as mdates
import os.path


    #Description show_graphic:

    # This function loads data from a CSV file and generates two bar graphs.
    #The first graph shows the number of received packets and received errors on each port, while the second one shows
    # the number of received packets and received errors on each port.
    #received and errors received on each port, while the second graph shows the number of packets transmitted
    #and errors transmitted on each port.
    #transmitted and errors transmitted on each port. The graphs are saved as
    #PNG files with different names, based on the switch number extracted from the CSV file name.
    #CSV file name.

def show_graphic(self,file):
    # Colores para cada tipo de dato
    colors = ['tab:blue', 'tab:orange']

    # Cargar los datos del archivo CSV
    df = pd.read_csv(file)
    # Elimino la última fila porque aparecían resultados no concluyentes
    df = df.drop(df.index[-1])
    # Obtener el número de switch a partir del nombre de archivo
    switch_num = file.split("portStats")[1].split(".csv")[0]


    ax1 = df.plot(kind='bar', x='port', y=['rx-pkts', 'rx-error'], color=colors, figsize=(8, 6), legend=False)
    ax1.set_xticklabels(df['port'], rotation=0)
    ax1.set_xlabel("Ports Switch" + switch_num)
    ax1.set_ylabel("Packets Received")
    ax1.set_title("Packets Received by Port Switch" + switch_num)

    # Agregar el valor de cada barra como texto
    for i in ax1.containers:
        ax1.bar_label(i, label_type='edge', fontsize=10)
        for j, value in enumerate(i):
            ax1.text(j, value.get_height(), str(value.get_height()), ha='center')

    # Agregar leyenda
    ax1.legend(labels=['Received Packets', 'Received Errors'])



    plt.savefig('port_rx_pkts' + switch_num + '.png')

    ax2 = df.plot(kind='bar', x='port', y=['tx-pkts', 'tx-error'], color=colors, figsize=(8, 6), legend=False)
    ax2.set_xticklabels(df['port'], rotation=0)
    ax2.set_xlabel("Ports Switch" + switch_num)
    ax2.set_ylabel("Packets Transmitted")
    ax2.set_title("Packets Transmitted by Port Switch" + switch_num)

    # Agregar el valor de cada barra como texto
    for i in ax2.containers:
        ax2.bar_label(i, label_type='edge', fontsize=10)
        for j, value in enumerate(i):
            ax2.text(j, value.get_height(), str(value.get_height()), ha='center')

    # Agregar leyenda
    ax2.legend(labels=['Transmitted Packets', 'Transmitted Errors'])

    plt.savefig('port_tx_pkts' + switch_num + '.png')


    #Description generate_time_chart()

    #The function generate_time_chart takes a CSV file name and a switch number as input.
    #It reads the data from the CSV file, preprocesses it, and generates a time-based chart
    #showing the evolution of packets for the specified switch. The chart includes multiple
    #lines, each representing a different port of the switch. The x-axis represents timestamps,
    #and the y-axis represents the number of packets. The resulting chart is saved as a PNG file.


def generate_time_chart(self,file_name, num):
    switch = num

    if os.path.isfile(file_name):
        data = pd.read_csv(file_name, names=["Switch", "Port", "Packets", "Timestamp", "Time"])
        # This line is used to remove the last row of each switch as it contains
        # irrelevant information for port 4664270078
        data = data[data['Port'] <= 1000]

        data['Timestamp'] = pd.to_datetime(data['Timestamp'])  # Convert the Timestamp column to datetime

        # Create a list of unique ports in the DataFrame
        unique_ports = data['Port'].unique()

        # Create a figure for each switch
        fig, ax = plt.subplots()

        # Iterate over each port of the switch and plot the evolution of received packets
        for port in unique_ports:
            port_data = data[data['Port'] == port]
            ax.plot(port_data['Timestamp'], port_data['Packets'], label=f"Port {port}")

        ax.set_title(f"Switch {switch} - Packet Evolution")
        # Format the x-axis
        ax.xaxis.set_major_locator(mdates.AutoDateLocator())
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        ax.set_xlabel("Timestamp")
        ax.set_ylabel("Packets")
        ax.legend()
        fig.savefig(f"switch_{switch}.png")  # Save the figure as a PNG file
        plt.close(fig)  # Close the figure to free up memory



    #This class extends the functionality of the SimpleSwitch13 class, initializes attributes,
    #and sets STP configurations for the switches using the stplib.Stp module.

class SimpleSwitch13(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.stp = kwargs['stplib']
        self.monitor_thread = hub.spawn(self._monitor)
        #self.graphs_thread1 = hub.spawn(self._graphicator1)
        #self.graphs_thread2 = hub.spawn(self._graphicator2)
        self.times = 0


        # Sample of stplib config.
        #  please refer to stplib.Stp.set_config() for details.
        config = {dpid_lib.str_to_dpid('0000000000000001'):
                  {'bridge': {'priority': 0x8000}},
                  dpid_lib.str_to_dpid('0000000000000002'):
                  {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('0000000000000003'):
                  {'bridge': {'priority': 0xa000}}}
        self.stp.set_config(config)


    #This method takes care of monitoring the switches on the network.
    #After waiting 80 seconds to ensure that the STP configuration is complete,

    def _monitor(self):

        #We wait some seconds to start the monitoring so STP can be completed.
        hub.sleep(80)

        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            self.times = self.times + 1
            hub.sleep(10)


    #This method generates a packet evolution chart by calling the generate_time_chart
    #function if self.times is greater than 4.

    def _graphicator1(self):

        while True:
            if self.times > 4:
                generate_time_chart(self)
            hub.sleep(10)

    def _graphicator2(self):

        while True:
            if self.times > 4:
                show_graphic(self)
            hub.sleep(10)


    #FUNCTION: _request_stats: Is responsible for sending statistics requests to a specific switch (datapath).

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)




    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        # Creates a new empty DataFrame (df) with columns labeled 'datapath', 'in-port', 'eth-dst',
        # 'out-port', 'packets', 'bytes' and 'time'. The DataFrame will be used to store the flow statistics.
        df = pd.DataFrame(columns= ['datapath', 'in-port', 'eth-dst', 'out-port', 'packets', 'bytes','time'])

        #column headers for the flow statistics and then display the values of the flow statistics received.
        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes time')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- -------- ----------')

        #Creates a file name to save the flow statistics in CSV format
        num = ev.msg.datapath.id
        filename = "flowStats" + str(num) + ".csv"
        i = 0

        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):

            #Adds a new row to the DataFrame df with the values of the current flow statistics.
            df.loc[i] = [ev.msg.datapath.id,
                              stat.match['in_port'], stat.match['eth_dst'],
                              stat.instructions[0].actions[0].port,
                              stat.packet_count, stat.byte_count,datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
            self.logger.info('%016x %8x %17s %8x %8d %8d %s',
                             ev.msg.datapath.id,
                              stat.match['in_port'], stat.match['eth_dst'],
                              stat.instructions[0].actions[0].port,
                              stat.packet_count, stat.byte_count,datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            i = i+1

        self.logger.info('Writing in file flowStats%d', num)

        #Method to write the DataFrame object to a csv file.
        df.to_csv(filename, index = False)

        


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):


        body = ev.msg.body
        #creates a new empty DataFrame (df) with columns labeled 'datapath', 'port', 'rx-pkts', 'rx-bytes', 'rx-error',
        #'tx-pkts', 'tx-bytes' and 'tx-error'. The DataFrame will be used to store the port statistics.
        df = pd.DataFrame(columns= ['datapath', 'port', 'rx-pkts', 'rx-bytes', 'rx-error', 'tx-pkts', 'tx-bytes', 'tx-error'])

        #Print information in the register
        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')

        #Creates a file name to save the port statistics in CSV format
        num = ev.msg.datapath.id 
        filename = "portStats" + str(num) + ".csv"
        filename2 = "timeStats" + str(num) + ".csv" 
        now = datetime.now()
        time = now.time()
        i = 0

        file2 = open(filename2, 'a')
        writer_obj = writer(file2)

        #This loop iterates over the port statistics in the message body
        for stat in sorted(body, key=attrgetter('port_no')):
            df.loc[i] = [ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors]
            writer_obj.writerow([ev.msg.datapath.id,
                            stat.port_no, stat.rx_packets, now, time])
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                              ev.msg.datapath.id, stat.port_no,
                              stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                              stat.tx_packets, stat.tx_bytes, stat.tx_errors)
            i=i+1

        self.logger.info('Writing in file portStats%d', num)

        #Method to write the DataFrame object to a csv file
        df.to_csv(filename, index = False)

        show_graphic(self, filename)
        generate_time_chart(self, filename2, num)


    #Function: delete_flow() description:

    #Delete the flows (rules) of a switch controlled by OpenFlow based on the destination MAC addresses
    #stored in the mac_to_port dictionary of the object containing this method.

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

    #FUNCTION: _packet_in_handler() description:

    #Handling incoming packets in the switch controlled by OpenFlow.
    #Its function is to process and make decisions based on the information contained in the packet received.

    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        #Learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        #Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    #Function: _topology_change_handler() description:

    #It is responsible for managing changes in the network topology.
    #Its main purpose is to update and manage information related to changes in the connected switches.

    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]

        if dp.id not in self.datapaths:
            self.datapaths[dp.id] = dp
            self.logger.info("Datapaths registered:")
            for d in self.datapaths.values():
                self.logger.info(d.id)

    #Function: _port_state_change_handler() description.

    #It is responsible for managing port state changes on switch ports.
    #Its main purpose is to record and manage information related to port state changes.

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])