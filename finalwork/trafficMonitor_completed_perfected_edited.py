import json
import os
from operator import attrgetter
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import numpy as np
import joblib
import ryu.app.ofctl_rest as ofctlRest

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from time import sleep

minmaxScaller = 4.12099233e-05
logReg = joblib.load("/home/osboxes/sdn/software_defined_networking/ddos_logisticRegression.pkl")


class SimpleMonitor13(simple_switch_13.SimpleSwitch13, ofctlRest.RestStatsApi):
    print("\n This is a custom ryu controller designed by Emmanuel Ebong NDA \n ")
    print("\n This detects and mitigates attacks on any sdn environment \n ")

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        # timer
        self.initialTime = 0
        self.presentTime = 0
        self.currentTime = 0
        self.counter = 0
        self.counter = 0
        self.counter2 = 0

        # bits
        self.bitInfo = []
        self.bitInfo_newList = []
        self.bitSlice = []
        self.bitDifference = []
        self.totalPortNumberList = []
        self.totalPortNumber = 0
        self.tx_pcks = 0

        self.tx_bits = 0
        self.rx_bits = 0
        self.src_add = ""
        self.dec_add = ""

        self.port_under_attack = 0
        self.totalbits = 0
        self.data_path_gotten = 0

        self.attack_ports = []
        self.table_info = []

        self.iterations = 0

        self.swtich_id = 1
        self.flag = 0
        self.ports_attacked = []
        self.ports_result = []

        # total_number_of_bits_for each iteration
        self.totalbits = 0


        #new variables..
        self.pak1 = 0
        self.pak2 = 0
        self.pakList  = []
        self.pakListB = []
        self.pakListA = []
        self.pakListgp = []
        self.pakListTx = []
        self.pakListTxA = []
        self.pakListTxB = []
        self.newPorts = np.zeros(6)


    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
                self.swtich_id = dp
                self.pakListB = self.pakListA
               
               
                

                # print(f'this is the old list {self.pakListB}')
                

            hub.sleep(10)  # this gets requests every 5 seconds
            
        

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        # print(" ")

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if self.port_under_attack == 0:  # packet in messages are only send if there is no attacker found.... when port under attack is zero no attaker is found
            # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)



    def delete_all_flows(self, dp, inport):

            print(f"  ADMIN  -->> To block port {inport} on switch {dp}<<-- \n")
            print(":::: Execute the command below from the mininet command Line::::")
            print(f'sh ovs-ofctl add-flow s{dp} priority=65535,in_port={inport},actions=drop \n')


            match = dp.ofproto_parser.OFPMatch(in_port=inport)
            priority = 65535
            m = dp.ofproto_parser.OFPFlowMod(dp, match=match, priority=priority,
                                            command=dp.ofproto.OFPFC_DELETE,
                                            out_port=dp.ofproto.OFPP_ANY,
                                            out_group=dp.ofproto.OFPG_ANY
                                            )
            dp.send_msg(m)
            print("\n -------------> message sent")
          
           
            


    def delete_all_flows_rest(self, dp, inport):
        print(dp, inport)
        jsonMatch = {
            "dpid": dp,
            "cookie": 1,
            "cookie_mask": 1,
            "table_id": 0,
            "idle_timeout": 30,
            "hard_timeout": 30,
            "priority": 65535,
            "flags": 1,
            "match": {
                "in_port": inport
            },
            "actions": [
                {
                 
               
                }
            ]
        }

        jsonStr = json.dumps(jsonMatch)
        # print(jsonStr)

        url = "http://localhost:8080/stats/flowentry/add"

        build = "curl -X POST -d" + "'" + json.dumps(jsonMatch) + "' " + url
        print(build)
        os.system(build)

    def accept_all_flows(self, dp):
        if self.port_under_attack != 0:
            print(f"      -->> allowing all ports now  <<-- \n")

            m = dp.ofproto_parser.OFPFlowMod(dp,
                                             command=dp.ofproto.OFPFC_ADD,

                                             )

            dp.send_msg(m)


    def _request_stats(self, datapath):
        print("\n the stat request happened here \n")
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)  # flow stats requests here
        datapath.send_msg(req)
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)  # port stats request here
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath.id

         

        self.logger.info('datapath         port     '
                        'rx-pkts  rx-bytes rx-error '
                        'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                        '-------- -------- -------- '
                        '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):           


            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                            ev.msg.datapath.id, stat.port_no,
                            stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                            stat.tx_packets, stat.tx_bytes, stat.tx_errors)

            self.data_path_gotten = ev.msg.datapath.id
            self.tx_bits = stat.tx_bytes  # number of transmitted bytes per unit time
            self.tx_pcks = stat.tx_packets  # number of transmitted packets per unit time   ###not the switch here
            self.src_add = 0
            self.bitInfo.append(self.tx_pcks)  # we need the packet this time
            self.totalPortNumberList.append(stat.port_no)
            self.bitInfo_newList.append(self.bitInfo)

            self.table_info.append([stat.port_no, stat.tx_packets, stat.rx_packets, ])
            self.table_info = self.table_info[-self.totalPortNumber:]
            self.table_info = list(self.table_info)            
            
            self.pakList.append(stat.rx_packets)

            
        
        try: 
        
            self.pakListA = self.pakList[-6:]
        
            
            
            # print(f'*** this is the new list : {self.pakListA}')
            
            print("\n the diffrence is  : ")
            self.newPorts = np.array(self.pakListA)- np.array(self.pakListB)
            

            detection = []
        
            
            for index,dif in enumerate(self.newPorts):           
                verdict = ""
                result = logReg.predict(np.array(dif * minmaxScaller).reshape(-1, 1)) # model working here
                if result[0] == 1:
                    verdict = "attack"
                elif result[0] == 0:
                    verdict = "normal"
                
                
                
                detection.append(verdict)

                if dif <= 0:
                    dif = 0
                    index = index + 1
                # print(index, dif,result, verdict)

                
                

            print(detection)
        
        except:
            print("\n waiting... ... ... ")

        try:
            attakPort = detection.index('attack') + 1
            if datapath !=3:
                print(attakPort)
                print(f"Attack on port {attakPort} on swtich {datapath} \n")            
                self.delete_all_flows(datapath,attakPort)
                
                
            
            
        

        except Exception as e:
            print("\n no attack ports detected" + str(e))

           
                
                
            
        
     
            


       
        
        
       
        
