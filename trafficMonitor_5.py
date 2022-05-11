
from operator import attrgetter
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub


import numpy as np

import joblib
import os
import json

import ryu.app.ofctl_rest as ofctlRest




minmaxScaller = 4.12099233e-05
logReg = joblib.load("/home/ubuntu/ryu/ryu/app/software_defined_networking/ddos_logisticRegression.pkl")


class SimpleMonitor13(simple_switch_13.SimpleSwitch13, ofctlRest.RestStatsApi):
    print("\n This is a custom ryu controller designed by Emmanuel Ebong NDA \n ")
    print("\n this detects and mitigates attacks on any sdn environment \n ")



    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        # timer
        self.initialTime = 0
        self.presentTime = 0
        self.currentTime = 0

        self.counter = 0

        self.counter =  0

        self.counter2 = 0


        #bits
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
        self.ports_attacked =[]
        self.ports_result = []




        #total_number_of_bits_for each iteration
        self.totalbits = 0

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

            hub.sleep(5) #this gets requests every 5 seconds

            self.counter= 1 +   self.counter
            self.counter2 = 1 + self.counter2

            if len(self.totalPortNumberList)>=2:

                self.totalPortNumber = (self.totalPortNumberList[-2]+1)
                self.totalPortNumberList.clear()

            print(f"\n \n total number of ports in the network: {self.totalPortNumber} \n \n")




            if self.counter >= 1:
                self.counter = 0
                print(f"----the count is {self.counter}")


            if self.counter2 >= 1 and len(self.bitInfo_newList) != 0:
                self.counter2 = 0
                self.bitInfo_newList = self.bitInfo[-(self.totalPortNumber*2):]

                if len(self.bitInfo_newList) >= self.totalPortNumber*2:
                    smallList = self.bitInfo_newList[:self.totalPortNumber]
                    bigList = self.bitInfo_newList[self.totalPortNumber:]


                    for i1, i2 in zip(smallList, bigList):
                        self.bitDifference.append(i2-i1)

                    self.bitDifference = self.bitDifference[-self.totalPortNumber:]
                    self.port_collection = []

                    for count, bitdif in enumerate(self.bitDifference):

                       ###### the point of the phd is here #######

                        result = logReg.predict(np.array(bitdif*minmaxScaller).reshape(-1, 1))
                        self.ports_result.append(int(result))
                        self.ports_result = self.ports_result[-self.totalPortNumber:]
                        port_results = np.array(self.ports_result)


                        # for i in np.where(port_results == 1):
                        #     print(f"attakc on {i}")



                        if result == 1:
                            print(f"{result} ------ Abnormal Traffic -------")
                            self.port_under_attack = (count +1)
                            self.attack_ports.append(self.port_under_attack)
                            self.attack_ports = self.attack_ports[-self.port_under_attack:]
                            # mitigation code here
                            self.delete_all_flows(self.swtich_id, self.port_under_attack)
                            #self._mitigation_thread(self.port_under_attack)



                        elif result == 0:
                            print(f"{result} ------ Normal Traffic -------")
                            self.porto = (0)
                            self.attack_ports.append(self.porto)
                            self.attack_ports = self.attack_ports[:count]
                            self.ports_attacked.append(result)


                            if self.port_under_attack != 0:
                                pass
                                #self.accept_all_flows(self.swtich_id, self.port_under_attack)
                            else:
                                pass


                    if self.ports_result.count(0) >= self.totalPortNumber:
                        print("re-allowed here")
                        print(self.ports_result)

                        #self.accept_all_flows(self.swtich_id)


                    # print(self.attack_ports)
                    # print(f"the attacker(s) on port(s):{self.attack_ports}")

            if self.counter2 >= 1 and len(self.bitInfo_newList)!=0:
                self.counter2 = 0
                self.bitInfo_newList = self.bitInfo[-(self.totalPortNumber*2):]



                if len(self.bitInfo_newList)>=self.totalPortNumber*2:
                    smallList = self.bitInfo_newList[:self.totalPortNumber]
                    bigList = self.bitInfo_newList[self.totalPortNumber: ]
                    # print(f"small list lllllllllllllllllll { smallList}  \n biglist {bigList}")

                    for i1,i2 in zip(smallList, bigList):
                        self.bitDifference.append(i2-i1)

                    self.bitDifference = self.bitDifference[-self.totalPortNumber:]




                    # self.bitDifference = [(self.bitInfo_newList[4] - self.bitInfo_newList[0]),
                    #                       (self.bitInfo_newList[5] - self.bitInfo_newList[1]),
                    #                       (self.bitInfo_newList[6] - self.bitInfo_newList[2]),
                    #                       (self.bitInfo_newList[7] - self.bitInfo_newList[3])
                    #                       ]
                    for count, bitdif in enumerate(self.bitDifference):
                        # print(f'--->  {bitdif}')

                        result = logReg.predict(np.array(bitdif*minmaxScaller).reshape(-1, 1))


                        if result == 1:
                            print(f"{result}------ Attack Detected on port  {count+1}")
                            os.system("beep -f 2000 -l 1500")
                        else:
                            print(f"{result} ------ Normal Traffic -------")


                        #machine learning kicks in here
                        # if bitdif>100000:
                        #     print(f"------ Attack Detected on port  {count+1}")
                        # else:
                        #     print(" ------ Normal Traffic -------
                        print()




                    print(f"\nThe byte differences within the time interval are: {self.bitDifference} \n")
                    print(f"counter reset {self.counter2} bytes list in interval\n{self.bitInfo_newList} \n")




    def _run_once(f,*args):
        def wrapper(*args, **kwargs):
            if not wrapper.has_run:
                wrapper.has_run = True
                return f(*args, **kwargs)

        wrapper.has_run = False
        return wrapper


    def _mitigation_thread(self, inport):
        print(f"      -->> blocking port {inport} <<-- \n")
        json_string3 = {
                            "dpid": 1,
                            "cookie": 0,
                            "table_id": 0,
                            "priority": 100,
                            "flags": 1,
                            "match": {
                                # "nw_src": "10.0.0.1",
                                "dl_type": 2048,
                                "in_port":inport

                            },
                            "actions": [
                            ]
                                }
        url__3 = "http://localhost:8080/stats/flowentry/add"
        builtString = "curl -X POST -d" + f"'{str(json.dumps(json_string3))}' " + url__3
        if self.port_under_attack != 0:
            print("\n" + builtString +"\n")
            os.system(builtString)
            pass
        else:
            print("\n Thread was skipped here \n")




        # return self.iterations+1

    def _restoration_thread(self, inport):
        print(f"-->> restoring port {inport} <<--")
        json_string3 = {
            "dpid": 1,
            "cookie": 0,
            "table_id": 0,
            "priority": 100,
            "flags": 1,
            "match": {
                # "nw_src": "10.0.0.1",
                "dl_type": 2048,
                "in_port": inport

            },
            "actions": [
                {
                    "type": "OUTPUT",
                    "port": "ALL"
                }
            ]
        }
        url__3 = "http://localhost:8080/stats/flowentry/add"
        builtString = "curl -X POST -d" + f"'{str(json.dumps(json_string3))}' " + url__3
        if self.port_under_attack != 0:
            # print("\n" + builtString +"\n")
            # os.system(builtString)
            pass
        else:
            print("\n Thread was skipped here \n")




    def delete_all_flows(self, dp, inport):
        print(f"      -->> blocking port {inport} <<-- \n")
        match = dp.ofproto_parser.OFPMatch(in_port=inport)
        m = dp.ofproto_parser.OFPFlowMod(dp, match=match, priority=100,
                                         command=dp.ofproto.OFPFC_DELETE,
                                            out_port = dp.ofproto.OFPP_ANY,
                                                       out_group = dp.ofproto.OFPG_ANY

                                         )

        dp.send_msg(m)



    def accept_all_flows(self,dp):
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


    def _send_features_request(self, datapath):
        print("\n the feature request happens here \n")
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPFeaturesRequest(datapath)
        datapath.send_msg(req)






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
        flows = []

        # self.logger.info('datapath         '
        #                  'in-port  eth-dst           '
        #                  'out-port packets  bytes')
        # self.logger.info('---------------- '
        #                  '-------- ----------------- '
        #                  '-------- -------- --------')


        # self.logger.info('table_id=%s '
        #                  'duration_sec=%d duration_nsec=%d '
        #                  'priority=%d '
        #                  'idle_timeout=%d hard_timeout=%d flags=0x%04x '
        #                  'cookie=%d packet_count=%d byte_count=%d ')

        self.logger.info('table_id=%s '
                         'duration_sec=%d duration_nsec=%d '
                         'priority=%d '
                         'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                         'cookie=%d packet_count=%d byte_count=%d ')




        # self.logger.info('---------------- -------- '
        #                  '-------- -------- -------- '
        #                  '-------- -------- -------- -------- --------')
        #
        #
        # for stat in ev.msg.body:
        #     self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d %8d %8d' ,
        #                   stat.table_id,
        #                   stat.duration_sec, stat.duration_nsec,
        #                   stat.priority,
        #                   stat.idle_timeout, stat.hard_timeout, stat.flags,
        #                   stat.cookie, stat.packet_count, stat.byte_count )


        print("\n --------- new data -----------------")




        # for stat in sorted([flow for flow in body if flow.priority == 1],
        #                    key=lambda flow: (flow.match['in_port'],
        #                                      flow.match['eth_dst'])):
        #     self.logger.info('%016x %8x %17s %8x %8d %8d',
        #                      ev.msg.datapath.id,
        #                      stat.match['in_port'], stat.match['eth_dst'],
        #                      stat.instructions[0].actions[0].port,
        #                      stat.packet_count, stat.byte_count)
        #     flows.append('table_id=%s '
        #                  'duration_sec=%d duration_nsec=%d '
        #                  'priority=%d '
        #                  'idle_timeout=%d hard_timeout=%d flags=0x%04x '
        #                  'cookie=%d packet_count=%d byte_count=%d '
        #                  'match=%s' %
        #                  (stat.table_id,
        #                   stat.duration_sec, stat.duration_nsec,
        #                   stat.priority,
        #                   stat.idle_timeout, stat.hard_timeout, stat.flags,
        #                   stat.cookie, stat.packet_count, stat.byte_count,
        #                   stat.match))
        #     # self.logger.debug('FlowStats: %s', flows)
        #     print("\n ----------------------- new data --------------")
        #     print(flows[0])



    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

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
            self.tx_bits = stat.tx_bytes #number of transmitted bytes per unit time
            self.tx_pcks = stat.rx_packets #number of transmitted packets per unit time   ###not the switch here


            self.tx_bits = stat.tx_bytes #number of transmitted bytes per unit time
            self.tx_pcks = stat.tx_packets #number of transmitted packets per unit time

            self.src_add = 0
            self.bitInfo.append(self.tx_pcks)   # we need the packet this time
            self.totalPortNumberList.append(stat.port_no)
            self.bitInfo_newList.append(self.bitInfo)

            self.table_info.append([stat.port_no, stat.tx_packets, stat.rx_packets, ])
            self.table_info = self.table_info[-self.totalPortNumber:]
            self.table_info = list(self.table_info)


















    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, MAIN_DISPATCHER)
    def _switch_features_handler(self, ev):
        print("\n the fxn is working \n")
        msg = ev.msg

        self.logger.debug('OFPSwitchFeatures received: '
                          'datapath_id=0x%016x n_buffers=%d '
                          'n_tables=%d capabilities=0x%08x',
                          msg.datapath_id, msg.n_buffers, msg.n_tables,
                          msg.capabilities)


