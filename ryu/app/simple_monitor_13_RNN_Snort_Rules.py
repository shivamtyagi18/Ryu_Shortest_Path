# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import numpy as np
import pandas as pd
import tensorflow as tf
# from ryu.app.RNN import recurrentNeuralNetwork
import os
import ryu.app.blocked_ip as ip_class  # list to save blocked IPs
import json
import time


class SimpleMonitor13(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.stats = {}
        self.test_data = {}
        self.test_data_frame = pd.DataFrame()
        self.rnn_classification = {}
        self.Q_table = {}
        self.snort_id  = 1000001
        self.total_time = {}
        self.total_packets = {}
        self.flow_count = {}
        # self.f= open("snortRules.txt","w+")
        
        
        # self.sess = tf.Session()
        # self.sess.run(tf.global_variables_initializer())
        
        # self.tensorGraph = tf.get_default_graph()

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
            # self.rnn = tf.keras.models.load_model("myModel")
            # 
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

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
        msg = ev.msg
        body = ev.msg.body
        dpid = msg.datapath.id
        # self.rnn = tf.keras.models.load_model("/home/shivamtyagi/ryu/ryu/app/trainedModels/model87%") 
        self.rnn = tf.keras.models.load_model("/home/shivamtyagi/ryu/ryu/app/myModel")
        # self.rnn = tf.keras.models.load_model("/users/shivam18/Ryu_Shortest_Path/ryu/app/myModel") 
        self.total_time.setdefault(dpid, {})
        self.total_packets.setdefault(dpid, {})
        self.flow_count.setdefault(dpid, {})
        packet_count = 0
        flow_count = 0
        
        start_time = time.time()
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['ipv4_dst'])):
            # print(stat)
            self.test_data =  {
                            'dpid'          :   dpid,
                            'Src IP Addr'   :   stat.match['ipv4_src'],
                            'Dst IP Addr'   :   stat.match['ipv4_dst'],
                            'Src Pt'        :   stat.match['in_port'],
                            'Dst Pt'        :   stat.instructions[0].actions[0].port,
                            'Packets'       :   stat.packet_count,
                            'Duration'      :   stat.duration_sec,
                            'Flags'         :   stat.flags,
                            'Bytes'         :   stat.byte_count,
                            'Proto'         :   stat.match['ip_proto'],
                            'class'         :   ""
                            }
            
            test_data_frame = pd.DataFrame(self.test_data,index=[0])
            test_data_frame = test_data_frame[['Src IP Addr', 'Dst IP Addr', 'Src Pt', 'Dst Pt', 'Packets',
                                               'Bytes', 'Duration', 'Proto', 'class']]
            
            test_x = test_data_frame.iloc[:, 4:8]
            test_x = np.asarray(test_x)
            test_x = tf.convert_to_tensor(test_x, np.float32)
            test_y = test_data_frame.iloc[:, 8]
            
            rnn_key = (self.test_data['Proto'], self.test_data['Src IP Addr'],
                       self.test_data['Dst IP Addr'], self.test_data['Src Pt'], self.test_data['Dst Pt'])
            
            self.rnn_classification[rnn_key] = (self.rnn.predict(test_x,steps=1))

            self.logger.info('Switch Proto  '
                         'Src IP  Dst IP  '
                         'Src Pt  Dst Pt  Classification')
            self.logger.info('------------------------------------------------------------------')
            self.logger.info("---%s----%s----%s----%s----%s----%s---%s",dpid, rnn_key[0], rnn_key[1],
                             rnn_key[2], rnn_key[3], rnn_key[4], self.rnn_classification[rnn_key])
            
            # if rnn_key[1] in ['10.0.0.4','10.0.0.2'] :
            if self.rnn_classification[rnn_key] > 0.8 : # 1 : attacker 
                 
                if rnn_key not in ip_class.ip_class and self.test_data['Packets'] > 0: # if ip already not in blocked ips list then append
                    ip_class.ip_class.append(rnn_key)
                    self.snort_id += 1
                    
                    # print ('''alert ip {0} {1} -> {2} {3} (msg: \"Suspicious ICMP packet from {0} to {2} with type {2}!\"; reference:monitor_13; content:"Test_Data"; dsize: <{4}; ip_proto:{6}; classtype:trojan-activity; metadata:service http; sid:{5}; rev:1;)'''
                    #        .format(self.test_data['Src IP Addr'], self.test_data['Src Pt'],
                    #                self.test_data['Dst IP Addr'], self.test_data['Dst Pt'],
                    #                int(self.test_data['Bytes']/self.test_data['Packets']), 
                    #                self.snort_id, self.test_data['Proto'] )
                    #        )
                    
                    #writing a snort rule to text file
                    with open("snortRules.rules", "a+") as myfile:
                        myfile.write('''alert ip {0} {1} -> {2} {3} (msg: \"Suspicious ICMP packet from {0} to {2}!\"; dsize: <{4}; ip_proto:{6}; classtype:trojan-activity; metadata:service http; sid:{5};)\n'''
                        .format(self.test_data['Src IP Addr'], self.test_data['Src Pt'],
                                self.test_data['Dst IP Addr'], self.test_data['Dst Pt'],
                                int(self.test_data['Bytes']/self.test_data['Packets']), 
                                self.snort_id, self.test_data['Proto']))
                            
            packet_count += self.test_data['Packets']
            flow_count += 1 # counting number of flow rules
            self.logger.info("-----------------------------------------------------------------") 
        
        end_time = time.time()
        self.aggreagate_stats(dpid, (end_time - start_time), packet_count, flow_count )
        
    def aggreagate_stats(self, dpid, time, count, flow_count):
        print(time, count, flow_count)
        print(self.total_packets)
        print(self.flow_count)
        if self.flow_count[dpid] != flow_count or self.total_packets[dpid] != count:
            self.flow_count[dpid] = flow_count
            self.total_time[dpid] = time
            self.total_packets[dpid] = count
            print("After processing dpid: ",dpid," Total time = ", sum(self.total_time.values()), " Total packets = ", sum(self.total_packets.values()))
        else:
            print("------No Change------")
 