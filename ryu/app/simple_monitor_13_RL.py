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
import tensorflow as tf
import ryu.app.blocked_ip as ip_class  # list to save blocked IPs
import json


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
        self.Reward_table = {}
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
        self.Q_table.setdefault(dpid, {})
        self.Reward_table.setdefault(dpid, {})
        
        er=0.5
        lr=0.8
        discount=0.8                
        gamma=0.7
        iterations=1500
        max_value = -100
        
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['ipv4_dst'])):

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
            
            # print(self.test_data)
            test_data_frame = pd.DataFrame(self.test_data,index=[0])
            test_data_frame = test_data_frame[['Src IP Addr', 'Dst IP Addr', 'Src Pt', 'Dst Pt', 'Packets',
                                               'Bytes', 'Duration', 'Proto', 'class']]
            
            test_x = test_data_frame.iloc[:, 4:8]
            test_x = np.asarray(test_x)
            test_x = tf.convert_to_tensor(test_x, np.float32)
            test_y = test_data_frame.iloc[:, 8]
            
            rnn_key = (self.test_data['Proto'], self.test_data['Src IP Addr'],
                       self.test_data['Dst IP Addr'], self.test_data['Src Pt'])
            
            self.rnn_classification[rnn_key] = (self.rnn.predict(test_x,steps=1))

            #-----------------------------Q Table Part Start---------------------------------------------
            Q_table_key = (self.test_data['Src IP Addr'],self.test_data['Dst IP Addr'])
            Q_table_key_reverse = (self.test_data['Dst IP Addr'],self.test_data['Src IP Addr'])
            
            # self.Q_table[self.test_data['dpid']][Q_table_key] = self.test_data['Packets']
            # self.Reward_table[self.test_data['dpid']][Q_table_key] = 0
            
            #-----------------------------Q Table Part End---------------------------------------------
            
            self.logger.info('Switch Proto  '
                         'Src IP  Dst IP  '
                         'Src Pt  Classification')
            self.logger.info('------------------------------------------------------------------')
            self.logger.info("---%s----%s----%s----%s----%s----%s",dpid, rnn_key[0], rnn_key[1],
                             rnn_key[2], rnn_key[3], self.rnn_classification[rnn_key])
            
            
            # if rnn_key[1] in ['10.0.0.4','10.0.0.2'] :
            if self.rnn_classification[rnn_key] > 0.8 : # 1 : if attack detected penalise
                if Q_table_key in self.Reward_table[self.test_data['dpid']].keys():
                    self.Reward_table[self.test_data['dpid']][Q_table_key] -= 100
                else:   
                    # penalising Q_table
                    self.Reward_table[self.test_data['dpid']][Q_table_key] = -100
                    
            else:
                if Q_table_key in self.Reward_table[self.test_data['dpid']].keys():
                    self.Reward_table[self.test_data['dpid']][Q_table_key]  += 50
                else:
                    self.Reward_table[self.test_data['dpid']][Q_table_key] = 50
            
            if Q_table_key in self.Q_table[self.test_data['dpid']].keys():
                #max_value = self.test_data['dpid'] for switch where self.Q_table[self.test_data['dpid']][Q_table_key] is max
                if max_value < self.Q_table[self.test_data['dpid']][Q_table_key]:
                    max_value = self.Q_table[self.test_data['dpid']][Q_table_key]
                    
                self.Q_table[self.test_data['dpid']][Q_table_key] = int((1-lr) * 
                                                                self.Q_table[self.test_data['dpid']][Q_table_key] + 
                                                                lr * (self.Reward_table[self.test_data['dpid']][Q_table_key]
                                                                    + discount * max_value))
            else:
                self.Q_table[self.test_data['dpid']][Q_table_key] = int((1-lr) * 
                                                                0 + 
                                                                lr * (self.Reward_table[self.test_data['dpid']][Q_table_key]
                                                                    + discount * max_value))
                
            
            
            print("Q_table--------------------------------------------------------------")
            values = [{"Switch": str(k), "Src-Dst": str(v)} for k, v in self.Q_table.items()]
            print(json.dumps(values, indent=4))
            # if rnn_key[1] not in ip_class.ip_class: # if ip already not in blocked ips list then append
            #         ip_class.ip_class.append(rnn_key[1])
                
            '''
                Compare the predicted probability with a threashold probability
                Reward[dpid](src,dst) = Reward or Penalty
                New Q_table[dpid](src,dst) = f( Reward[dpid](src,dst), Q_table[dpid](src,dst) )
                
            '''
 
            # print("Q entry after reward / penalising: ",self.Q_table[self.test_data['dpid']][Q_table_key])
                        
                # self.logger.info("Modifying flows for %s in switch %s", rnn_key[1], dpid)
                # self.modify_flow(msg.datapath, rnn_key)
            self.logger.info("-----------------------------------------------------------------") 
    
    def modify_flow(self, datapath, match_info):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = []
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        match = parser.OFPMatch(    
                                eth_type=2048, # since only ip packets are traced
                                ipv4_src=match_info[1],
                                ipv4_dst=match_info[2],
                                in_port =match_info[3],
                                ip_proto=match_info[0],
                                )
        #modifying the rule
        mod = parser.OFPFlowMod(datapath, 0, 0,
                                0, ofproto.OFPFC_ADD,
                                0, 0,
                                1, ofproto.OFP_NO_BUFFER,
                                ofproto.OFPP_ANY, ofproto.OFPG_ANY,
                                ofproto.OFPFF_SEND_FLOW_REM,
                                match, inst)
        datapath.send_msg(mod)
        
          # def next_number(self,start,Q_table):
    #     next_node = -1
    #     er = 0.5
    #     if self.action_selection_approach == "epsilon-greedy" or self.action_selection_approach == "epsilon-greedy-decay":
    #         self.random_value=random.uniform(0,1)    
    #         if self.random_value<er:
    #                 sample=self.topology[start]
    #         else:
    #                 sample=np.where(Q_table[start,]==np.max(Q_table[start,]))[1]            
    #         next_node=int(np.random.choice(list(sample),1)) 
            
    #     return next_node
        
        #deleting the rule
        # mod = parser.OFPFlowMod(datapath=datapath,
        #                         command=ofproto.OFPFC_DELETE,
        #                         out_port=ofproto.OFPP_ANY,
        #                         out_group=ofproto.OFPG_ANY,
        #                         match=match,
        #                         instructions = inst)
 