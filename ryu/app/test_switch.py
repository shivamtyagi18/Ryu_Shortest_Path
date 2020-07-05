# from ryu.base import app_manager  
# from ryu.controller import ofp_event  
# from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER  
# from ryu.controller.handler import set_ev_cls  
# from ryu.ofproto import ofproto_v1_0  
# from ryu.lib.packet import packet  
# from ryu.lib.packet import ethernet  
# from ryu.lib.packet import arp  
# from ryu.lib.packet import ipv4  
# from collections import defaultdict  
# from ryu.topology.api import get_switch,get_link  
# from ryu.topology import event,switches 
# import time  # to give time to sense all the links 
# from ryu.lib.packet import arp
# from ryu.lib.packet import ipv6
# from ryu.lib import mac

# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER,  DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from collections import defaultdict
from ryu.topology.api import get_link, get_switch
from ryu.topology import event,switches 
import time
from ryu.lib import hub
from ryu.lib.ovs import bridge
from ryu.lib.dpid import dpid_to_str
from operator import attrgetter



sws = [] 
adjacency = defaultdict(lambda: defaultdict(lambda: None))  
path_map = defaultdict(lambda: defaultdict(lambda: (None, None)))  
sws = []  
switches={}  
mac_map={} 
links = []

class SimpleSwitch(app_manager.RyuApp):
# class SimpleSwitch(simple_switch.SimpleSwitch):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app=self 
        self.monitor_thread = hub.spawn(self._monitor)
        self.datapaths = {}
        self.host_ip_to_mac = {}

    def add_flow(self, datapath, in_port, dst, src, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port,
            dl_dst=haddr_to_bin(dst), dl_src=haddr_to_bin(src))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
	    # print("Packet In --------------------------------------------")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp = pkt.get_protocol(arp.arp)
        ipv4 = pkt.get_protocol(ipv4.ipv4)
        
        # ETH_TYPE_IP = 0x0800
        # ETH_TYPE_ARP = 0x0806
        # ETH_TYPE_TEB = 0x6558
        # ETH_TYPE_8021Q = 0x8100
        # ETH_TYPE_IPV6 = 0x86dd
        # ETH_TYPE_SLOW = 0x8809
        # ETH_TYPE_MPLS = 0x8847
        # ETH_TYPE_8021AD = 0x88a8
        # ETH_TYPE_LLDP = 0x88cc
        # ETH_TYPE_8021AH = 0x88e7
        # ETH_TYPE_IEEE802_3 = 0x05dc
        # ETH_TYPE_CFM = 0x8902
        # ETH_TYPE_NSH = 0x894f  # RFC8300
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        #checking if the packet type is IP
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            print("Packet type --------------------------------------------ETH_TYPE_IP",eth)
            print(pkt)
            
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            print("Packet type --------------------------------------------ETH_TYPE_ARP",eth)
            print(pkt)
            if arp.src_mac not in  self.host_ip_to_mac:
                self.host_ip_to_mac [arp.src_mac] = arp.src_ip
                
            if arp.dst_mac not in  self.host_ip_to_mac:
                self.host_ip_to_mac [arp.dst_mac] = arp.dst_ip

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
            print("flood!")

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, src, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
        datapath = msg.datapath
        dpid = datapath.id
        dpid_str = {'dpid': dpid_to_str(dpid)}
        port = ev.msg.desc
        link_down_flg = port.state & 0b1 # link status flag
       
       # status of port and reason  
        print("message state",msg.desc.state, "reason",reason)
        print("Inside Switch : ", dpid)
        

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
            
            # checking for link status
            if link_down_flg:
                    self.logger.info('[port=%d] Link down.',
                                     port.port_no, extra=dpid_str)
                    self.delete_port_from_topology_data(adjacency, dpid, port_no)
            else:
                self.logger.info('[port=%d] Link up.', port.port_no, extra=dpid_str)
                self.add_port_to_topology_data(adjacency, dpid, port_no)
                # bridge.link_up(port)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
        
            
    # To learn topology -----------------------------------------------------------------------
            
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches=[ switch.dp.id for switch in switch_list ]
        global sws  
        # assign mac for swtich to easy read  
        sws=['00-00-00-00-00-0'+ str(switch.dp.id) for switch in switch_list]
        print("sws ->", str(sws))
        global links

        # time delay before sensing links
        time.sleep(0.1) 
            
        links_list = get_link(self.topology_api_app, None)
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        
        print("links",links)
        print("switches",switches)
        for link in links_list:  
            sw_src='00-00-00-00-00-0'+ str(link.src.dpid)  
            sw_dst='00-00-00-00-00-0'+ str(link.dst.dpid) 
            adjacency[sw_src][sw_dst]=link.src.port_no
        print(" Adjacency Data ")
        for i in adjacency:
            print(str(i)+" : "+str(adjacency[i]))
            
    # delete port from adjacency list on link down -------------------------------------------
    
    def delete_port_from_topology_data(self,adjacency, datapath, port_no):
        # print(adjacency)
        print( "delete from Switch: ",datapath, "port: ", port_no)
        for i,j in adjacency.items():
            if i == "00-00-00-00-00-0"+str(datapath): # if datapath present in adjacency list
                print("found ",i)
                for switch,port in j.items():
                    # if port present for that datapath id
                    if port == port_no:  
                        print("port connected to: ",switch)
                        #delete the entry from adjacency list
                        del adjacency[i][switch]
                        print("updated adjacency")
                        for i in adjacency:
                            print(str(i)+" : "+str(adjacency[i]))    
                    else:
                        print("No port affected of switch ", datapath)
     
    # add port in adjacency list on link up -------------------------------------------------------------
                      
    def add_port_to_topology_data(self,adjacency, datapath, port_no):
        # print(adjacency)
        print( "add to Switch: ",datapath, "port: ", port_no)
        print(links)
        for link in links:  
            sw_src = '00-00-00-00-00-0'+ str(link[0])  
            sw_dst = '00-00-00-00-00-0'+ str(link[1]) 
            sw_port = link[2]['port']
            if link[0] == datapath and sw_port == port_no:
                print("connection to be added in adjacency",sw_src,sw_dst,sw_port)
                adjacency[sw_src][sw_dst]=sw_port
                for i in adjacency:
                            print(str(i)+" : "+str(adjacency[i]))
            else:
                print("switch",sw_src,"port", sw_port, " not found")

    # Monitor ---------------------------------------------------------------------- 
    
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
            hub.sleep(10)

    def _request_stats(self, datapath):
        # print("send stats request:",datapath)
        self.logger.debug('send stats request: %016x', datapath.id)
        # ofproto = datapath.ofproto
        # parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        # match = ofp_parser.OFPMatch(in_port=ofp.OFPP_IN_PORT)
        match = ofp_parser.OFPMatch(in_port=1)
        table_id = 0xff
        out_port = ofp.OFPP_NONE # No restriction
        
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0, match, table_id, out_port)
        #(datapath, flags, match, table_id, out_port)
        datapath.send_msg(req)

        req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_NONE)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        print("body",body,"datapath:",ev.msg.datapath.id)
       
        
        
        # for stat in sorted([flow for flow in body if flow.priority == 1],
        #                    key=lambda flow: (flow.match['in_port'],
        #                                      flow.match['eth_dst'])):
        #     self.logger.info('%016x %8x %17s %8x %8d %8d',
        #                      ev.msg.datapath.id,
        #                      stat.match['in_port'], stat.match['eth_dst'],
        #                      stat.instructions[0].actions[0].port,
        #                      stat.packet_count, stat.byte_count)
        
        flows = []
        for stat in ev.msg.body:
            flows.append((  "table_id = ",stat.table_id,
                            "duration_sec = ",stat.duration_sec,
                            "duration_nsec = ",stat.duration_nsec,
                            "priority = ",stat.priority,
                            "idle_timeout = ",stat.idle_timeout,
                            "hard_timeout = ",stat.hard_timeout,
                            "cookie = ",stat.cookie, 
                            "packet_count = ",stat.packet_count,
                            "byte_count = ",stat.byte_count,
                            "match = ",stat.match
                          ))
            
        print('FlowStats: %s', flows)
        # self.logger.debug('FlowStats: %s', flows)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        
        print("Port body",body)

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
            
        
