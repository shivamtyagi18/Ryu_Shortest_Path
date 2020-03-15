from ryu.base import app_manager  
from ryu.controller import ofp_event  
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER  
from ryu.controller.handler import set_ev_cls  
from ryu.ofproto import ofproto_v1_3  
from ryu.lib.packet import packet  
from ryu.lib.packet import ethernet  
from ryu.lib.packet import arp  
from ryu.lib.packet import ipv4  
from collections import defaultdict  
from ryu.topology.api import get_switch,get_link  
from ryu.topology import event,switches 
from ryu.lib import stplib 
from ryu.lib import dpid as dpid_lib
from ryu.app import simple_switch_13
import time  # to give time to sense all the links
  
ARP = arp.arp.__name__  
ETHERNET = ethernet.ethernet.__name__  
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"  
  
adjacency = defaultdict(lambda: defaultdict(lambda: None))  
path_map = defaultdict(lambda: defaultdict(lambda: (None, None)))  
sws = []  
switches={}  
mac_map={} 
links = [] 
  
def _get_raw_path(src, dst):  
    """ 
    Get a raw path (just a list of nodes to traverse) 
    """  
    if len(path_map) == 0: _dijkstra_paths() 
    # print("PATH_MAP after dijkstra  ", path_map[src][dst]) 
    if src is dst:  
        # We're here!  
        return []  
  
    if path_map[src][dst][0] is None:  
        return None  
    intermediate = path_map[src][dst][1]  
    if intermediate is None:  
        # Directly connected  
        return []  
    return _get_raw_path(src, intermediate) + [intermediate] + _get_raw_path(intermediate, dst)
  
def _get_path(src, dst, first_port, final_port):  
    """ 
    Gets a cooked path -- a list of (node,in_port,out_port) 
    """  
    # Start with a raw path...  
    print (src)
    print (dst)
    if src == dst:  
        path = [src]  
    else:  
        path = _get_raw_path(src, dst)
        # print(" Raw Path from _get_path -> ", path)  
        if path is None: return None  
        path = [src] + path + [dst] 
        print("Cooked Path from _get_path -> ", path)
    # return path
     
  
    # Now add the ports  
    r = []  
    in_port = first_port  
    for s1, s2 in zip(path[:-1], path[1:]):  
        out_port = adjacency[s1][s2]  
        r.append((s1, in_port, out_port))  
        in_port = adjacency[s2][s1]  
    r.append((dst, in_port, final_port))  
    print ('Route is ', r)
    return r  
  
def _dijkstra_paths():  
    path_map.clear()  
    for k in sws:  
        for j, port in adjacency[k].iteritems():  
            if port is None:  
                continue  
            path_map[k][j] = (1, None)  # 1 to switches connected directly
        path_map[k][k] = (0, None)  # 0 for self
  
    for t in sws:  
        final_point = [t]
        for i in range(len(sws) - 1):
            min_path = 999
            # HERE
            temp = None
            for p in sws:  
                if p not in final_point:  
                    if path_map[t][p][0] is not None and path_map[t][p][0] < min_path:  
                        min_path = path_map[t][p][0]  
                        temp = p  
            # HERE
            if temp is not None:
                final_point.append(temp)  

                for m in sws:  
                    if m not in final_point:  
                        if path_map[t][m][0] is None and \
                        path_map[t][temp][0] is not None and \
                        path_map[temp][m][0] is not None:
                            path_map[t][m] = (path_map[t][temp][0] + path_map[temp][m][0], temp)  

                        elif path_map[t][temp][0] is not None and \
                        path_map[temp][m][0] is not None and \
                        path_map[t][m][0] is not None:
                            if path_map[t][temp][0] + path_map[temp][m][0] < path_map[t][m][0]:  
                                path_map[t][m] = (path_map[t][temp][0] + path_map[temp][m][0], temp)  
    


class SimpleSwitch13(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] 
    _CONTEXTS = {'stplib': stplib.Stp} 
  
    def __init__(self, *args, **kwargs):  
        super(SimpleSwitch13, self).__init__(*args, **kwargs)  
        self.mac_to_port = {}  
        self.arp_table = {}  
        self.sw = {}  
        self.port_tx = {}  
        self.datapaths = {}  
        self.datapath_list={}  
        self.topology_api_app=self
        self.stp = kwargs['stplib']
        
        # Sample of stplib config.
        #  please refer to stplib.Stp.set_config() for details.
        config = {dpid_lib.str_to_dpid('0000000000000001'):
                  {'bridge': {'priority': 0x8000},
                   'ports': {1: {'priority': 0x80},
                             2: {'priority': 0x80},
                             3: {'priority': 0x80},
                             4: {'priority': 0x80}}},
                  dpid_lib.str_to_dpid('0000000000000002'):
                  {'bridge': {'priority': 0x9000},
                   'ports': {1: {'priority': 0x80},
                             2: {'priority': 0x80},
                             3: {'priority': 0x80},
                             4: {'priority': 0x80}}},
                  dpid_lib.str_to_dpid('0000000000000003'):
                  {'bridge': {'priority': 0xa000},
                   'ports': {1: {'priority': 0x80},
                             2: {'priority': 0x80},
                             3: {'priority': 0x80},
                             4: {'priority': 0x80}}},
                  dpid_lib.str_to_dpid('0000000000000006'):
                  {'bridge': {'priority': 0xb000},
                   'ports': {1: {'priority': 0x80},
                             2: {'priority': 0x80},
                             3: {'priority': 0x80},
                             4: {'priority': 0x80}}},
                  dpid_lib.str_to_dpid('0000000000000007'):
                  {'bridge': {'priority': 0xc000},
                   'ports': {1: {'priority': 0x80},
                             2: {'priority': 0x80},
                             3: {'priority': 0x80},
                             4: {'priority': 0x80}}},
                  dpid_lib.str_to_dpid('0000000000000008'):
                  {'bridge': {'priority': 0xd000},
                   'ports': {1: {'priority': 0x80},
                             2: {'priority': 0x80},
                             3: {'priority': 0x80},
                             4: {'priority': 0x80}}}
                  }
        # config = {}
        self.stp.set_config(config)

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

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                hard_timeout=20,
                                match=match, instructions=inst)

        datapath.send_msg(mod)

    # @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):  
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
        #avoid broadcast from LLDP  
        if eth.ethertype==35020:  
            return  
              
        dst = eth.dst
        src = eth.src  
  
        loc=('00-00-00-00-00-0'+str(datapath.id),in_port)  
        oldloc=mac_map.get(src)
        print("loc is ", loc,"old loc is",oldloc) 
         
        if oldloc is None:  
            mac_map[src]=loc
        elif src not in mac_map:  
            mac_map[src]=loc
  
        dpid = datapath.id  
        self.mac_to_port.setdefault(dpid, {})  
  
        # header_list = dict(  
        #     (p.protocol_name, p) for p in pkt.protocols if type(p) != str)  
        # if ARP in header_list:  
        #     self.arp_table[header_list[ARP].src_ip] = src  # ARP learning  
  
        self.logger.info("packet in switch:%s src_mac:%s dst_mac:%s inport:%s", dpid, src, dst, in_port)  
  
        # learn a mac address to avoid FLOOD next time.  
        if src not in self.mac_to_port[dpid]:  #record only one in_port  
            self.mac_to_port[dpid][src] = in_port  
  
        if dst in self.mac_to_port[dpid]: 
            print(" Calling Install Path ", mac_map) 
            out_port = self.mac_to_port[dpid][dst]  
            temp_src=mac_map[src]
            temp_dst=mac_map[dst]
            self.install_path(temp_src[0],temp_dst[0], temp_src[1], temp_dst[1], ev) 
            # self.logger.info("packet in %s %s %s %s %s", self.mac_to_port[dpid], dpid, src, dst, in_port)
            self.logger.info("packet in switch:%s src_mac:%s dst_mac:%s inport:%s outport:%s", dpid, src, dst, in_port, out_port)  
        else:  
            out_port = ofproto.OFPP_FLOOD  
            print("flood!")
  
        actions = [parser.OFPActionOutput(out_port)]  
  
        # install a flow to avoid packet_in next time  
        if out_port != ofproto.OFPP_FLOOD:  
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)              
  
        data = None  
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:  
            data = msg.data  
  
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,  
                                  in_port=in_port, actions=actions, data=data)  
        datapath.send_msg(out)  
 
    # @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])  
    # def state_change_handler(self, ev): 
    #     datapath = ev.datapath 
    #     print("Data path list",str(self.datapath_list)," ++ ",str(datapath.id))  
    #     if ev.state == MAIN_DISPATCHER:  
    #         if datapath.id == 1:  
    #             self.datapath_list[datapath.id] = datapath  
    #         if not datapath.id in self.datapath_list:  
    #             self.datapath_list[datapath.id]=datapath  
    #     elif ev.state == DEAD_DISPATCHER:  
    #         if datapath.id in self.datapath_list:  
    #             del self.datapath_list[datapath.id] 
                
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])  
    def state_change_handler(self, ev): 
        
        assert ev.datapath is not None 
        datapath = ev.datapath  
        print("Data path list1",str(self.datapath_list.keys())," ++ ",str(datapath.id))
        
        if ev.state == MAIN_DISPATCHER: 
             
            if datapath.id == 1:  
                self.datapath_list[datapath.id] = datapath 
                 
            if not datapath.id in self.datapath_list:  
                self.datapath_list[datapath.id]=datapath 
            stplib.Stp._register_bridge(self.stp,datapath)
            
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapath_list:
                stplib.Stp._unregister_bridge(self.stp,datapath.id)    
                del self.datapath_list[datapath.id] 
                    
        print("Data path list2",str(self.datapath_list.keys())) 
        
              
              
    def install_path(self,src_sw, dst_sw, in_port, last_port, ev):  
        """ 
        Attempts to install a path between this switch and some destination 
        """  
        p = _get_path(src_sw, dst_sw, in_port, last_port)  
        print(" Path -> ", str(p))

        # HERE
        if p is not None:
            self._install_path(p, ev)  
            # Now reverse it and install it backwards  
            # (we'll just assume that will work)  
            p = [(sw, out_port, in_port) for sw, in_port, out_port in p]  
            self._install_path(p, ev)  
  
    def _install_path(self, p, ev):  
        msg = ev.msg  
        datapath = msg.datapath  
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser  
        pkt = packet.Packet(msg.data)  

        # HERE
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst

        # HERE
        if p is not None:
            for sw, in_port, out_port in p:  

                # HERE
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)  
                actions = [parser.OFPActionOutput(out_port)]  
                ID=int(sw[-1:])  
                datapath=self.datapath_list[ID] 
                print("Next datapath is",datapath.id) 
                self.add_flow(datapath, 1, match, actions)  
    
    # To learn topology        
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
        
            
    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]

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

