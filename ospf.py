# from operator import attrgetter

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
# from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
# from ryu.topology import event, switches
from ryu.ofproto.ether import ETH_TYPE_IP
# from ryu.topology.api import get_switch, get_link
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import arp

import topology_discover, delay, monitor, paths_calculator
import ast, json, time
import setting


class baseline_Dijsktra(app_manager.RyuApp):
    '''
    A Ryu app that route traffic based on Dijkstra algorithm when it takes
    link delay as link delay.
    '''

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"awareness": topology_discover.TopologyDiscover,
                 "delay": delay.Delay,
                 "monitor": monitor.Statistics,
                 "paths_calculator": paths_calculator.PathsCalculator}

    def __init__(self, *args, **kwargs):
        super(baseline_Dijsktra, self).__init__(*args, **kwargs)
        self.awareness = kwargs["awareness"]
        self.monitor = kwargs["monitor"]
        self.paths_calculator = kwargs["paths_calculator"]
        self.delay = kwargs["delay"]
        self.datapaths = {} # why do not use topology module?
        self.paths = {}
        self.monitor_thread = hub.spawn(self.installation_module)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        """
            Record datapath information.
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('Datapath registered: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('Datapath unregistered: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def installation_module(self):
        """
            Main entry method of monitoring traffic.
        """
        while True:
            if self.awareness.link_to_port:
                self.paths = None
                self.flow_install_monitor()
            hub.sleep(setting.MONITOR_PERIOD)

    def flow_install_monitor(self):
        print("[INFO] Started flow installation routine")
        out_time= time.time()
        access_table = self.awareness.access_table
        for k in access_table.keys():
            sw_src = k[0]
            ip_src = access_table[k][0]
            host_src_port = k[1]
            for j in access_table.keys():
                sw_dst = j[0]
                ip_dst = access_table[j][0]
                host_dst_port = j[1]
                self.forwarding(ip_src, ip_dst, sw_src, sw_dst, host_src_port, host_dst_port)
        end_out_time = time.time()
        out_total_ = end_out_time - out_time
        return

    def forwarding(self, ip_src, ip_dst, sw_src, sw_dst, host_src_port, host_dst_port):
        """
            Get paths and install them into datapaths.
        """

        # self.installed_paths.setdefault(sw_src, {})
        if sw_dst == sw_src:
            path = [sw_dst]
        else:
            path = self.get_path(str(sw_src), str(sw_dst))
        # self.installed_paths[sw_src][sw_dst] = path
        flow_info = (ip_src, ip_dst)
        self.install_flow(self.awareness.datapaths, self.awareness.link_to_port, path, flow_info,
                           host_src_port, host_dst_port)


    def install_flow(self, datapaths, link_to_port, path,
                     flow_info, host_src_port, host_dst_port, data=None):
        init_time_install = time.time()
        '''
            Install flow entires.
            path=[dpid1, dpid2...]
            flow_info=(src_ip, dst_ip)
        '''
        if path is None or len(path) == 0:
            self.logger.info("Path error!")
            return

        in_port = host_src_port
        first_dp = datapaths[path[0]]

        out_port = first_dp.ofproto.OFPP_LOCAL
        back_info = (flow_info[1], flow_info[0])

        # Flow installing por middle datapaths nel path
        if len(path) > 2:
            for i in range(1, len(path)-1):
                port = self.get_port_pair_from_link(link_to_port,
                                                    path[i-1], path[i])
                port_next = self.get_port_pair_from_link(link_to_port,
                                                         path[i], path[i+1])
                if port and port_next:
                    src_port, dst_port = port[1], port_next[0]
                    datapath = datapaths[path[i]]
                    self.send_flow_mod(datapath, flow_info, src_port, dst_port)
                    self.send_flow_mod(datapath, back_info, dst_port, src_port)
        if len(path) > 1:
            # The last flow entry
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[-2], path[-1])
            if port_pair is None:
                self.logger.info("Port is not found")
                return
            src_port = port_pair[1]
            dst_port = host_dst_port
            last_dp = datapaths[path[-1]]
            self.send_flow_mod(last_dp, flow_info, src_port, dst_port)
            self.send_flow_mod(last_dp, back_info, dst_port, src_port)

            # The first flow entry
            port_pair = self.get_port_pair_from_link(link_to_port, path[0], path[1])
            if port_pair is None:
                self.logger.info("Port not found in first hop.")
                return
            out_port = port_pair[0]
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
            self.send_flow_mod(first_dp, back_info, out_port, in_port)

        # src and dst on the same datapath
        if len(path) == 1:
            out_port = host_dst_port
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
            self.send_flow_mod(first_dp, back_info, out_port, in_port)

        end_time_install = time.time()
        total_install = end_time_install - init_time_install

    def send_flow_mod(self, datapath, flow_info, src_port, dst_port):
        """
            Build flow entry, and send it to datapath.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = []
        actions.append(parser.OFPActionOutput(dst_port))

        match = parser.OFPMatch(
             eth_type=ETH_TYPE_IP, ipv4_src=flow_info[0],
             ipv4_dst=flow_info[1])

        self.add_flow(datapath, 1, match, actions,
                      idle_timeout=250, hard_timeout=0)

    def add_flow(self, dp, priority, match, actions, idle_timeout=0, hard_timeout=0):
        """
            Send a flow entry to datapath.
        """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, command=dp.ofproto.OFPFC_ADD, priority=priority,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    def build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Build packet out object.
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def arp_forwarding(self, msg, src_ip, dst_ip):
        """
            Send ARP packet to the destination host if the dst host record
            is existed.
            result = (datapath, port) of host
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto

        result = self.awareness.get_host_location(dst_ip)
        if result:
            # Host has been recorded in access table.
            print("[DEBUG] Getting location host %s" % dst_ip)
            datapath_dst, out_port = result[0], result[1]
            datapath = self.datapaths[datapath_dst]
            out = self.build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                         ofproto.OFPP_CONTROLLER,
                                         out_port, msg.data)
            datapath.send_msg(out)
            self.logger.debug("Deliver ARP packet to knew host")
        else:
            # Should we know the host location?
            # out_port = ofproto.OFPP_FLOOD
            # out = self.build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
            #                              ofproto.OFPP_CONTROLLER,
            #                              out_port, msg.data)
            # datapath.send_msg(out)
            pass

    def get_path(self, src, dst):
        if self.paths != None:
            path = self.paths.get(src).get(dst)
            return path
        else:
            # paths = self.awareness.shortest_paths
            paths = self.paths_calculator.get_shortest_paths()
            path = paths.get(src).get(dst)
            return path

    def get_dijkstra_paths_(self):
        file = setting.PATHS
        try:
            with open(file,'r') as json_file:
                paths_dict = json.load(json_file)
                paths_dict = ast.literal_eval(json.dumps(paths_dict))
                self.paths = paths_dict
                return self.paths
        except ValueError as e: #error excpetion when trying to read the json and is still been updated
            return
        else:
            with open(file,'r') as json_file: #try again
                paths_dict = json.load(json_file)
                paths_dict = ast.literal_eval(json.dumps(paths_dict))
                self.paths = paths_dict
                return self.paths

    def get_port_pair_from_link(self, link_to_port, src_dpid, dst_dpid):
        """
            Get port pair of link, so that controller can install flow entry.
            link_to_port = {(src_dpid,dst_dpid):(src_port,dst_port),}
        """
        if (src_dpid, dst_dpid) in link_to_port:
            return link_to_port[(src_dpid, dst_dpid)]
        else:
            self.logger.info("Link from dpid:%s to dpid:%s is not in links" %
             (src_dpid, dst_dpid))
            return None


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        """
            Handle the port status changed event.
        """
        msg = ev.msg
        ofproto = msg.datapath.ofproto
        reason = msg.reason
        dpid = msg.datapath.id
        port_no = msg.desc.port_no

        reason_dict = {ofproto.OFPPR_ADD: "added",
                       ofproto.OFPPR_DELETE: "deleted",
                       ofproto.OFPPR_MODIFY: "modified", }

        if reason in reason_dict:
            print("switch%d: port %s %s" % (dpid, reason_dict[reason], port_no))
        else:
            print("switch%d: Illegal port state %s %s" % (dpid, port_no, reason))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        '''
            In packet_in handler, we need to learn access_table by ARP and IP packets.
            Therefore, the first packet from UNKOWN host MUST be ARP
        '''
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        if isinstance(arp_pkt, arp.arp):
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)
