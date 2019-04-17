#!/usr/local/bin/python2.7
import dpkt
import sys

FILENAME = 'assignment3.pcap'
ALPHA = 0.125

def find_ports():
    ports = []
    num_ports = 0
    for ts, pkt in dpkt.pcap.Reader(open(FILENAME, 'rb')):
        if dpkt.ethernet.Ethernet(pkt).type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        if dpkt.ethernet.Ethernet(pkt).data.p == dpkt.ip.IP_PROTO_TCP:
            sport = dpkt.ethernet.Ethernet(pkt).data.data.sport
            if sport not in ports and sport != 80:
                ports.append(sport)
                num_ports += 1
    return ports, num_ports

def print_duration(ports, tspf):
    for port in ports:
        value = tspf[port][1] - tspf[port][0]
        print "Port: ", port, " has flow with duration: ", value

def get_duration(port, tspf):
    duration = tspf[port][1] - tspf[port][0]
    return duration

def find_ts(ports):
    ts_per_flow = {}
    for port in ports:
        ts_per_flow[port] = [sys.maxint, 0]
    for ts, pkt in dpkt.pcap.Reader(open(FILENAME, 'rb')):
        if dpkt.ethernet.Ethernet(pkt).type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        if dpkt.ethernet.Ethernet(pkt).data.p == dpkt.ip.IP_PROTO_TCP:
            sport = dpkt.ethernet.Ethernet(pkt).data.data.sport
            if sport in ports:
                if ts < ts_per_flow[sport][0]:
                    ts_per_flow[sport][0] = ts
                if ts > ts_per_flow[sport][1]:
                    ts_per_flow[sport][1] = ts
    return ts_per_flow

def print_first_two_transactions(ports):
    for port in ports:
        conn_init_counter = 0
        for ts, pkt in dpkt.pcap.Reader(open(FILENAME, 'rb')):
            if dpkt.ethernet.Ethernet(pkt).type != dpkt.ethernet.ETH_TYPE_IP:
                continue
            if dpkt.ethernet.Ethernet(pkt).data.p == dpkt.ip.IP_PROTO_TCP:
                tcp = dpkt.ethernet.Ethernet(pkt).data.data
                if tcp.sport != port:
                    continue
                if conn_init_counter < 3:
                    conn_init_counter += 1
                elif conn_init_counter < 5:
                    print "Port: ", port, "Sequence number: ", tcp.seq, " Acknowledgement: ", tcp.ack, " Calculated window size: ", tcp.win * 16384
                    conn_init_counter += 1
                else:
                    break

def print_throughput(ports, tspf):
    data_count_pf = {}
    for port in ports:
        data_count_pf[port] = 0
    for ts, pkt in dpkt.pcap.Reader(open(FILENAME, 'rb')):
        if dpkt.ethernet.Ethernet(pkt).type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        if dpkt.ethernet.Ethernet(pkt).data.p == dpkt.ip.IP_PROTO_TCP:
            tcp = dpkt.ethernet.Ethernet(pkt).data.data
            if tcp.sport in ports:
                data_count_pf[tcp.sport] += len(tcp.data)
    for port in ports:
        print "Throughput for port ", port, " is: ", data_count_pf[port] / get_duration(port, tspf)


def calculate_rtt(rtt, nrtt):
    if rtt>1:
        print "   "
        print "New RTT: ", (1-ALPHA) * rtt + ALPHA * nrtt
        print "Old RTT: ", rtt
        print "   "
    # if ((1-ALPHA) * rtt + ALPHA * nrtt) > rtt:
    return (1-ALPHA) * rtt + ALPHA * nrtt
    # else:
    #     return rtt

def print_loss(ports):
    laf = {} # Lost and Found packets
    for port in ports:
        laf[port] = [0,0]
        seq_per_port = []
        re_tx_cnt = 0
        total_rx_cnt = 0
        dup_loss = {}
        dup_tx_count = 0
        conn_init_counter = 0
        prev_ts = 0
        dup_ack = [0, 0, 0]
        init_ts = 0
        set_init_seq = 0
        set_init_ts = 0
        rto = 0
        trans_counter = 0
        for ts, pkt in dpkt.pcap.Reader(open(FILENAME, 'rb')):
            if dpkt.ethernet.Ethernet(pkt).type != dpkt.ethernet.ETH_TYPE_IP:
                continue
            if dpkt.ethernet.Ethernet(pkt).data.p == dpkt.ip.IP_PROTO_TCP:
                tcp = dpkt.ethernet.Ethernet(pkt).data.data
                if tcp.dport == port:
                    if tcp.ack in dup_loss:
                        dup_loss[tcp.ack] += 1
                    else:
                        dup_loss[tcp.ack] = 1
                if tcp.sport == port:
                    total_rx_cnt += 1
                    if tcp.seq not in seq_per_port:
                        seq_per_port.append(tcp.seq)
                    else:
                        re_tx_cnt += 1
        for key in dup_loss:
            if dup_loss[key] >= 3:
                dup_tx_count += 1
        print "Lost packets/Lost due to re-TX/Lost due to timeout: ", re_tx_cnt, "/", dup_tx_count, "/", re_tx_cnt - dup_tx_count
        print "Loss rate for port ", port, ": ", 1.0 * re_tx_cnt / total_rx_cnt

def print_cwnd(ports):
    cwnd = {}
    for port in ports:
        conn_init_counter = 0
        prev_ts = 0
        rtt = 0
        fix_start_ts = 0
        start_ts = 0
        cwnd[port] = [0,0,0,0,0]
        iter = 0
        for ts, pkt in dpkt.pcap.Reader(open(FILENAME, 'rb')):
            if dpkt.ethernet.Ethernet(pkt).type != dpkt.ethernet.ETH_TYPE_IP:
                continue
            if dpkt.ethernet.Ethernet(pkt).data.p == dpkt.ip.IP_PROTO_TCP:
                tcp = dpkt.ethernet.Ethernet(pkt).data.data
                if tcp.sport == port:
                    if conn_init_counter < 2:
                        rtt = ts - prev_ts
                        prev_ts = ts
                        conn_init_counter += 1
                    else:
                        if fix_start_ts == 0:
                            start_ts = ts
                            fix_start_ts = 1
                        if ts < start_ts + rtt:
                            cwnd[port][iter] += len(tcp.data)
                            # print "cwnd[",port,"][",iter,"] = ", cwnd[port][iter]
                        else:
                            fix_start_ts = 0
                            iter += 1
                        if iter == 5:
                            break
    for port in ports:
        print "First five congestion window sizes for port ", port, ": ", cwnd[port][0],cwnd[port][1],cwnd[port][2],cwnd[port][3],cwnd[port][4]


def main():
    ports, num_ports = find_ports()
    print "In this pcap file we have ", num_ports, " flows"
    ts_per_flow = find_ts(ports)
    print_first_two_transactions(ports)
    print_throughput(ports, ts_per_flow)
    print_loss(ports)
    print_cwnd(ports)
    # for port in ports:
    #     print "Estimated loss:", est_loss[port][0]/est_loss[port][1], " loss: ", est_loss[port][0], " total packets: ", est_loss[port][1]


if __name__ == "__main__":
    main()