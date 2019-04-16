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
                    print port, tcp.seq, tcp.ack, tcp.win * 16384
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
    return (1-ALPHA) * rtt + ALPHA * nrtt

def find_loss(ports):
    for port in ports:
        conn_init_counter = 0
        rtt = 0;
        prev_ts = 0;
        for ts, pkt in dpkt.pcap.Reader(open(FILENAME, 'rb')):
            if dpkt.ethernet.Ethernet(pkt).type != dpkt.ethernet.ETH_TYPE_IP:
                continue
            if dpkt.ethernet.Ethernet(pkt).data.p == dpkt.ip.IP_PROTO_TCP:
                tcp = dpkt.ethernet.Ethernet(pkt).data.data
                if tcp.sport != port:
                    continue
                if conn_init_counter < 2:
                    print "Timestamp: ", ts
                    prev_ts = ts
                    rtt = ts - prev_ts
                    conn_init_counter += 1
                elif conn_init_counter < 5:
                    rtt = calculate_rtt(rtt, ts - prev_ts)
                    print "RTT: ", rtt, " port: ", port
                    prev_ts = ts
                    conn_init_counter += 1
                else:
                    break



def main():
    ports, num_ports = find_ports()
    ts_per_flow = find_ts(ports)
    print_first_two_transactions(ports)
    print_throughput(ports, ts_per_flow)
    find_loss(ports)


if __name__ == "__main__":
    main()