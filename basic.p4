/* -*- P4_16 -*- */
/*
Created by Parardha Sarmah
*/
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<2>    version;
    bit<6>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}
header tcp_options_t{
    varbit<320> opt;
}
header mqtt_fixed_t{
    bit<4> pkttype;
    bit<4> flags;
}
header mqtt_len_t{
    varbit<8> rem_len;
}
header mqtt_variable_t{
    bit<16> topic_len;
    bit<448> topic_name;
    bit<16> pkt_id;
}
struct metadata {
}
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t      tcp;
    tcp_options_t tcp_opt;
    mqtt_fixed_t mqtt_fixed;
    mqtt_len_t mqtt_len;
    mqtt_variable_t mqtt_var;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        packet.extract(hdr.tcp_opt,(((bit <32>)hdr.tcp.dataOffset)*32)-160);
        transition select(hdr.tcp.dstPort){
            1883:parse_mqtt;
            default:accept;
        }
    }
    state parse_mqtt{
        packet.extract(hdr.mqtt_fixed);
        transition select(hdr.mqtt_fixed.pkttype){
            4w3:parse_totallen;
            default:accept;
        }
    }
    state parse_totallen{
        bit<1> p1=packet.lookahead<bit<1>>();
        packet.extract(hdr.mqtt_len,8);
        transition select(p1){
            0:parse_varhdr;
            1:parse_totallen;
        }
    }
    state parse_varhdr{
        packet.extract(hdr.mqtt_var);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        if(hdr.mqtt_var.topic_name==448w0x696f6d742f70617469656e742f626f64795f74656d70){
            hdr.ipv4.dscp=57;
        }
        else if(hdr.mqtt_var.topic_name==448w0x696f6d742f70617469656e742f726f6f6d5f74656d70){
            hdr.ipv4.dscp=59;
        }
        else if(hdr.mqtt_var.topic_name==448w0x696f6d742f70617469656e742f677372526561646572){
            hdr.ipv4.dscp=58;
        }
        else if(hdr.mqtt_var.topic_name==448w0x696f6d742f70617469656e742f68756d69646974795f){
            hdr.ipv4.dscp=60;
        }
        else if(hdr.mqtt_var.topic_name==448w0x696f6d742f70617469656e742f73706f325f696e666f){
            hdr.ipv4.dscp=62;
        }
        else if(hdr.mqtt_var.topic_name==448w0x696f6d742f70617469656e742f70756c736564617461){
            hdr.ipv4.dscp=61;
        }
        else if(hdr.mqtt_var.topic_name==448w0x696f6d742f70617469656e742f6563675f696e666f72){
            hdr.ipv4.dscp=63;
        }
        else if(hdr.mqtt_var.topic_name==448w0x696f6d742f70617469656e742f737973746f6c69635f){
            hdr.ipv4.dscp=49;
        }
        else if(hdr.mqtt_var.topic_name==448w0x696f6d742f70617469656e742f64696173746f6c6963){
            hdr.ipv4.dscp=50;
        }
        else if(hdr.mqtt_var.topic_name==448w0x73656e736f722f37306666326438322d393732652d313165362d386264652d343438353030303162633634622f646174612f74657374){
            hdr.ipv4.dscp=51;
        }
    }

    table ipv4 {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4.apply();
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcp_opt);
        packet.emit(hdr.mqtt_fixed);
        packet.emit(hdr.mqtt_len);
        packet.emit(hdr.mqtt_var);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
