# MODULES and PACKAGES
from bcc import BPF
from time import sleep
import socket
import struct
from ctypes import *
import pandas as pd
import time
# from kitsune
import numpy as numpy
from Kitsune import Kitsune
from scipy.stats import norm
from matplotlib import pyplot as plt
import traceback
import copy

# the number of temporal frame considered
my_lambdas = 5
# Maximum size for each autoencoder in the ensemble layer
maxAE = 10
# Number of instances used to learn the feature mapping
FMgrace = 1000
# Number of instances used to train the anomaly detector
ADgrace = 1000
# Instanciates Kitsune and its RMSE array
RMSEs = []
# The number of features aspected
featuresNumber = 100
# To store the features of the packet extracted
callback_features = []
# The packet information received
callback_packet = []
# List of ALL packets collected
list_of_packets = []
# The final labeling to be compared with the corresponding packets in the csv
packet_label = []

# Define the structure matching the eBPF program
class IpAddr(Union):
    _fields_ = [
        ("v4", c_uint32),
        ("v6", c_char * 16),
    ]

class PacketInfo(Structure):
    _fields_ = [
        ("src_mac", c_char * 6),
        ("dst_mac", c_char * 6),
        ("eth_proto", c_uint16),
        ("src_ip", IpAddr),
        ("dst_ip", IpAddr),
        ("ip_proto", c_uint16),
        ("sport", c_int32),
        ("dport", c_int32),
        ("IPType", c_uint16),
        ("pkt_len", c_uint16),
        ("timestamp", c_ulonglong),
    ]

class Features_1D(Structure):
    _fields_ = [
        ("w", c_uint32),
        ("mean", c_ulong),
        ("std_dev", c_ulong),
    ]

class Features_2D(Structure):
    _fields_ = [
        ("magnitude", c_ulong),
        ("radius", c_long),
        ("aprx_cov", c_long),
        ("corr_coeff", c_long),
    ]

class PacketFeature(Structure):
    _fields_ = [
        ("MI", Features_1D),
        ("jitter", Features_1D),
        ("socket_1D", Features_1D),
        ("socket_2D", Features_2D),
        ("channel_1D", Features_1D),
        ("channel_2D", Features_2D),
    ]

class AllPacketFeature(Structure):
    _fields_ = [
        ("packet_features", PacketFeature * my_lambdas),
    ]

class FinalPacket(Structure):
    _fields_ = [
        ("packet_info", PacketInfo),
        ("all_packet_features", AllPacketFeature),
    ]

# Helper function to convert IP from integer to readable format
def int_to_ip(ip):
    return socket.inet_ntoa(struct.pack('!I', ip)[::-1])

def int_to_mac_address(integer):
    # Ensure the integer fits within the 48-bit MAC address space
    if integer < 0 or integer > 0xFFFFFFFFFFFF:
        raise ValueError("Integer out of range for MAC address")
    
    # Convert the integer to a 12-character hex string (without the '0x' prefix)
    hex_string = f"{integer:012x}"
    
    # Split the hex string into 6 pairs of characters, then join with colons
    mac_address = ":".join(hex_string[i:i+2] for i in range(0, 12, 2))
    
    return mac_address

def callback(ctx, data, size):
    pkt = b.get_table("packet_and_features_ring")
    pkt = cast(data, POINTER(FinalPacket)).contents
    #pkt = copy.deepcopy(pkt)
    # The pkt sampling policy will be applied here detecting if
    # this pkt can be analysed or not
    '''
    print(
            f"Packet infos:\n"
            f"src_mac={pkt.packet_info.src_mac}, dest_mac={pkt.packet_info.dst_mac},\n"
            f"src_ip={int_to_ip(pkt.packet_info.src_ip.v4)}, dst_ip={int_to_ip(pkt.packet_info.dst_ip.v4)},\n"
            f"eth_protocol={pkt.packet_info.eth_proto}, ip_protocol={pkt.packet_info.ip_proto},\n"
            f"sport={pkt.packet_info.sport}, dport={pkt.packet_info.dport},\n"
            f"IPType={pkt.packet_info.IPType}, length={pkt.packet_info.pkt_len},\n"
            f"timestamp={pkt.packet_info.timestamp}, size={size}\n\n"
            f"Packet features:"
    )
    '''
    callback_packet.append(pkt.packet_info.src_ip.v4)
    callback_packet.append(pkt.packet_info.dst_ip.v4)
    callback_packet.append(pkt.packet_info.sport)
    callback_packet.append(pkt.packet_info.dport)
    callback_packet.append(pkt.packet_info.eth_proto)
    callback_packet.append(pkt.packet_info.ip_proto)

    # here the features list is filled with the values
    '''
    for i in range(my_lambdas):
        print(
            f"Lambda {i}:\n"
            f"MI_w={pkt.all_packet_features.packet_features[i].MI.w}, MI_mean={pkt.all_packet_features.packet_features[i].MI.mean}, MI_std_dev={pkt.all_packet_features.packet_features[i].MI.std_dev}\n"
            f"jitter_w={pkt.all_packet_features.packet_features[i].jitter.w}, jitter_mean={pkt.all_packet_features.packet_features[i].jitter.mean}, jitter_std_dev={pkt.all_packet_features.packet_features[i].jitter.std_dev}\n"
            f"socket_1D_w={pkt.all_packet_features.packet_features[i].socket_1D.w}, socket_1D_mean={pkt.all_packet_features.packet_features[i].socket_1D.mean}, socket_1D_std_dev={pkt.all_packet_features.packet_features[i].socket_1D.std_dev}\n"
            f"socket_2D_magnitude={pkt.all_packet_features.packet_features[i].socket_2D.magnitude}\n"
            f"socket_2D_radius={pkt.all_packet_features.packet_features[i].socket_2D.radius}\n"
            f"socket_2D_aprx_cov={pkt.all_packet_features.packet_features[i].socket_2D.aprx_cov}\n"
            f"socket_2D_corr_coeff={pkt.all_packet_features.packet_features[i].socket_2D.corr_coeff}\n"
            f"channel_1D_w={pkt.all_packet_features.packet_features[i].channel_1D.w}, channel_1D_mean={pkt.all_packet_features.packet_features[i].channel_1D.mean}, channel_1D_std_dev={pkt.all_packet_features.packet_features[i].channel_1D.std_dev}\n"
            f"channel_2D_magnitude={pkt.all_packet_features.packet_features[i].channel_2D.magnitude}\n"
            f"channel_2D_radius={pkt.all_packet_features.packet_features[i].channel_2D.radius}\n"
            f"channel_2D_aprx_cov={pkt.all_packet_features.packet_features[i].channel_2D.aprx_cov}\n"
            f"channel_2D_corr_coeff={pkt.all_packet_features.packet_features[i].channel_2D.corr_coeff}\n"
        )
    '''
    for i in range(my_lambdas):
        
        callback_features.append(pkt.all_packet_features.packet_features[i].MI.w)
        callback_features.append(pkt.all_packet_features.packet_features[i].MI.mean)
        callback_features.append(pkt.all_packet_features.packet_features[i].MI.std_dev)
        callback_features.append(pkt.all_packet_features.packet_features[i].jitter.w)
        callback_features.append(pkt.all_packet_features.packet_features[i].jitter.mean)
        callback_features.append(pkt.all_packet_features.packet_features[i].jitter.std_dev)
        callback_features.append(pkt.all_packet_features.packet_features[i].socket_1D.w)
        callback_features.append(pkt.all_packet_features.packet_features[i].socket_1D.mean)
        callback_features.append(pkt.all_packet_features.packet_features[i].socket_1D.std_dev)
        callback_features.append(pkt.all_packet_features.packet_features[i].socket_2D.magnitude)
        callback_features.append(pkt.all_packet_features.packet_features[i].socket_2D.radius)
        callback_features.append(pkt.all_packet_features.packet_features[i].socket_2D.aprx_cov)
        callback_features.append(pkt.all_packet_features.packet_features[i].socket_2D.corr_coeff)
        callback_features.append(pkt.all_packet_features.packet_features[i].channel_1D.w)
        callback_features.append(pkt.all_packet_features.packet_features[i].channel_1D.mean)
        callback_features.append(pkt.all_packet_features.packet_features[i].channel_1D.std_dev)
        callback_features.append(pkt.all_packet_features.packet_features[i].channel_2D.magnitude)
        callback_features.append(pkt.all_packet_features.packet_features[i].channel_2D.radius)
        callback_features.append(pkt.all_packet_features.packet_features[i].channel_2D.aprx_cov)
        callback_features.append(pkt.all_packet_features.packet_features[i].channel_2D.corr_coeff)

#name of eBPF program to compile
ebpf_program = "xdp_features_ring.c"

# Load BPF program
b = BPF(src_file=ebpf_program)

# Attach eBPF program to eXpress Data Path ingress hook
fn = b.load_func("xdp_ingress", BPF.XDP)

iface = "enp2s0f0np0"  # Dedicated network interface
b.attach_xdp(dev=iface, fn=fn, flags=0)

print("Attached BPF to interface: %s" % iface)

# Pointer to the ring buffer
ring = b.get_table("packet_and_features_ring")

ring.open_ring_buffer(callback)
print("Ring buffer is open!")

try:
    while True:
        time.sleep(1000000) # it's just to keep alive the eBPF program
    

except Exception as e:
    print(f"{e}")
    traceback.print_exc()
    print("\nRing buffer is closed now...\n")

finally:
    # Detach the eBPF program on exit
    b.remove_xdp(dev=iface, flags=0)
    print(f"Detached eBPF program from interface: {iface}")
