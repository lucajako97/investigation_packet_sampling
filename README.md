# An Investigation on packet sampling

In this repo there is the code used in the research paper "An Investigation on Packet Sampling between Kernel and User Space for NIDS" for testing the performance of a considered kernel-to-user-space pipeline.

## Testbed

The PCs are two Lenovo ThinkCentre M720t with an Intel Core i5-8400 hexa-core CPU with a frequency of 2.8 GHz, working in an architecture x86 at 64 bits, 6 cores per socket, 1 thread per core, and a RAM of 32 GB. They mount Ubuntu 22.04.5 LTS as OS with a 6.8.0-52-generic kernel. The peer-to-peer link is a Gigabit connection.

(ongoing: The programmable firewalls are two Protectli VP6650 with a Intel Core i5-1235U twelve-core CPU with a maximum frequency of 4.4GHz, working in an architecture x86 at 64 bits, 10 cores per socket, 2 threads per core, and a RAM of 64 GB. They mount Ubuntu 22.04.5 LTS as OS with a 6.8.0-52-generic kernel. The peer-to-peer link is a 10 Gigabit/s connection)

## Requirements

First of all, make sure your machines are updated:

```
sudo apt update
sudo apt upgrade
```

You are required to install the iperf3 tool on both the machines (we have used the 3.9 version):

```
sudo apt -y install iperf3
```

From now on the installing phase will take place only on the machine labeled as the Server!

It is required to have installed [python3](https://www.cherryservers.com/blog/install-python-on-ubuntu) and pip3 (we have tested all the code with the 3.10.12 and 22.0.2 version respectively) in conjunction with the requirements:

```
sudo pip3 install -r requirements.txt
```

Then, you will need to install some tools and headers in order to run the code:

```
sudo apt install clang llvm libelf-dev linux-headers-$(uname -r) gcc make git
sudo apt install bpfcc-tools python3-bpfcc
```

To test the feature reader written in C, you will need to download also the libbpf library:

```
sudo apt install libbpf-dev
```


## How to start the tests

This procedure MUST be executed in this exact order!

The first step is to run the eBPF loader written in Python with one of these two commands, depending on which part of the pipeline you want to test (only the feature extractor, the features reader written in Python, and kitnet with the complete pipeline on):

```
sudo python3 xdp_features_FE.py

sudo python3 xdp_features_ring_FE_reader_python.py

sudo python3 xdp_features_ring_FE_reader_kitnet.py
```

Then, you need to activate the iperf3 server running this command on the server machine (the default port should be fine):

```
iperf3 -s
```

As final step, you need to run the client iperf3 tool in the client machine:

```
iperf3 -c server_ip -M packet_size -t 600 // for TCP
iperf3 -c server_ip --length packet_size -u -b desired_throughput -t 600 // for UDP
```

### Testing the C-coded features reader

If you want to test the reading procedure with the reader written in C: you need to identify the map id of the ring buffer data structure used in eBPF to collect the features while running a version of the python code which is not reading the features in python.

The steps are these:

```
// run the adjusted python version
sudo python3 xdp_features_ring_FE_.py

// find the map id
sudo bpftool map show | grep packet_and_feat
// obtaining a similar result:
// map_id: ringbuf  name packet_and_feat  flags 0x0

// to compile the reader in C after having inserted the map id
gcc features_reader.c -o features_reader.o -lbpf

// execute the reader
./features_reader.o
```

and then you need to start the server and client with iperf3.


### eBPF debugging

We are using the BCC toolkit in python which is helping us to compile the eBPF program, to attach and deattach it to the XDP hook, and to load the maps into the user space.

To check if an eBPF print statement is working, you need to read the kernel's trace buffer. The easiest way to do this is by using the trace_pipe file located in the /sys/kernel/debug/tracing directory with this comand:

```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

The trace_pipe file will continuously show any new prints from the kernel's trace buffer, so you can keep it open while your eBPF program processes packets.
