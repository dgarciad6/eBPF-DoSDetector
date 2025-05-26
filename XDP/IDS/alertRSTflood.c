/**
 * @author David García Diez
 * Program to detect RST flood attempt from an specific IP
 */

 #include <linux/bpf.h>
 #include <linux/if_ether.h>
 #include <linux/ip.h>
 #include <linux/tcp.h>
 #include <bpf/bpf_helpers.h>
 #include <linux/in.h>
 
 #define MAX_SYN_THRESHOLD 100
 
 struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(max_entries, 1024);
     __type(key, __u32);       // IP de origen
     __type(value, __u64);     // Contador de RSTs
     __uint(pinning, LIBBPF_PIN_BY_NAME);
 } rst_counter SEC(".maps");
 
 struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(max_entries, 1024);
     __type(key, __u32);       // IP atacante
     __type(value, __u64);     // Timestamp o 1 (marca de bloqueo)
     __uint(pinning, LIBBPF_PIN_BY_NAME);
 } dos_detector SEC(".maps");
 
 SEC("xdp")
 int xdp_alertRSTflood(struct xdp_md *ctx) {
     void *data = (void *)(long)ctx->data;
     void *data_end = (void *)(long)ctx->data_end;
 
     // Validamos cabecera Ethernet
     struct ethhdr *eth = data;
     if ((void *)(eth + 1) > data_end)
         return XDP_PASS;
 
     // Solo IPv4
     if (eth->h_proto != __constant_htons(ETH_P_IP))
         return XDP_PASS;
 
     // Cabecera IP
     struct iphdr *ip = (void *)(eth + 1);
     if ((void *)(ip + 1) > data_end)
         return XDP_PASS;
 
     if (ip->protocol != IPPROTO_TCP)
         return XDP_PASS;
 
     // Cabecera TCP
     struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
     if ((void *)(tcp + 1) > data_end)
         return XDP_PASS;
 
     // Cabecera RST
     if (tcp->rst && !tcp->ack && !tcp->fin && !tcp->psh && !tcp->syn && !tcp->urg) {
         __u32 src_ip = ip->saddr;
         __u64 *count = bpf_map_lookup_elem(&rst_counter, &src_ip);
         __u64 new_count = 1;
 
         if (count)
             new_count = *count + 1;
 
         bpf_map_update_elem(&rst_counter, &src_ip, &new_count, BPF_ANY);
 
         if (new_count > MAX_SYN_THRESHOLD) {
             __u64 flag = 1;
             bpf_map_update_elem(&dos_detector, &src_ip, &flag, BPF_ANY);
         }
     }
 
     return XDP_PASS;
 }
 
 char __license[] SEC("license") = "GPL";
 