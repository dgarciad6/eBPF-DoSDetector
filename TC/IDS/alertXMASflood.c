/**
 * @author David García Diez
 * Program to detect XMAS flood attempt from an specific IP
 * 
 */

 #include <linux/bpf.h>
 #include <linux/ip.h>
 #include <linux/tcp.h>
 #include <bpf/bpf_helpers.h>
 #include <linux/if_ether.h>
 #include <linux/in.h>
 #include <linux/pkt_cls.h>
 
 
 #define MAX_XMAS_THRESHOLD 100
 
 //Mapa para contar paquetes XMAS
 struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(max_entries, 1024);
     __type(key, __u32);       // IP de origen
     __type(value, __u64);     // Contador de SYNs
     __uint(pinning, LIBBPF_PIN_BY_NAME);
 } xmas_counter SEC(".maps");
 
 //Mapa para guardar una especie de lista negra de IPs
 struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(max_entries, 1024);
     __type(key, __u32);       // IP atacante
     __type(value, __u64);     // Timestamp o 1 (marca de bloqueo)
     __uint(pinning, LIBBPF_PIN_BY_NAME);
 } dos_detector SEC(".maps");
 
 SEC("tcx/ingress")
 int alertXMASflood(struct __sk_buff *skb) {
     void *data_end = (void *)(long)skb->data_end;
     void *data = (void *)(long)skb->data;
 
     struct iphdr *ip = data + sizeof(struct ethhdr);
     if ((void *)(ip + 1) > data_end)
         return TC_ACT_OK;
 
     if (ip->protocol != IPPROTO_TCP)
         return TC_ACT_OK;
 
     struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
     if ((void *)(tcp + 1) > data_end)
         return TC_ACT_OK;
 
         //XMAS FLOOD -> FIN, PSH & URG
     if (tcp->fin && tcp->psh && tcp->urg && !tcp->ack && !tcp->rst && !tcp->syn) {
         __u32 src_ip = ip->saddr;
         __u64 *count = bpf_map_lookup_elem(&xmas_counter, &src_ip);
         __u64 new_count = 1;
 
         if (count) {
             new_count = *count + 1;
         }
 
         bpf_map_update_elem(&xmas_counter, &src_ip, &new_count, BPF_ANY);
 
         if (new_count > MAX_XMAS_THRESHOLD) {
             __u64 flag = 1;
             bpf_map_update_elem(&dos_detector, &src_ip, &flag, BPF_ANY);
         }
     }
 
     return TC_ACT_OK;
 }
 
 char __license[] SEC("license") = "GPL";
 