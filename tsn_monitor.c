#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


// PTP UDP Port (standard port is 319, 320)
#define PTP_DST_PORT_1 319
#define PTP_DST_PORT_2 320
// 필터링할 VLAN ID
#define VLAN_ID_FILTER 1  

// Hook function
static unsigned int ptp_udp_drop_hook(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state)
{
    struct ethhdr *eth;
    __be16 proto;
    u16 vlan_id;
    
    struct iphdr *ip_header;
    struct udphdr *udp_header;
    unsigned int dst_port;
 
    // 패킷 유효성 검사
    if (!skb) {
        printk(KERN_INFO "PTP Hook: Received NULL skb.\n");
        return NF_ACCEPT;
    }

    if(mode == TAS_Traffic_monitor) {
        // Ethernet 헤더 추출
        eth = eth_hdr(skb);
        if (!eth)
            return NF_ACCEPT;

        proto = eth->h_proto;
    
        // VLAN 태그 확인
        if (proto == htons(ETH_P_8021Q)) {
            // VLAN 헤더 추출
            vhdr = (struct vlan_hdr *)(skb->data + sizeof(struct ethhdr));
            vlan_id = ntohs(vhdr->h_vlan_TCI) & VLAN_VID_MASK;
            proto = vhdr->h_vlan_encapsulated_proto;

            // 원하는 VLAN ID 필터링
            if (vlan_id == VLAN_ID_FILTER)
                return NF_ACCEPT;
        } else {
            // VLAN 태그가 없는 경우 필터링 대상에서 제외
            return NF_ACCEPT;
        }
    }
    // IP 헤더 추출
    ip_header = ip_hdr(skb);
    if (!ip_header) {
        printk(KERN_INFO "TSN_Filter: Failed to get IP header.\n");
        return NF_ACCEPT;
    }

    // IPv4 UDP 패킷 확인
    if (ip_header->protocol != IPPROTO_UDP) {
        return NF_ACCEPT;
    }

    // UDP 헤더 추출
    udp_header = udp_hdr(skb);
    if (!udp_header) {
        printk(KERN_INFO "TSN_Filter: Failed to get UDP header.\n");
        return NF_ACCEPT;
    }

    // 목적지 포트 확인 (PTP 포트: 319, 320)
    dst_port = ntohs(udp_header->dest);
    if (dst_port == PTP_DST_PORT_1 || dst_port == PTP_DST_PORT_2) {
        printk(KERN_INFO "TSN_Filter: PTP message detected over UDP. Dropping packet.\n");
        return NF_DROP;
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops my_nfho = {
	.hook		= ptp_udp_drop_hook,
	.hooknum	= NF_INET_PRE_ROUTING,
	.pf		= PF_INET,
	.priority	= NF_IP_PRI_FIRST
	
};

static int __init ptp_drop_init(void)
{	
	printk("TSN_Filter: PTP Drop Start! \n");
	return nf_register_net_hook(&init_net, &my_nfho);
}

static void __exit ptp_drop_exit(void)
{
	printk("TSN_Filter: PTP Drop End! \n");
	nf_unregister_net_hook(&init_net, &my_nfho);
}

module_init(ptp_drop_init);
module_exit(ptp_drop_exit);

MODULE_LICENSE("GPL");


