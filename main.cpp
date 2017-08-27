// UDP Gaming Firewall

#include "ban.h"
#include "haxball_whitelist.h"
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

AttackFirewall fw;

static u_int32_t verdict_pkt(struct nfq_data *tb, u_int32_t *verdict)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        ret = nfq_get_payload(tb, &data);
        if (ret < 20 + 8) // not a full IPv4 + UDP header
        {
            return id;
        }
        id = ntohl(ph->packet_id);
        int hw_proto = ntohs(ph->hw_protocol);
        if (hw_proto != 0x0800 || data[9] != 0x11) // IPv4 and UDP
        {
            return id;
        }
        uint32_t saddr = ntohl(*((uint32_t *)(data + 12)));
        uint32_t daddr = ntohl(*((uint32_t *)(data + 16)));
        uint16_t sport = ntohs(*((uint16_t *)(data + 20)));
        uint16_t dport = ntohs(*((uint16_t *)(data + 22)));
        if (dport < 1024) {
            return id;
        }
        BanStatus info = fw.ReceivePacket(saddr, sport);
        if (info == BanStatus::Banned || info == BanStatus::Ban) {
            *verdict = NF_DROP;
        }
        fw.ClearOldEntries();
    }
    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t verdict = NF_ACCEPT; // default policy
    u_int32_t id = verdict_pkt(nfa, &verdict);
    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

int main(int argc, char **argv)
{
    struct rlimit core_limits;
    core_limits.rlim_cur = core_limits.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &core_limits);
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--block-data-centers") == 0)
        {
            fprintf(stderr, "Blocking data center IP ranges.\n");
            fw.SetBlacklist(&DataCenters, &HaxBallMatcher);
        }
    }

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[0xFFFF] __attribute__((aligned));

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);

    nfq_close(h);

    exit(0);
}
