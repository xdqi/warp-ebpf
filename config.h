#pragma once

#define MAKE_IPv4(a, b, c, d) ((((__u32) a) << 24) | ((b) << 16) | ((c) << 8) | (d))

struct warp_conversion {
    // warp client_id, all zero means EOF of configuration
    __u8 warp_private[3];
    // convert to warp format when endpoint (IP, Port) is source
    // (also implies converting to zeros when endpoint (IP, Port) is destination)
    bool is_source;
    // the (IP, port) to match
    struct sockaddr_in endpoint;
};

// configuration, allowing multiple warp instances on different (IP, port) combinations
static struct warp_conversion config[] = {
    {
        .warp_private = {11, 45, 14},
        .is_source = false,  // means convert to warp at TX, to zero at RX
        .endpoint = {
            .sin_family = AF_INET,
            .sin_addr = {
                // 162.159.192.1 is the IPv4 address of engage.cloudflareclient.com
                .s_addr = __bpf_constant_htonl(MAKE_IPv4(162, 159, 192, 1)),
            },
            .sin_port = __bpf_constant_htons(2408),
        },
    },
    {0}  // means EOF
};

// original reserved zero, don't touch it.
static const __u8 wg_reserved[3] = {0x00, 0x00, 0x00};
