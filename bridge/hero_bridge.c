/* hero_bridge.c — 读 KPM herobin 定长 seqlock 文件, 通过 WebSocket 推送 JSON
 * 用法: hero_bridge [bin_path] [port]    默认 /data/local/tmp/heroes.bin 8787
 * 编译: clang -O2 -o hero_bridge hero_bridge.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <time.h>
#include <math.h>
#include "heromap.h"

/* 英雄 id -> 名字 (来自模块的 heromap.h) */
static const char *hname(unsigned int id)
{
    unsigned int i;
    for (i = 0; i < (unsigned int)(sizeof(g_heromap)/sizeof(g_heromap[0])); i++)
        if (g_heromap[i].id == id) return g_heromap[i].name;
    return "?";
}

/* ---------- 与模块一致的记录布局 (packed, 小端) ---------- */
struct hb_eq { uint16_t id, cnt; } __attribute__((packed));
struct hb_sk { uint8_t lvl, ready, lvlup, bean; int32_t cd, cdmax, power, powermax, tgt, hit; } __attribute__((packed));
struct hb_rec {
    uint32_t heroid, camp, objid;
    int32_t hp, hpmax, exp, expmax, lvl, gold, incgold;
    int32_t charge, chargemax, shield, shieldmax;
    int32_t x, y, z, fx, fz, move, groundy;
    int32_t mx, mz;              /* 小地图组件位置 */
    int32_t ad, def, res;
    uint32_t atktarget;
    uint8_t dead, dying, grass, freeze, battle, nomove, inroom, fantasy, autoai, lvis, cam, me;
    uint32_t eqn;
    struct hb_eq eq[8];
    struct hb_sk sk[6];
} __attribute__((packed));
struct hb_hdr { uint32_t magic, version, seq, rec_size, max_rec, n; uint64_t ts_ms; uint32_t flags, rsv[7]; } __attribute__((packed));
#define HB_MAGIC 0x48523031u

static long long cnow_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ---------- 最小 SHA1 + base64 (WS 握手用) ---------- */
static void sha1(const uint8_t *m, size_t len, uint8_t out[20]) {
    uint32_t h[5] = {0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0};
    size_t n = ((len + 9 + 63) / 64) * 64;
    uint8_t *b = calloc(1, n);
    memcpy(b, m, len); b[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) b[n - 1 - i] = (bits >> (8 * i)) & 0xff;
    for (size_t o = 0; o < n; o += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++)
            w[i] = (b[o+4*i]<<24)|(b[o+4*i+1]<<16)|(b[o+4*i+2]<<8)|b[o+4*i+3];
        for (int i = 16; i < 80; i++) {
            uint32_t v = w[i-3]^w[i-8]^w[i-14]^w[i-16];
            w[i] = (v<<1)|(v>>31);
        }
        uint32_t a=h[0],c=h[1],d=h[2],e=h[3],f=h[4];
        for (int i = 0; i < 80; i++) {
            uint32_t k, t;
            if (i<20){t=(c&d)|((~c)&e);k=0x5A827999;}
            else if(i<40){t=c^d^e;k=0x6ED9EBA1;}
            else if(i<60){t=(c&d)|(c&e)|(d&e);k=0x8F1BBCDC;}
            else{t=c^d^e;k=0xCA62C1D6;}
            uint32_t tmp=((a<<5)|(a>>27))+t+f+k+w[i]; f=e;e=d;d=(c<<30)|(c>>2);c=a;a=tmp;
        }
        h[0]+=a;h[1]+=c;h[2]+=d;h[3]+=e;h[4]+=f;
    }
    free(b);
    for (int i = 0; i < 5; i++) { out[4*i]=h[i]>>24; out[4*i+1]=h[i]>>16; out[4*i+2]=h[i]>>8; out[4*i+3]=h[i]; }
}
static void b64(const uint8_t *in, int n, char *out) {
    static const char *T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, o = 0;
    for (i = 0; i + 2 < n; i += 3) {
        out[o++]=T[in[i]>>2]; out[o++]=T[((in[i]&3)<<4)|(in[i+1]>>4)];
        out[o++]=T[((in[i+1]&15)<<2)|(in[i+2]>>6)]; out[o++]=T[in[i+2]&63];
    }
    if (i < n) {
        out[o++]=T[in[i]>>2];
        if (i+1 < n){ out[o++]=T[((in[i]&3)<<4)|(in[i+1]>>4)]; out[o++]=T[(in[i+1]&15)<<2]; }
        else out[o++]=T[(in[i]&3)<<4];
        out[o++]='=';
    }
    out[o]=0;
}

/* ---------- 读文件 (seqlock) 并生成 JSON ---------- */
static char g_json[16384];
static int  g_json_len = 0;

static int build_json(const volatile uint8_t *m) {
    const struct hb_hdr *H = (const struct hb_hdr *)m;
    const struct hb_rec *R;
    int i, o = 0;
    uint32_t n;
    if (H->magic != HB_MAGIC) return -1;
    if (H->rec_size != sizeof(struct hb_rec)) return -1;
    if (H->n > H->max_rec) n = H->max_rec; else n = H->n;
    R = (const struct hb_rec *)(m + sizeof(struct hb_hdr));
    o += snprintf(g_json+o, sizeof(g_json)-o, "{\"seq\":%u,\"n\":%u,\"heroes\":[", H->seq, n);
    for (i = 0; i < (int)n && o < (int)sizeof(g_json)-600; i++) {
        const struct hb_rec *r = &R[i];
        int k, fyaw, px, pz;
        { float qy, qw; memcpy(&qy, &r->fx, 4); memcpy(&qw, &r->fz, 4);
          fyaw = (int)(atan2f(2.0f*qw*qy, 1.0f - 2.0f*qy*qy) * 1000.0f); }   /* 朝向 yaw (毫弧度) */
        /* 优先 native 链坐标 (mx/mz, 无值时回退 C# 镜像); 雾中 C# 会冻结, native 不会 */
        /* 原生坐标只在两个轴都有效时采用: 实测会偶发 (0,z) 脏值,
         * 否则会把最近敌人算错 (箭头/距离/人数全错)。 */
        px = (r->mx && r->mz) ? r->mx : r->x;
        pz = (r->mx && r->mz) ? r->mz : r->z;
        o += snprintf(g_json+o, sizeof(g_json)-o,
            "%s{\"heroid\":%u,\"camp\":%u,\"objid\":%u,\"me\":%u,\"name\":\"%s\","
            "\"hp\":%d,\"hpmax\":%d,\"lvl\":%d,\"gold\":%d,"
            "\"x\":%d,\"y\":%d,\"z\":%d,\"move\":%d,\"fyaw\":%d,\"mx\":%d,\"mz\":%d,"
            "\"ad\":%d,\"def\":%d,\"res\":%d,"
            "\"dead\":%u,\"dying\":%u,\"grass\":%u,\"freeze\":%u,\"battle\":%u,"
            "\"nomove\":%u,\"inroom\":%u,\"fantasy\":%u,\"autoai\":%u,\"lvis\":%u,\"cam\":%u,"
            "\"atktarget\":%u,\"eqn\":%u,\"eq\":[",
            i?" ,":"", r->heroid, r->camp, r->objid, r->me, hname(r->heroid),
            r->hp, r->hpmax, r->lvl, r->gold, px, r->y, pz, r->move, fyaw, r->mx, r->mz,
            r->ad, r->def, r->res,
            r->dead, r->dying, r->grass, r->freeze, r->battle,
            r->nomove, r->inroom, r->fantasy, r->autoai, r->lvis, r->cam,
            r->atktarget, r->eqn);
        for (k = 0; k < (int)r->eqn && k < 8; k++)
            o += snprintf(g_json+o, sizeof(g_json)-o, "%s[%u,%u]", k?" ,":"", r->eq[k].id, r->eq[k].cnt);
        o += snprintf(g_json+o, sizeof(g_json)-o, "],\"skills\":[");
        for (k = 0; k < 6; k++) {
            const struct hb_sk *s = &r->sk[k];
            o += snprintf(g_json+o, sizeof(g_json)-o,
                "%s{\"s\":%d,\"lvl\":%u,\"cd\":%d,\"cdmax\":%d,\"ready\":%u,\"bean\":%u,\"power\":%d,\"powermax\":%d,\"tgt\":%d,\"hit\":%d,\"lvlup\":%u}",
                k?",":"", k, s->lvl, s->cd, s->cdmax, s->ready, s->bean, s->power, s->powermax, s->tgt, s->hit, s->lvlup);
        }
        o += snprintf(g_json+o, sizeof(g_json)-o, "]}");
    }
    o += snprintf(g_json+o, sizeof(g_json)-o, "]}\n");
    g_json_len = o;
    return 0;
}

/* ---------- WebSocket 发送 ---------- */

static int ws_send(int fd, const char *buf, int len) {
    uint8_t hdr[10]; int hl = 0, i;
    hdr[0] = 0x81; /* FIN + text */
    if (len < 126) hdr[1] = (uint8_t)len, hl = 2;
    else if (len < 65536) { hdr[1] = 126; hdr[2] = (len>>8)&0xff; hdr[3] = len&0xff; hl = 4; }
    else { hdr[1] = 127; for (i = 0; i < 8; i++) hdr[2+i] = (len >> (56-8*i)) & 0xff; hl = 10; }
    if (send(fd, hdr, hl, MSG_NOSIGNAL) < 0) return -1;
    if (send(fd, buf, len, MSG_NOSIGNAL) < 0) return -1;
    return 0;
}
/* 处理握手 (读 HTTP 请求, 回 101 + Sec-WebSocket-Accept) */
static int ws_handshake(int fd) {
    char req[2048]; int n = recv(fd, req, sizeof(req)-1, 0);
    char *key, *end; char acc[64], raw[128];
    if (n <= 0) return -1;
    req[n] = 0;
    key = strcasestr(req, "Sec-WebSocket-Key:");
    if (!key) return -1;
    key += strlen("Sec-WebSocket-Key:");
    while (*key == ' ') key++;
    end = strstr(key, "\r\n"); if (!end) return -1; *end = 0;
    snprintf(raw, sizeof(raw), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    { uint8_t sh[20]; sha1((const uint8_t *)raw, strlen(raw), sh); b64(sh, 20, acc); }
    {
        char resp[256];
        int rl = snprintf(resp, sizeof(resp),
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n\r\n", acc);
        if (send(fd, resp, rl, MSG_NOSIGNAL) < 0) return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "/data/local/tmp/heroes.bin";
    int port = argc > 2 ? atoi(argv[2]) : 8787;
    int lfd, cfd = -1;
    struct sockaddr_in sa;
    int one = 1;
    void *m = NULL; size_t msz = 0;
    int ffd = -1;
    uint32_t last_seq = 0xffffffffu;
    int last_n = -1;
    long long last_send_ms = 0;   /* 心跳: 至少每 1s 推一帧, 客户端不会读超时 */

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   /* 仅本机 */
    sa.sin_port = htons(port);
    if (bind(lfd, (void*)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }
    listen(lfd, 4);
    fprintf(stderr, "[bridge] listening ws://127.0.0.1:%d/ws  file=%s\n", port, path);

    for (;;) {
        fd_set rf; struct timeval tv; int r;
        /* 打开文件 (可能还没创建) */
        if (ffd < 0) {
            ffd = open(path, O_RDONLY);
            if (ffd >= 0) {
                struct stat st;
                if (fstat(ffd, &st) == 0) {
                    msz = st.st_size; m = mmap(NULL, msz, PROT_READ, MAP_SHARED, ffd, 0);
                    if (m == MAP_FAILED) { m = NULL; close(ffd); ffd = -1; }
                    else fprintf(stderr, "[bridge] mmap %s (%zu B)\n", path, msz);
                }
            }
        }
        FD_ZERO(&rf);
        FD_SET(lfd, &rf);
        if (cfd >= 0) FD_SET(cfd, &rf);
        tv.tv_sec = 0; tv.tv_usec = 20000; /* 20ms: 数据 200ms 一帧, 降低空转唤醒 */
        r = select((cfd > lfd ? cfd : lfd) + 1, &rf, NULL, NULL, &tv);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r == 0) { /* timeout -> 检查新帧 + 心跳 */
            long long nowms = cnow_ms();
            if (m) {
                const struct hb_hdr *H = (const struct hb_hdr *)m;
                uint32_t s1 = H->seq, s2;
                if ((s1 & 1) == 0 && (s1 != last_seq || (int)H->n != last_n)) {
                    last_n = (int)H->n;
                    if (build_json(m) == 0) {
                        s2 = H->seq;
                        if (s2 == s1 && cfd >= 0) {
                            if (ws_send(cfd, g_json, g_json_len) < 0) { close(cfd); cfd = -1; }
                            else last_send_ms = nowms;
                        }
                        if (s2 == s1) last_seq = s1;
                    }
                }
                /* 心跳: seq 没变也至少每 1s 推一次, 免得客户端读超时反复重连 */
                if (cfd >= 0 && nowms - last_send_ms >= 1000 && build_json(m) == 0) {
                    if (ws_send(cfd, g_json, g_json_len) < 0) { close(cfd); cfd = -1; }
                    else last_send_ms = nowms;
                }
            }
            continue;
        }
        if (FD_ISSET(lfd, &rf)) {
            int nf = accept(lfd, NULL, NULL);
            if (nf >= 0) {
                if (cfd >= 0) close(cfd);
                if (ws_handshake(nf) == 0) { cfd = nf; last_seq = 0xffffffffu; fprintf(stderr, "[bridge] client connected\n"); }
                else close(nf);
            }
        }
        if (cfd >= 0 && FD_ISSET(cfd, &rf)) {
            char tmp[256];
            if (recv(cfd, tmp, sizeof(tmp), 0) <= 0) { close(cfd); cfd = -1; fprintf(stderr, "[bridge] client disconnected\n"); }
            /* 忽略客户端消息 (含 ping/close); 简化处理 */
        }
    }
    return 0;
}
