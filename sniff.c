/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1986, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copright (c) 2006-2010  Kazuyoshi Aizawa <admin2@whiteboard.ne.jp>
 * All rights reserved.
 */
/*********************************************
 * sniff.c
 * 
 * packet monitor using DLPI
 *
 * gcc sniff.c -lnsl -o sniff
 * 
 ********************************************/
#Include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stropts.h>
#include <sys/dlpi.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/signal.h>
#include <sys/stream.h>
#include <string.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/varargs.h>
#include <errno.h>
#include <unistd.h>

#define  ERR_MSG_MAX 300
#define  MAXDLBUFSIZE  8192
#define  DLBUFSIZE     8192
#define  TCP_DATA_PRINT_LENGTH  100
#define  PRINT_MAC_ADDR(ether_addr_octet)     {         \
        int i;                                          \
        for ( i =0; i < 6; i++){                        \
            printf("%02x",(ether_addr_octet[i]));       \
            if(i != 5)                                  \
                printf(":");                            \
        }                                               \
    }

void   print_packet(caddr_t,  int);
void   print_usage(char *);
int    dlattachreq(int, t_uscalar_t, caddr_t );
int    dlpromisconreq(int, t_uscalar_t, caddr_t);
int    dlbindreq(int, t_uscalar_t, t_uscalar_t, uint16_t, uint16_t, t_uscalar_t, caddr_t);
void   print_err(int , char *, ...);
int    dldetachreq(int , caddr_t);
int    dlpromiscoffreq(int, t_uscalar_t, caddr_t);

int
main(int argc, char *argv[])
{
    char                   buf[DLBUFSIZE]; // getmsg(2) で利用するバッファ
    struct strbuf          databuf; // getmsg(2) に引数として渡す構造体    
    union  DL_primitives  *dlp;
    int                    flags = 0;
    int                    ppa;  // NIC のインスタンス番号に相当(Physical Point of Attachment)
    int                    sap;  // Ethernet フレームタイプに相当(Service Access Point)
    int                    fd;   // デバイスをオープンしたファイル記述子
    struct  strioctl	   strioc; // stream デバイス用の ioctl(2) のコマンドを指定する構造体
    char                  *interface; // 引数で渡されたインターフェース名 (例: hme0)
    char                   devname[30] = {0};  // interface 名から instance を取ったもの (例: hme)
    char                   devpath[30] = {0};  // open() 時に指定する device file への path (例: /dev/hme)
    char                  *instance;  // interface の instance 番号。ppa となる (例: 0)
    
    if (argc != 2)
        print_usage(argv[0]);

    interface = argv[1];
    if ((instance = strpbrk(interface, "0123456789")) == NULL){
        fprintf(stderr, "%s: no instance specified\n", interface);                
        print_usage(argv[0]);
    }

    ppa = atoi(instance);

    strncpy(devname, interface, instance - interface);

    sprintf(devpath, "/dev/%s",devname);

    /*
     * デバイスをオープンする
     */    
    if((fd = open (devpath , O_RDWR)) < 0 ){
        perror("open");
        exit(1);
    }

    /*
     * PPA(instance) にアッタチする
     */    
    if(dlattachreq(fd, ppa, buf) < 0){
        fprintf(stderr, "%s: no such instance\n", interface);        
        print_usage(argv[0]);
    }

    /*
     * プロミスキャスモードをセット
     */    
    if(dlpromisconreq(fd, DL_PROMISC_PHYS, buf) < 0){
        fprintf(stderr, "%s: Cannot set promiscuous mode\n", interface);
        exit(1);
    }

    /*
     * SAP(flame type) にバインド
     */    
    if(dlbindreq (fd, ETHERTYPE_IP, 0, DL_CLDLS, 0, 0, buf) < 0){
        fprintf(stderr, "%s: Cannot bind to ETHERTYPE_IP\n", interface);
        exit(1);
    }

    /*
     * RAW モードにセット
     */
    strioc.ic_cmd    = DLIOCRAW;
    strioc.ic_timout = -1;
    strioc.ic_len    = 0;
    strioc.ic_dp     = NULL;
    if(ioctl(fd, I_STR, &strioc) < 0){
        perror("ioctl: I_STR: DLIOCRAW");
        exit(1);
    }

    /*
     * キューをフラッシュ
     */        
    if (ioctl(fd, I_FLUSH, FLUSHR) < 0){
        perror("ioctl: I_FLUSH");
        exit(1);
    }

    databuf.maxlen = MAXDLBUFSIZE;
    databuf.len = 0;
    databuf.buf = (caddr_t)buf;    

    while (getmsg(fd, NULL, &databuf, &flags) == 0) {
        if (databuf.len > 0)
            print_packet(databuf.buf, databuf.len);
    }
    
    perror("getmsg");
    exit(1);    
}

void
print_packet(caddr_t buf, int len)
{
    struct ether_header   *ether;
    struct tcphdr         *tcp;
    struct ip             *ip;
    u_char                *tcpdata;
    int                    etherlen;
    int                    iphlen;
    int                    iptotlen;
    int                    tcphlen;
    int                    tcpdatalen;

    etherlen = sizeof(struct ether_header);
    ether = (struct ether_header *)buf;

    /*
     * Ether Type が IP(0x800) じゃなかったらリターン
     */
    if(ether->ether_type != ETHERTYPE_IP)
        return;

    /*
     * 全フレームサイズがデフォルト（最小）の ether, ip, tcp
     * ヘッダー長の合計よりも小さかったら不正パケットとみなして
     * リターン。
     */
    if(len < etherlen + sizeof(struct ip) + sizeof(struct tcphdr) )
        return;

    /*
     * アライメントエラーを避けるため、IP ヘッダー以降を、別途確保
     * したメモリにコピーする。
     */
    ip = (struct ip *)malloc(len);
    memcpy(ip, buf + etherlen, len);

    /*
     * TCP でなければリターン
     */
    if(ip->ip_p != IPPROTO_TCP)
        goto error;

    iphlen = ip->ip_hl << 2;

    /*
     * パケット内で申告されている IP ヘッダー長が分かった
     * ので改めて、フレーム長を確認。
     * もし小さかったら不正パケットとみなして無視。
     */
    if(len < etherlen + iphlen + sizeof(struct tcphdr) )
        goto error;
    
    tcp = (struct tcphdr *)((u_char *)ip + iphlen);
    tcphlen = tcp->th_off << 2;

    /*
     * パケット内で申告されている TCP ヘッダー長が分かった
     * ので改めて、フレーム長を確認。
     * もし小さかったら不正パケットとみなして無視。
     */
    if(len < etherlen + iphlen + tcphlen )
        goto error;
    
    printf("\n----Ether Header----\n");
    printf("src addr    : ");
    PRINT_MAC_ADDR(ether->ether_shost.ether_addr_octet);
    printf("\n");
    printf("dest addr   : ");
    PRINT_MAC_ADDR(ether->ether_dhost.ether_addr_octet);        
    printf("\n");
    printf("ether type  : 0x%x\n",ether->ether_type);

    printf("----IP Header----\n");
    printf("version     : %d\n",ip->ip_v);
    printf("header len  : %d (%d bytes)\n",ip->ip_hl, ip->ip_hl <<2);
    printf("tos         : %d\n",ip->ip_tos);
    printf("total len   : %d\n",ntohs(ip->ip_len));
    printf("id          : %d\n",ntohs(ip->ip_id));
    printf("frag offset : %d\n",ip->ip_off);
    printf("ttl         : %d\n",ip->ip_ttl);
    printf("protocol    : %d\n",ip->ip_p);
    printf("checksum    : 0x%x\n",ip->ip_sum);
    printf("src address : %s\n",inet_ntoa(ip->ip_src));
    printf("dst address : %s\n",inet_ntoa(ip->ip_dst));

    printf("----TCP Header----\n");
    printf("source port : %d\n",ntohs(tcp->th_sport));
    printf("dest port   : %d\n",ntohs(tcp->th_dport));
    printf("seq         : %u\n",ntohl(tcp->th_seq));
    printf("ack         : %u\n",ntohl(tcp->th_ack));
    printf("data offset : %d (%d bytes)\n",tcp->th_off, tcp->th_off <<2);
    printf("flags       : ");
    if((tcp->th_flags | TH_FIN) == tcp->th_flags)
        printf("FIN ");
    if((tcp->th_flags | TH_SYN) == tcp->th_flags)
        printf("SIN ");
    if((tcp->th_flags | TH_RST) == tcp->th_flags)
        printf("RST ");
    if((tcp->th_flags | TH_PUSH) == tcp->th_flags)
        printf("PUSH ");
    if((tcp->th_flags | TH_ACK) == tcp->th_flags)
        printf("ACK ");
    if((tcp->th_flags | TH_URG) == tcp->th_flags)
        printf("URG ");
    printf("\n");
    printf("window      : %d\n",ntohs(tcp->th_win));
    printf("check sum   : 0x%x\n",tcp->th_sum);
    printf("urt_ptr     : %d\n",tcp->th_urp);

    /*
     *  ヘッダ情報から TCP データサイズを計算
     *  もしヘッダ情報から求めたTCPデータ長が残りの読み込み可能
     *  バイト数より大きかったら、残りのバイト数をデータ長とみなす。
     */
    iptotlen   = ntohs(ip->ip_len);
    tcpdatalen = iptotlen - iphlen - tcphlen;
    if( tcpdatalen > len - etherlen - iphlen - tcphlen)
        tcpdatalen = len - etherlen - iphlen - tcphlen;

    if( tcpdatalen > 0){
        int   i = 0;
        
        tcpdata = (u_char *)tcp + tcphlen;
        printf("------DATA-------\n");
        printf("data length : %d\n", tcpdatalen);
        /*
         * 表示可能データであれば最初の 100 文字だけ表示
         */
        while ( i < tcpdatalen && i < TCP_DATA_PRINT_LENGTH){
            if(isprint(tcpdata[i]))
                printf("%c",tcpdata[i]);
            i++;
        }
    }
    
    printf("\n\n");

  error:
    free(ip);
    return;
}

/*****************************************************************************
 * print_usage()
 * 
 * Usage を表示し、終了する。
 *****************************************************************************/
void
print_usage(char *argv)
{
    printf("Usage: %s ifname \n",argv);
    printf("  Example) %s eri0\n", argv);
    exit(1);
}

/*****************************************************************************
 * dlattachreq()
 *
 * DLPI のルーチン。putmsg(9F) を使って DL_ATTACH_REQ をドライバに送る
 * 
 *****************************************************************************/
int
dlattachreq(int fd, t_uscalar_t ppa ,caddr_t buf)
{
    union DL_primitives	 *primitive;    
    dl_attach_req_t       attachreq;
    struct strbuf         ctlbuf;
    int	                  flags = 0;
    int                   ret;
    
    attachreq.dl_primitive = DL_ATTACH_REQ;
    attachreq.dl_ppa = ppa;

    ctlbuf.maxlen = 0;
    ctlbuf.len    = sizeof(attachreq);
    ctlbuf.buf    = (caddr_t)&attachreq;

    if (putmsg(fd, &ctlbuf, (struct strbuf*) NULL, flags) < 0){
        fprintf(stderr, "dlattachreq: putmsg: %s", strerror(errno));
        return(-1);
    }

    ctlbuf.maxlen = MAXDLBUFSIZE;
    ctlbuf.len = 0;
    ctlbuf.buf = (caddr_t)buf;

    if ((ret = getmsg(fd, &ctlbuf, (struct strbuf *)NULL, &flags)) < 0) {
        fprintf(stderr, "dlattachreq: getmsg: %s\n", strerror(errno));
        return(-1);
    }

    primitive = (union DL_primitives *) ctlbuf.buf;
    if ( primitive->dl_primitive != DL_OK_ACK){
        fprintf(stderr, "dlattachreq: not DL_OK_ACK\n");
        return(-1);
    }
    
    return(0);
}

/*****************************************************************************
 * dlpromisconreq()
 *
 * DLPI のルーチン。 putmsg(9F) を使って DL_PROMISCON_REQ をドライバに送る
 * 
 *****************************************************************************/
int
dlpromisconreq(int fd, t_uscalar_t level, caddr_t buf)
{
    union DL_primitives	 *primitive;        
    dl_promiscon_req_t    promisconreq;
    struct strbuf         ctlbuf;
    int	                  flags = 0;
    int                   ret;

    promisconreq.dl_primitive = DL_PROMISCON_REQ;
    promisconreq.dl_level = level;

    ctlbuf.maxlen = 0;
    ctlbuf.len    = sizeof (promisconreq);
    ctlbuf.buf    = (caddr_t)&promisconreq;

    if (putmsg(fd, &ctlbuf, (struct strbuf*) NULL, flags) < 0){
        fprintf(stderr, "dlpromisconreq: putmsg: %s", strerror(errno));
        return(-1);
    }

    ctlbuf.maxlen = MAXDLBUFSIZE;
    ctlbuf.len = 0;
    ctlbuf.buf = (caddr_t)buf;

    if ((ret = getmsg(fd, &ctlbuf, (struct strbuf *)NULL, &flags)) < 0) {
        fprintf(stderr, "dlpromisconreq: getmsg: %s\n", strerror(errno));
        return(-1);
    }

    primitive = (union DL_primitives *) ctlbuf.buf;
    if ( primitive->dl_primitive != DL_OK_ACK){
        fprintf(stderr, "dlpromisconreq: not DL_OK_ACK\n");
        return(-1);
    }
    
    return(0); 
}

/*****************************************************************************
 * dlbindreq()
 *
 * DLPI のルーチン。 putmsg(9F) を使って DL_BIND_REQ をドライバに送る
 * 
 *****************************************************************************/
int
dlbindreq(
    int fd,
    t_uscalar_t sap,
    t_uscalar_t max_conind,
    uint16_t    service_mode,
    uint16_t    conn_mgmt,
    t_uscalar_t xidtest_flg,
    caddr_t     buf
    )
{
    union DL_primitives	 *primitive;        
    dl_bind_req_t         bindreq;
    struct strbuf	  ctlbuf;
    int	                  flags = 0;
    int                   ret;    

    bindreq.dl_primitive    = DL_BIND_REQ;
    bindreq.dl_sap          = sap;
    bindreq.dl_max_conind   = max_conind;
    bindreq.dl_service_mode = service_mode;
    bindreq.dl_conn_mgmt    = conn_mgmt;
    bindreq.dl_xidtest_flg  = xidtest_flg;

    ctlbuf.maxlen = 0;
    ctlbuf.len    = sizeof(bindreq);
    ctlbuf.buf    = (caddr_t)&bindreq;

    if (putmsg(fd, &ctlbuf, (struct strbuf*) NULL, flags) < 0){
        fprintf(stderr, "dlbindreq: putmsg: %s", strerror(errno));
        return(-1);
    }

    ctlbuf.maxlen = MAXDLBUFSIZE;
    ctlbuf.len    = 0;
    ctlbuf.buf    = (caddr_t)buf;

    if ((ret = getmsg(fd, &ctlbuf, (struct strbuf *)NULL, &flags)) < 0) {
        fprintf(stderr, "dlbindreq: getmsg: %s\n", strerror(errno));
        return(-1);
    }

    primitive = (union DL_primitives *) ctlbuf.buf;
    if ( primitive->dl_primitive != DL_BIND_ACK){
        fprintf(stderr, "dlbindreq: not DL_BIND_ACK\n");
        return(-1);
    }
    
    return(0);
}
