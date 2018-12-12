//
// cloriTCP New Reno拥塞控制算法实现
// New Reno Congestion Control Algorithm Implementation of cloriTCP
// version: 1.0 
// Copyright (C) 2016 James Wei (weijianlhp@163.com). All rights reserved
// 

#include <ctcp_congestion_control.h>

void ctcp_slow_start(ctcp_sock *sk, u32 acked) {   
    /* 在慢启动阶段,有多少个skb被acked了,就将拥塞窗口相应地增大 */
    u32 cwnd = sk->snd_cwnd + acked;

    /* 超过慢启动阈值,就调整至慢启动阈值 */
    if (cwnd > sk->send_ssthresh) {   
        cwnd = sk->send_ssthresh + 1; 
    }
    sk->snd_cwnd = cwnd;
    return;
}

// 
// 拥塞避免阶段的处理流程: 在拥塞避免阶段,每当有当前拥塞窗口
// (current_cwnd)一样多的skb被确认时,拥塞窗口自增1 */
//
void ctcp_cong_avoid_ai(ctcp_sock *sk, u32 wnd_cnt) {
    // 收到确认ack的个数达到current_cwnd了,将拥塞窗口自增1,并将
    // send_cwnd_cnt清零以准备下次计数 
    if (sk->send_cwnd_cnt >= wnd_cnt) {
        ++sk->snd_cwnd;
        sk->send_cwnd_cnt = 0;
    } else {
        // 收到ack的个数没达到cwnd,则累积计数 
        ++sk->send_cwnd_cnt; 
    }
}

// 
// 超时发生时或者进入快速重传时会调用本函数,将慢启动
// 阈值减半,但不能低于2 
//
u32 ctcp_reno_ssthresh(ctcp_sock *sk) {
    return max((sk->snd_cwnd >> 1U), 2U);
}

//
// 慢启动/拥塞避免阶段
//
void ctcp_tcp_reno_cong_avoid(ctcp_sock *sk, u32 ack , u32 acked) {
    //
    // is_cwnd_limited的意思是"发送过程是否因拥塞窗口不够用而打断"
    // ctcp_is_cwnd_limited返回true则拥塞窗口不够用,有增大拥塞窗口的必要
    // ,否则,则是因为待发送数据太少,或者是因发送窗口限制,就没必要
    // 调整拥塞窗口了 
    //
    if (!ctcp_is_cwnd_limited(sk)) {
        return;
    }

    //
    // 拥塞窗口小于慢启动阈值,则启用慢启动
    // 否则,采用拥塞避免算法 
    //
    if (sk->snd_cwnd <= sk->send_ssthresh) {
        ctcp_slow_start(sk, acked);
    } else {   
        ctcp_cong_avoid_ai(sk, sk->snd_cwnd);
    }
}

//
// 下面的name域目前没有用,只是标记它是哪种拥塞控制算
// 法为支持多种拥塞控制算法预留的 
//
struct ctcp_congestion_ops g_ctcp_reno = 
{
    .name = "reno",
    .init = NULL,
    .ssthresh = ctcp_reno_ssthresh,
    .cong_avoid = ctcp_tcp_reno_cong_avoid,
    .set_state = NULL,
    .undo_cwnd = NULL,
    .pkts_acked = NULL,
};
