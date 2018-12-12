//
// cloriTCP Cubic拥塞控制算法实现
// Cubic Congestion Control Algorithm Implementation of cloriTCP
// version: 1.0 
// Copyright (C) 2016 James Wei (weijianlhp@163.com). All rights reserved
// 

#include <ctcp_congestion_control.h>

#define CTCP_BICTCP_BETA_SCALE          1024 // 主要用于重新计算慢启动阈值 

#define CTCP_BICTCP_HZ                  10   // 用于时间单位转换,Cubic函数的时间分辨率为1 << CTCP_BICTCP_HZ秒
#define CTCP_ACK_RATIO_SHIFT            4    // ACK确认率(就是ack ratio = packets / acks)左移位数,避开浮点运算 

// ACK延迟回复系数上限,参考linux 内核取为32 
#define CTCP_ACK_RATIO_LIMIT            (32U << CTCP_ACK_RATIO_SHIFT) 
#define CTCP_FAST_CONVERGENCE          1 // 是否启用快速收敛模式 
#define CTCP_TCP_FRIEND_ON             1 // 是否保持与标准TCP保持一致 

//
// Cubic TCP拥塞控制算法同时集成了一个Hybrid Slow Start算法,
// 用以从慢启动过渡到拥塞避免阶段.听其作者说还挺好用的,于是
// 我们也加上去... (如果觉得不好用,就把CTCP_HYSTART_ON宏置0即可),以下是
// Hystart 算法的宏定义
//
// 两种Hybrid slow start 的判别方法, hybrid slow start 是指当满足一定条件时,退出慢启动阶段
//
#define CTCP_HYSTART_ON                1   // 是否启用hystart (hybrid slow start)算法 

// ACK train 方法: 当一系列的,对连续发出
// 的数据的确认ACK占用时间超过一定
// 范围时,ACK train标志置上,转拥塞避免 
#define CTCP_HYSTART_ACK_TRAIN         0x1 
#define CTCP_HYSTART_DELAY             0x2 // 延迟ACK方法

#define CTCP_HYSTART_MIN_SAMPLES       8  // Number of delay samples for detecting the increase of delay 
#define CTCP_HYSTART_DELAY_MIN         (4U << 3)
#define CTCP_HYSTART_DELAY_MAX         (16U << 3)
#define CTCP_HYSTART_DELAY_THRESH(x)   clamp(x, CTCP_HYSTART_DELAY_MIN, CTCP_HYSTART_DELAY_MAX)
#define CTCP_HYSTART_LOW_WINDOW        16  // 只有拥塞窗口大于这个时才有必要调用hystart 探测
#define CTCP_HYSTART_ACK_DELTA         2   // 连续ACK 之间的时间间隙小于这个值才算是属于一个ack train,单位为ms
#define CTCP_CONGAVOID_INCREMENT       100 

//
// 部分全局常量
//
static int beta __read_mostly = 717; // 与CTCP_BICTCP_BETA_SCALE配套使用,作为比例因子

// ((CTCP_BICTCP_BETA_SCALE + beta) << 3) / (3 * (CTCP_BICTCP_BETA_SCALE - beta)) 
static u32 beta_scale __read_mostly = 15; 

//
// cube_rtt_scale = 41 * 10,Linux 内核的实现是cube_rtt_scale = bic_scale * 10,以做成动态可调的 . 这里将之简化了
//
static u32 cube_rtt_scale __read_mostly = 410;
//
// 2^40 / 410, 计算Cubic 函数的参数K 会用到
// do_div(1ULL << (10 + 3 * CTCP_BICTCP_HZ), cube_rtt_scale); 
//
static u64 cube_factor __read_mostly = 2681735677ULL;

typedef struct bictcp {
    u32 cnt;        // 1, increase cwnd by 1 when cnt packets are acked , in congestion avoid phase
    u32 last_max_cwnd;  // 2,  last maximum snd_cwnd 
    u32 loss_cwnd;  // 3, congestion window at last loss 
    u32 last_cwnd;  // 4, the last snd_cwnd 
    u32 last_time;  // 5, time when updated last_cwnd 
    u32 bic_origin_point;// 6,  origin point of bic function ,原点,就是Wmax 
    u32 bic_K;      // 7, time to origin point from the beginning of the current epoch, Cubic 函数中的K 
    u32 delay_min;  // 8, min delay (msec << 3), 最小延迟左移三位 
    u32 epoch_start;    // 9,  beginning of an epoch 
    u32 ack_cnt;    // 10, number of acks 
    u32 tcp_cwnd;   // 11, estimated tcp cwnd , 标准TCP算法(比如New Reno)此时的拥塞窗口大小
    u16 delayed_ack;    // 12,  estimate the ratio of Packets/ACKs << 4 , 延迟确认ACK 估计 
    //
    // 以下是为了实现Hystart算法而添加的                                         
    //
    u8  sample_cnt; // number of samples to decide curr_rtt 
    u8  found;      // the exit point is found? 
    u32 round_start;//13, beginning of each round 
    u32 end_seq;    // 14, end_seq of the round 
    u32 last_ack;   // 15, last time when the ACK spacing is close 
    u32 curr_rtt;   // 16, the minimum rtt of current round 
} ctcp_bictcp;

static inline void ctcp_bictcp_reset(ctcp_bictcp* ca) {
    ca->cnt = 0;
    ca->last_max_cwnd = 0;
    ca->last_cwnd = 0;
    ca->last_time = 0;
    ca->bic_origin_point = 0;
    ca->bic_K = 0;
    ca->delay_min = 0;
    ca->epoch_start = 0;
    ca->delayed_ack = 2 << CTCP_ACK_RATIO_SHIFT; // 初始化为2 <<...,即认为对端每收到2个packets 就回复一个ack 
    ca->ack_cnt = 0;
    ca->tcp_cwnd = 0;
    ca->found = 0;
}

//
// 返回当前时间,以毫秒计 
//
static inline u32 ctcp_bictcp_clock(void) {
    return jiffies_to_msecs(jiffies);
}

static inline void ctcp_bictcp_hystart_reset(ctcp_sock *sk) {
    ctcp_bictcp* ca = ctcp_get_ca_priv(sk);
    struct ctcp_connection *lpc = ctcp_sock(sk);
    
    ca->round_start = ca->last_ack = ctcp_bictcp_clock();
    ca->end_seq = lpc->snd_seq;
    ca->curr_rtt = 0;
    ca->sample_cnt = 0;
}

static void ctcp_bictcp_init(ctcp_sock *sk) {
    struct bictcp *ca = ctcp_get_ca_priv(sk);
    ctcp_bictcp_reset(ca);
    ca->loss_cwnd = 0;
    if (CTCP_HYSTART_ON) {
        ctcp_bictcp_hystart_reset(sk);
    }
}

//
// 这是个开立方函数,是直接从linux 内核搬过
// 来的(对应linux内核的cubic_root函数). 原文注释"
// calculate the cubic root of x using a table lookup followed by one
// Newton-Raphson iteration. Avg err ~= 0.195%"
//
static u32 ctcp_cubic_root(u64 a) {
    u32 x, b, shift;
    // (这个是原文注释...,提示: MSB是指最高有效位 
    // cbrt(x) MSB values for x MSB values in [0..63].
    // Precomputed then refined by hand - Willy Tarreau
    // For x in [0..63],
    //   v = cbrt(x << 18) - 1
    //   cbrt(x) = (v[x] + 10) >> 6
    // 
    static const u8 v[] = {
        /* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
        /* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
        /* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
        /* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
        /* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
        /* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
        /* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
        /* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
    };
    // 先获取a的最高有效位
    b = fls64(a); 
    if (b < 7) {
        // a in [0..63] 
        return ((u32)v[(u32)a] + 35) >> 6; // 若0<=a <=63,调用本方法
    }

    b = ((b * 84) >> 8) - 1;
    shift = (a >> (b * 3));

    x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;

   //  
   //  Newton-Raphson iteration
   //                          2
   //  x    = ( 2 * x  +  a / x  ) / 3
   //   k+1          k         k
   // 
   // 牛顿-拉弗森求立方根公式: 如果b是a 的立方根近似值,则
   // x = (2 x b + a / b^2) / 3 将更加靠近a 的立方根 
   // Newton-Raphson 迭代法具有二次收敛性质,经过一次迭代,精度就
   // 满足Cubic TCP拥塞控制算法的需要了
   // 
    x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));  // x != 1,不会有除数为0的情况
    x = ((x * 341) >> 10);
    return x;
}

// 
// 完整公式: W(t) = C (t - K)^3 + Wmax, 取C = c / rtt
// 则 W(t) = c (t - K)^3 /rtt + Wmax, 令t = 0, 则c K^3  = (Wmax - W(0)) x rtt
// , K  = ((Wmax - W(0)) x rtt /c)^(1/3), 做单位转换,当K以1/1024 s 为单位后,则
// K x 2^(-10) = ..., 移位为K^3 = (2^30 x rtt /c) x (Wmax - W(0)) . 
// (此公式中以秒为时间单位)
//
//     下面,令cube_factor = 2^30 x rtt /c, 
//     则 
//         K^3 = cube_factor x (Wmax - W(0))
// Attention: 由于c = bic_scale >> 10, 即c = 2^10 x bic_scale, 又rtt = 100 ms  = 1/10 s
// 故cube_factor = 2^30 x rtt /c  = 2^30 x (1/10)  / (bic_scale >> 10)
//                          = 2^40 /(bic_scale x 10)
//  
static inline void ctcp_bictcp_update(struct bictcp *ca, u32 cwnd) {
    u32 delta, bic_target, max_cnt;
    u64 offs, t;
    // 
    // count the number of ACKs
    //
    ca->ack_cnt++;  
    // 拥塞窗口不变并且时间间隔很短,就不用往下走了
    if (ca->last_cwnd == cwnd && ((s32)(tcp_time_stamp - ca->last_time) <= HZ / 32)) {
        return;
    }

    ca->last_cwnd = cwnd;
    ca->last_time = tcp_time_stamp;
    //
    // 这种情况说明刚从fast_recovery中回到congestion avoid 状态,这是回到
    // congestion avoid 状态后收到的第一个非dubious ack(即,ack正常确认数据) 
    //
    if (0 == ca->epoch_start)  {
        ca->epoch_start = tcp_time_stamp;   
        ca->ack_cnt = 1;
        ca->tcp_cwnd = cwnd;

        // 发生undo时会出现此情况,马上进入凸函数增长区
        if (ca->last_max_cwnd <= cwnd) { 
            ca->bic_K = 0;
            ca->bic_origin_point = cwnd; 
        } else {
            // Compute new K based on (原文注释)
            // (Wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
            // 
            // W(t) = C x (t - K)^3 + Wmax, 当t = 0时, CK^3 = Wmax - W(0),W(0)即cwnd
            //            解释一下为什么Cubic具有很好的RTT公平性: 对于不同RTT
            //            的TCP连接来说,Cubic TCP的K值
            //                              K =  f (last_max_cwnd), 即Cubic 函数的参数只与发生拥塞之
            //            前的拥塞窗口相关.
            // 
            ca->bic_K = ctcp_cubic_root(cube_factor * (ca->last_max_cwnd - cwnd));
            //
            // 1/C  = cube_factor = 2^40/410 
            // bic_origin_point即Wmax 
            //
            ca->bic_origin_point = ca->last_max_cwnd; 
        }
    }

    //
    // (原文注释)       
    //    cubic function - calc
    // calculate c * time^3 / rtt,
    //  while considering overflow in calculation of time^3
    // (so time^3 is done by using 64 bit)
    // and without the support of division of 64bit numbers
    // (so all divisions are done by using 32 bit)
    //  also NOTE the unit of those veriables
    //    time  = (t - K) / 2^bictcp_HZ
    //    c = bic_scale >> 10
    // rtt  = (srtt >> 3) / HZ
    // !!! The following code does not have overflow problems,
    // if the cwnd < 1 million packets !!! (目前的测试环境中,还没见过cwnd > 80的...)
    // 
    // 下面的工作是预测下一个rtt的拥塞窗口值 
    // t = (s32)(tcp_time_stamp - ca->epoch_start);
    // t += msecs_to_jiffies(ca->delay_min >> 3); /* 注意这句话...预测下一
    // 个rtt后的cwnd... 
    //
    // change the unit from HZ to bictcp_HZ 
    t <<= CTCP_BICTCP_HZ; 
    do_div(t, HZ);
    //
    // offs = |t - K | 
    //
    if (t < ca->bic_K)  {
        offs = ca->bic_K - t;
    } else {
        offs = t - ca->bic_K;
    }

    // 
    // c/rtt * (t-K)^3 
    //  cube_rtt_scale = 2^10 * c /rtt, 故 c/rtt = cube_rtt_scale / (2^10) 
    //  W(t) = c (t - K)^3 /rtt + Wmax  
    //               = cube_rtt_scale x (t - K)^3 /(2^10) + Wmax,将单位转换为秒,则
    //               = cube_rtt_scale x offs^3 /(2^40) + Wmax
    //               = cube_rtt_scale x offs x offs x offs >> 40 + Wmax
    //               
    //               令delta   = cube_rtt_scale x offs x offs x offs >> 40,
    //                     Wmax = bic_origin_point
    //                     W(t)   = bic_target
    //              则...                                                       
    // 
    delta = (cube_rtt_scale * offs * offs * offs) >> (10 + 3 * CTCP_BICTCP_HZ);
    //
    // W(t) = C(t - K)^3 + Wmax = delta + Wmax, delta都是正数,you knew... 
    // bic_target 就是W(t) 
    //
    if (t < ca->bic_K) {
        bic_target = ca->bic_origin_point - delta;
    } else {
        bic_target = ca->bic_origin_point + delta;
    }
    //
    // bic_target表示我们预期的下一个rtt后的cwnd值,如果cwnd比预期的小
    //      ,就减小cnt以快速达到预期值;否则, 就减缓增长速率了... 
    //      注意Cubic TCP算法的本质!它只是给出一个参考线,并不强求
    //      拥塞窗口的变化完全遵守Cubic 函数 
    //      
    // 增长率为(bic_target - cwnd)/cwnd,意思是说: 平均每个skb被ACKed
    //      以后,拥塞窗口应该涨多少(注意,不是每收到多少个
    //      ACK 拥塞窗口涨多少,因为下面还要除以delayed_ack) 
    // 如果预测的窗口比当前拥塞窗口大,就把拥塞窗口增长率调大
    //      一些,并且bic_target - cwnd 的差值越大,cnt越小,增长率越快
    //
    if (bic_target > cwnd) {
        ca->cnt = cwnd / (bic_target - cwnd); 
    } else {
        // 比预测的值大了,就涨得很慢
        ca->cnt = CTCP_CONGAVOID_INCREMENT * cwnd; // very small increment
    }
    
    //
    // The initial growth of cubic function may be too conservative
    // when the available bandwidth is still unknown.
    // 说明Hystart slow start 算法预测有误,在这里调一下 
    //
    if (unlikely((ca->last_max_cwnd == 0) && (ca->cnt > 20))) {
        // 没丢包过,并且cwnd增
        // 长幅度小于5% ,以保证提前退出慢启动时,拥塞窗口的
        // 增长幅度不会太低 
        ca->cnt = 20; 
    }
    //
    // TCP Friendly 
    // 目前对这一处理过程的合理性存疑.. 
    //
    if (CTCP_TCP_FRIEND_ON) {
        delta = (cwnd * beta_scale) >> 3; // 1.89 x cwnd,用于估算reno算法的当前拥塞窗口 
        while (ca->ack_cnt > delta) {       
            ca->ack_cnt -= delta;
            ca->tcp_cwnd++;
        }

        // if bic is slower than tcp 
        if (ca->tcp_cwnd > cwnd) {   
            delta = ca->tcp_cwnd - cwnd;
            max_cnt = cwnd / delta;
            if (ca->cnt > max_cnt) {
                ca->cnt = max_cnt;
            }
        }
    }
    // 左移ACK_RATIO_SHIFT位: 因为除数delayed_ack是左移ACK_RATIO_SHIFT存放的
    ca->cnt = (ca->cnt << CTCP_ACK_RATIO_SHIFT) / ca->delayed_ack;
    if (unlikely(0 == ca->cnt)) {
        ca->cnt = 1;
    }
}

//
// Cubic TCP拥塞控制算法慢启动/拥塞避免阶段处理
//
static void ctcp_bictcp_cong_avoid(ctcp_sock *sk, u32 ack, u32 acked) {
    struct bictcp *ca = ctcp_get_ca_priv(sk);

    if (!ctcp_is_cwnd_limited(sk)) {
        return; 
    }
    if (sk->snd_cwnd <= sk->send_ssthresh) {
        if (CTCP_HYSTART_ON && after(ack, ca->end_seq)) {
            ctcp_bictcp_hystart_reset(sk);
        }
        ctcp_slow_start(sk, acked);
    } else {
        ctcp_bictcp_update(ca, sk->snd_cwnd);
        ctcp_cong_avoid_ai(sk, ca->cnt);
    }
}

//
// Cubic 算法重新计算慢启动阈值
//
static u32 ctcp_bictcp_recalc_ssthresh(ctcp_sock *sk) {
    struct bictcp *ca = ctcp_get_ca_priv(sk);
    ca->epoch_start = 0; // End of epoch 
    if ((sk->snd_cwnd < ca->last_max_cwnd) && CTCP_FAST_CONVERGENCE) {
        // 快速收敛时,last_max_cwnd调小一点 
        ca->last_max_cwnd = (sk->snd_cwnd * (CTCP_BICTCP_BETA_SCALE + beta)) / (CTCP_BICTCP_BETA_SCALE << 1);
    } else {
        ca->last_max_cwnd = sk->snd_cwnd;
    }
    ca->loss_cwnd = sk->snd_cwnd;

    return max((sk->snd_cwnd * beta) / CTCP_BICTCP_BETA_SCALE, 2U);
}

//
// 错误地进入recovery状态时,撤销之 
//
static u32 ctcp_bictcp_undo_cwnd(ctcp_sock *sk) {
    struct bictcp *ca = ctcp_get_ca_priv(sk);
    return max(sk->snd_cwnd, ca->loss_cwnd);
}

//
// 进入loss状态时,控制信息撤销 
static void ctcp_bictcp_state(ctcp_sock *sk, u8 new_state) {
    if (CTCP_CA_LOSS == new_state) {
        ctcp_bictcp_reset(ctcp_get_ca_priv(sk));
        ctcp_bictcp_hystart_reset(sk);
    }
}

//
// 更新hystart算法相关统计变量,条件满足则转
// 入拥塞避免阶段
//
static void ctcp_hystart_update(ctcp_sock *sk, u32 delay) {
    struct bictcp *ca = ctcp_get_ca_priv(sk);
    u32 now = ctcp_bictcp_clock();
    
    if (unlikely(ca->found & (CTCP_HYSTART_ACK_TRAIN | CTCP_HYSTART_DELAY))) {
        return;
    }
    //
    // 只有连续两个ack之间的时间差小于CTCP_HYSTART_ACK_DELTA, 才
    // 认为是属于一个"ACK TRAIN" 
    //
    if ((s32)(now - ca->last_ack) <= CTCP_HYSTART_ACK_DELTA) {
        ca->last_ack = now;
        // ack train的长度大于最小rtt的一半,则认为cwnd接近饱和了 
        if ((s32)(now - ca->round_start) > (ca->delay_min >> 4)) {
            ca->found |= CTCP_HYSTART_ACK_TRAIN;
        }
    }

    if (ca->sample_cnt < CTCP_HYSTART_MIN_SAMPLES) {
        if (0 == ca->curr_rtt || ca->curr_rtt > delay) {
            ca->curr_rtt = delay;
        }
        ca->sample_cnt++;
    } else {
        if (ca->curr_rtt > (ca->delay_min + CTCP_HYSTART_DELAY_THRESH(ca->delay_min >> 4))) {
            ca->found |= CTCP_HYSTART_DELAY;
        }
    }

    if (ca->found & (CTCP_HYSTART_ACK_TRAIN | CTCP_HYSTART_DELAY)) {
        sk->send_ssthresh = sk->snd_cwnd;
    }
}

//
// 收到确认数据的ack报文时,进入本流程,更新
// 延迟确认及最小RTT,开启Hystart时,还要更新
// hystart相关数据
// 
static void ctcp_bictcp_acked(ctcp_sock *sk, u32 cnt, s32 rtt_us) {
    u32 delay = 0;
    struct bictcp *ca = ctcp_get_ca_priv(sk);
    
    if (CTCP_CA_OPEN == sk->ca_state) {
        u32 ratio = ca->delayed_ack;
        // delayed_ack = 15/16 x delayed_ack + 1/16 x new_count 
        ratio -= ca->delayed_ack >> CTCP_ACK_RATIO_SHIFT;
        ratio += cnt;
        ca->delayed_ack = clamp(ratio, 1U, CTCP_ACK_RATIO_LIMIT);
    }
    // 有重传的报文被acked时,rtt_us会小于0 
    if (rtt_us < 0) {
        return;
    }
    // Discard delay samples right after fast recovery 
    if (ca->epoch_start && ((s32)(tcp_time_stamp - ca->epoch_start) < HZ)) {
        return;        
    }
    delay = (rtt_us << 3) / USEC_PER_MSEC;
    if (0 == delay) {
        delay = 1;
    }
    // 重置最小延迟 
    if (0 == ca->delay_min || (ca->delay_min > delay)) {
        ca->delay_min = delay;  
    }

    if (CTCP_HYSTART_ON && sk->snd_cwnd <= sk->send_ssthresh && 
        sk->snd_cwnd >= CTCP_HYSTART_LOW_WINDOW) {
        ctcp_hystart_update(sk, delay);
    }
}

struct ctcp_congestion_ops g_ctcp_cubic = {
    .name = "cubic",
    .init = ctcp_bictcp_init,
    .ssthresh = ctcp_bictcp_recalc_ssthresh,
    .cong_avoid =  ctcp_bictcp_cong_avoid,
    .set_state = ctcp_bictcp_state,
    .undo_cwnd = ctcp_bictcp_undo_cwnd,
    .pkts_acked = ctcp_bictcp_acked,
};

