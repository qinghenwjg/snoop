//go:build ignore
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>


#define ARGSIZE  128
#define TASK_COMM_LEN 16
#define NANOSECOND 1000000000
#define COMMSIZE  16
#define PWDSIZE 20 //单个pwd 最大长度
#define PWDDEEPSIZE 6 //pwd for 循环最大次数为6，再多的话指令过于复杂，会报错

#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif

// Existing map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 128);
} ipv4_events SEC(".maps");

// Existing map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct sock *);
} currsock SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, u64);
} curtime SEC(".maps");

struct event_baseinfo {
    u64 pid; //放在第一位
    u64 ppid;
    u64 start_time;
	u64 uid;
    u64 cpuid;
    u64 arg_size; //进程的参数长度，如果小于ARGSIZE，则argv数组余下数据无效。
    u64 sid; //进程的session id
    u32 saddr;
    u32 daddr;
    u16 dport;
    u16 sport;
    u8 argv[ARGSIZE]; //进程的所有参数
    u8 pwd[PWDDEEPSIZE][PWDSIZE];//进程当前工作目录,PWDDEEP控制目录深度，PWDSIZE控制每个目录长度。
    u8 comm[COMMSIZE]; //进程的命令，或者进程的名字
};

// Force emitting struct event into the ELF.
const struct event_baseinfo *unused_baseinfo __attribute__((unused));

SEC("kprobe/tcp_v4_connect")
int trace_connect_entry(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    struct sock *sk = (struct sock *)ctx->di;  // 使用 PT_REGS_PARM1 获取 sk
    u64 now = bpf_ktime_get_ns(); // 进程启动时间
    bpf_map_update_elem(&currsock, &tid, &sk, 0);
    bpf_map_update_elem(&curtime, &tid, &now, 0);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int trace_connect_v4_return(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    struct sock **skpp = bpf_map_lookup_elem(&currsock, &tid);
    if (!skpp)
        return 0;

    struct sock *skp = *skpp;
    struct task_struct *task;
    struct dentry *dentry;
    unsigned long daddr;

    //获取网络相关信息
    struct event_baseinfo data4 = {};
    data4.saddr = BPF_CORE_READ(skp, __sk_common.skc_rcv_saddr);
    data4.daddr = BPF_CORE_READ(skp, __sk_common.skc_daddr);
    u16 dport = BPF_CORE_READ(skp, __sk_common.skc_dport);
    data4.sport= BPF_CORE_READ(skp,__sk_common.skc_num);//主机字节序列，不需要转化
    data4.dport = bpf_ntohs(dport); //网络字节序，需要转化
    
    //获取进程相关信息
    task = (struct task_struct*)bpf_get_current_task();
    data4.pid = bpf_get_current_pid_tgid() >> 32;
    data4.ppid= BPF_CORE_READ(task,real_parent,pid);
    data4.uid = bpf_get_current_uid_gid() & 0xffffffff;
	data4.ppid= BPF_CORE_READ(task,real_parent,pid);
    bpf_core_read(&data4.start_time,sizeof(data4.start_time),bpf_map_lookup_elem(&curtime,&tid)); // 获取tcp连接开始时间
    data4.sid = BPF_CORE_READ(task,group_leader,pids[PIDTYPE_SID].pid,numbers[0].nr); //该字段的采集方式需要关注。
    //data4.sid = 0;
    bpf_get_current_comm(&data4.comm,sizeof(data4.comm));

    //获取进程命令行
    daddr = BPF_CORE_READ(task,mm,arg_start);
    data4.arg_size = BPF_CORE_READ(task,mm,arg_end)-daddr;
    if (data4.arg_size > ARGSIZE){
        data4.arg_size = ARGSIZE;
    }
    bpf_probe_read_user(data4.argv,ARGSIZE,(void *)daddr);

    //获取当前工作目录
    dentry = BPF_CORE_READ(task,fs,pwd.dentry);
    int i;
	for(i=0;i<PWDDEEPSIZE;i++){ //循环指令过于复杂的话，会被限制循环次数
        daddr = (unsigned long)BPF_CORE_READ(dentry,d_name.name);
        bpf_core_read(&data4.pwd[i],PWDSIZE,(void *)daddr);
        dentry = BPF_CORE_READ(dentry,d_parent);
	}
    //输出到Map中
    bpf_perf_event_output(ctx, &ipv4_events, 0xffffffffULL, &data4, sizeof(data4));

    bpf_map_delete_elem(&currsock, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
