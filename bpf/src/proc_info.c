//go:build ignore

#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define ARGSIZE  128
#define COMMSIZE  16
#define PATHSIZE 80
#define NANOSECOND 1000000000
#define PWDSIZE 20 //单个pwd 最大长度
#define PWDDEEPSIZE 6 //pwd for 循环最大次数为6，再多的话指令过于复杂，会报错

struct event_baseinfo {
    u64 pid; //放在第一位
    u64 ppid;
    u64 start_time;
	u64 uid;
    u64 cpuid;
    u64 arg_size; //进程的参数长度，如果小于ARGSIZE，则argv数组余下数据无效。
    u64 sid; //进程的session id
    u8 pwd[PWDDEEPSIZE][PWDSIZE];//进程当前工作目录,PWDDEEP控制目录深度，PWDSIZE控制每个目录长度。
    u8 comm[COMMSIZE]; //进程的命令，或者进程的名字
    u8 path[PATHSIZE]; // 进程的绝对路径
    u8 argv[ARGSIZE]; //进程的所有参数
};

struct event_fork {
    pid_t pid;
    pid_t cpid; //子进程pid
    u64 arg_size;
    u8 argv[ARGSIZE];
};

struct event_enter{
   u8 path[PATHSIZE];
   u64 now;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, struct event_enter);
} curproc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events_fork SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events_exit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240); // 根据需要调整最大条目数
    __type(key, char[ARGSIZE]);
    __type(value, u32); // 可以用来存储额外信息，这里用u32作为标记
} seen_args SEC(".maps");

// Force emitting struct event into the ELF.
const struct event_baseinfo *unused_info __attribute__((unused));

SEC("kprobe/sys_execve")
int kprobe_execve_path(struct pt_regs *ctx){
    struct event_enter enter;
    int pid = bpf_get_current_pid_tgid();
    bpf_probe_read(enter.path,PATHSIZE,(void *)ctx->di);// 进程二进制文件的路径
    enter.now = bpf_ktime_get_ns(); // 进程启动时间
    bpf_map_update_elem(&curproc, &pid, &enter, 0);
    return 0;
}

SEC("kretprobe/sys_execve")
int kretprobe_execve_info(struct pt_regs *ctx) {

	struct event_baseinfo event;
    struct event_enter enter;
	struct task_struct *task,*ptask;
    struct dentry *dentry;
    unsigned long daddr;
    u32 dlen;
    u32 dummy = 0;

	task = (struct task_struct*)bpf_get_current_task();

	//采集进程信息，并放到event中
    event.pid = bpf_get_current_pid_tgid();
    event.cpuid = bpf_get_smp_processor_id();
	event.uid = bpf_get_current_uid_gid() & 0xffffffff;
	event.ppid= BPF_CORE_READ(task,real_parent,pid);
    //event.start_time = BPF_CORE_READ(task,start_time)/NANOSECOND;
    //event.start_time = bpf_ktime_get_ns()/NANOSECOND;
    event.sid = BPF_CORE_READ(task,group_leader,pids[PIDTYPE_SID].pid,numbers[0].nr); //该字段的采集方式需要关注。
    //event.sid = 0;
    //获取进程执行参数
    daddr = BPF_CORE_READ(task,mm,arg_start);
    event.arg_size = BPF_CORE_READ(task,mm,arg_end)-daddr;
    if (event.arg_size > ARGSIZE){
        event.arg_size = ARGSIZE;
    }
    bpf_probe_read_user(event.argv,ARGSIZE,(void *)daddr);

    // 根据参数对进程进行过滤
    // u32 *val = bpf_map_lookup_elem(&seen_args, &event.argv);
    // if (val) {
    //     // 如果进程全部参数已经存在，跳过记录
    //     return 0;
    // }

    // 如果是新的命令名，添加到seen_cmds哈希表中
    //bpf_map_update_elem(&seen_args, &event.argv, &dummy, 0);

    //获取进程名称（执行命令）
    bpf_get_current_comm(&event.comm,sizeof(event.comm));
    
    //获取进程工作目录
    dentry = BPF_CORE_READ(task,fs,pwd.dentry);
    int i;
	for(i=0;i<PWDDEEPSIZE;i++){ //循环指令过于复杂的话，会被限制循环次数
        daddr = (unsigned long)BPF_CORE_READ(dentry,d_name.name);
        bpf_core_read(&event.pwd[i],PWDSIZE,(void *)daddr);
        dentry = BPF_CORE_READ(dentry,d_parent);
	}

    //获取进程路径
    bpf_probe_read(&enter,sizeof(enter),(void *)bpf_map_lookup_elem(&curproc, &event.pid));
    event.start_time = enter.now;
    bpf_probe_read(&event.path,PATHSIZE,(void*)enter.path);
    bpf_map_delete_elem(&curproc,&event.pid);

	//将event map输出到用户态
	bpf_perf_event_output(ctx, &events_info, 0xffffffffULL, &event, sizeof(event));

	return 0;
}

SEC("kretprobe/_do_fork")
int kretprobe_fork_info(struct pt_regs *ctx) {
    pid_t id = bpf_get_current_pid_tgid();

    pid_t child_pid = (pid_t)((ctx)->ax); //获取返回值
    struct task_struct *task;
    unsigned long daddr;

    struct event_fork evt = {};
    evt.pid = id;
    evt.cpid = child_pid;

    task = (struct task_struct*)bpf_get_current_task();
    daddr = BPF_CORE_READ(task,mm,arg_start);
    evt.arg_size = BPF_CORE_READ(task,mm,arg_end)-daddr;
    if (evt.arg_size > ARGSIZE){
        evt.arg_size = ARGSIZE;
    }
    bpf_probe_read_user(evt.argv,ARGSIZE,(void *)daddr);

    bpf_perf_event_output(ctx, &events_fork, 0xffffffffULL, &evt, sizeof(evt));

	return 0;
}

SEC("kprobe/do_exit")
int kprobe_exit(struct pt_regs *ctx){
    pid_t pid = bpf_get_current_pid_tgid();
    bpf_perf_event_output(ctx, &events_exit, 0xffffffffULL, &pid, sizeof(pid));
    return 0;
}
