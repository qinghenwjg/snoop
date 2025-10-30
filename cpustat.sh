#!/bin/bash


# 检查是否提供了进程名作为参数
if [ -z "$1" ]; then
  echo "请提供进程名作为参数。例如：$0 firefox"
  exit 1
fi

# 获取进程名
PROCESS_NAME=$1

# 使用pgrep查找进程ID
PID=$(pgrep "$PROCESS_NAME" | head -n 1)
echo $PID
INTERVAL=600 # 设置采样间隔时间，默认为5秒

# 函数：获取指定进程的CPU时间（用户态+系统态）
get_cpu_time() {
    pid=$1
    stat_file="/proc/$pid/stat"
    
    if [ ! -f $stat_file ]; then
        echo "进程不存在或无权限访问."
        exit 1
    fi
    
    # 读取stat文件，提取utime(14)和stime(15)，注意字段可能因系统不同而有所变化
    cpu_times=$(awk '{print $14 "+" $15}' $stat_file)
    echo $cpu_times | bc
}

# 第一次采样
start_cpu_time=$(get_cpu_time $PID)
start_time=$(date +%s)

echo "开始监控进程$PID的CPU使用情况..."

# 等待一段时间
sleep $INTERVAL

# 第二次采样
end_cpu_time=$(get_cpu_time $PID)
end_time=$(date +%s)

# 计算时钟滴答数差异
cpu_time_diff=$(echo "$end_cpu_time - $start_cpu_time" | bc)

# 计算实际经过的时间（秒）
elapsed_time=$(echo "$end_time - $start_time" | bc)

# 转换CPU时间为秒 (需要获取系统每秒的时钟滴答数)
clk_tck=$(getconf CLK_TCK)
cpu_time_seconds=$(echo "scale=2; $cpu_time_diff / $clk_tck" | bc)

# CPU利用率百分比
cpu_usage_percent=$(echo "scale=2; ($cpu_time_seconds / $elapsed_time) * 100" | bc)

echo "进程$PID在这$INTERVAL秒内的CPU使用率为: $cpu_usage_percent%"
echo "$cpu_time_diff"