# prj-sniffer
Network Packet Sniffer Based on eBPF

## 前期学习

[bpf-developer-tutorial/src/4-opensnoop at main · eunomia-bpf/bpf-developer-tutorial (github.com)](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/4-opensnoop)

### 协议与对应数据

参考[TCP/IP常见协议及协议号端口号 - 碗安 - 博客园 (cnblogs.com)](https://www.cnblogs.com/cqwangye/p/12714676.html)

### Linux数据结构

#### ethhdr

```c
#include <linux/if_ether.h>
struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	__be16		h_proto;		/* packet type ID field	*/
} __attribute__((packed));
```



### eBPF

#### eBPF程序组成

eBPF 程序由内核态部分和用户态部分构成。内核态部分包含程序的实际逻辑，用户态部分负责加载和管理内核态部分。使用 eunomia-bpf 开发工具，只需编写内核态部分的代码。

内核态部分的代码需要符合 eBPF 的语法和指令集。eBPF 程序主要由若干个函数组成，每个函数都有其特定的作用。可以使用的函数类型包括：

- kprobe：插探函数，在指定的内核函数前或后执行。
- tracepoint：跟踪点函数，在指定的内核跟踪点处执行。
- raw_tracepoint：原始跟踪点函数，在指定的内核原始跟踪点处执行。
- xdp：网络数据处理函数，拦截和处理网络数据包。
- perf_event：性能事件函数，用于处理内核性能事件。
- kretprobe：函数返回插探函数，在指定的内核函数返回时执行。
- tracepoint_return：跟踪点函数返回，在指定的内核跟踪点返回时执行。
- raw_tracepoint_return：原始跟踪点函数返回，在指定的内核原始跟踪

#### eBPF程序的基本框架

- 包含头文件：需要包含 <linux/bpf.h> 和 <bpf/bpf_helpers.h> 等头文件。
- 定义许可证：需要定义许可证，通常使用 "Dual BSD/GPL"。
- 定义 BPF 函数：需要定义一个 BPF 函数，例如其名称为 handle_tp，其参数为 void *ctx，返回值为 int。通常用 C 语言编写。
- 使用 BPF 助手函数：可以使用 BPF 助手函数 bpf_get_current_pid_tgid() 和 bpf_printk()。
  - bpf_get_current_pid_tgid()将信息输出到trace_pipe (/sys/kernel/debug/tracing/trace_pipe) 简单机制。一个更好的方式是通过 BPF_PERF_OUTPUT()。
- 返回值`return 0;`

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;
char LICENSE[] SEC("license") = "Dual BSD/GPL";
// 使用 SEC 宏把handle_up附加到 sys_enter_write tracepoint
// 即在进入 write 系统调用时执行
SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx){
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  if (pid_filter && pid != pid_filter)
    return 0;
  bpf_printk("BPF triggered sys_enter_write from PID %d.\n", pid);
  return 0;
}
```

+ 使用hash map需要定义个结构体

  ```c
  struct {
   __uint(type, BPF_MAP_TYPE_HASH);
   __uint(max_entries, MAX_ENTRIES);
   __type(key, __u32);
   __type(value, struct event);
  } values SEC(".maps");
  ```

+ 使用perf buffer：通过 perf event array 向用户态命令行打印输出，通过 perf event array 向用户态发送信息之后，可以进行复杂的数据处理和分析。在 libbpf 对应的内核态代码中，定义这样一个结构体和对应的头文件：

  ```c
  struct {
   __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
   __uint(key_size, sizeof(u32));
   __uint(value_size, sizeof(u32));
  } events SEC(".maps");
  ```

  就可以往用户态直接发送信息。

#### eBPF程序运行

+ 使用 eunomia-bpf 的编译器工具链将其编译为 bpf 字节码文件（比如ecc）

  ```shell
  docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
  ```

+ 使用 ecli 工具加载并运行该程序。

  ```shell
  sudo ./ecli run package.json
  ```

+ 查看eBPF输出

  ```shell
  sudo cat /sys/kernel/debug/tracing/trace_pipe
  ```

+ 命令行传参

  ```shell
  sudo ecli run package.json -- --pid_target 780
  ```

  

## 参考

### 实践参考

+ [bpf-developer-tutorial/src/1-helloworld/README.md at main · eunomia-bpf/bpf-developer-tutorial (github.com)](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/1-helloworld/README.md)
+ [ebpf-slide/networking/Fast-Packet-Processing-using-eBPF-and-XDP.pdf at master · gojue/ebpf-slide (github.com)](https://github.com/gojue/ebpf-slide/blob/master/networking/Fast-Packet-Processing-using-eBPF-and-XDP.pdf)

### demo参考

+ [gcla/termshark: A terminal UI for tshark, inspired by Wireshark (github.com)](https://github.com/gcla/termshark)

### 理论参考

+ [eBPF maps — Prototype Kernel 0.0.1 documentation (prototype-kernel.readthedocs.io)](https://prototype-kernel.readthedocs.io/en/latest/bpf/ebpf_maps.html)

+ [gojue/ebpf-slide: Collection of Linux eBPF slides/documents. (github.com)](https://github.com/gojue/ebpf-slide)

+ [moranzcw/Computer-Networking-A-Top-Down-Approach-NOTES: 《计算机网络－自顶向下方法(原书第6版)》编程作业，Wireshark实验文档的翻译和解答。 (github.com)](https://github.com/moranzcw/Computer-Networking-A-Top-Down-Approach-NOTES)

+ [bpf_study/trace-packet-with-tracepoint-perf-ebpf/index_zh.md at master · DavadDi/bpf_study (github.com)](https://github.com/DavadDi/bpf_study/blob/master/trace-packet-with-tracepoint-perf-ebpf/index_zh.md)

+ [DavadDi/skbtracer: skbtracer on ebpf (github.com)](https://github.com/DavadDi/skbtracer)
+ [mikeroyal/eBPF-Guide: eBPF (extended Berkeley Packet Filter) Guide. Learn all about the eBPF Tools and Libraries for Security, Monitoring , and Networking. (github.com)](https://github.com/mikeroyal/eBPF-Guide#books--tutorials)
+ [OpenCloudOS/nettrace: nettrace is a eBPF-based tool to trace network packet and diagnose network problem. (github.com)](https://github.com/OpenCloudOS/nettrace)
+ [nirmata/kube-netc: A Kubernetes eBPF network monitor (github.com)](https://github.com/nirmata/kube-netc)
+ [yadutaf/tracepkt: Trace a ping packet journey across network interfaces and namespace on recent Linux. Supports IPv4 and IPv6. (github.com)](https://github.com/yadutaf/tracepkt)
+ [lizrice/ebpf-networking: The Beginner's Guide to eBPF Programming for Networking (github.com)](https://github.com/lizrice/ebpf-networking)
+ [Gui774ume/network-security-probe: A process level network security monitoring and enforcement project for Kubernetes, using eBPF (github.com)](https://github.com/Gui774ume/network-security-probe)
