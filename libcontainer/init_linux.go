// +build linux

package libcontainer

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/system"
	"github.com/opencontainers/runc/libcontainer/user"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/vishvananda/netlink"
)

type initType string

const (
	initSetns    initType = "setns"
	initStandard initType = "standard"
)

type pid struct {
	Pid int `json:"pid"`
}

// network is an internal struct used to setup container networks.
type network struct {
	configs.Network

	// TempVethPeerName is a unique temporary veth peer name that was placed into
	// the container's namespace.
	TempVethPeerName string `json:"temp_veth_peer_name"`
}

// initConfig is used for transferring parameters from Exec() to Init()
type initConfig struct {
	Args             []string         `json:"args"`
	Env              []string         `json:"env"`
	Cwd              string           `json:"cwd"`
	Capabilities     []string         `json:"capabilities"`
	ProcessLabel     string           `json:"process_label"`
	AppArmorProfile  string           `json:"apparmor_profile"`
	NoNewPrivileges  bool             `json:"no_new_privileges"`
	User             string           `json:"user"`
	AdditionalGroups []string         `json:"additional_groups"`
	Config           *configs.Config  `json:"config"`
	Console          string           `json:"console"`
	Networks         []*network       `json:"network"`
	PassedFilesCount int              `json:"passed_files_count"`
	ContainerId      string           `json:"containerid"`
	Rlimits          []configs.Rlimit `json:"rlimits"`
	ExecFifoPath     string           `json:"start_pipe_path"`
}

type initer interface {
	Init() error
}

func newContainerInit(t initType, pipe *os.File, stateDirFD int) (initer, error) {
	var config *initConfig
	// 读取runc create传递过来的容器配置
	if err := json.NewDecoder(pipe).Decode(&config); err != nil {
		return nil, err
	}
	utils.StupigCommonLog(config)
	// {"args":["bash"],"env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","HOSTNAME=c1ccf57dc95c","TERM=xterm","NGINX_VERSION=1.17.5","NJS_VERSION=0.3.6","PKG_RELEASE=1~buster"],"cwd":"/","capabilities":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"process_label":"","apparmor_profile":"","no_new_privileges":false,"user":"0:0","additional_groups":null,"config":{"no_pivot_root":false,"parent_death_signal":0,"pivot_dir":"","rootfs":"/home/docker_rt/overlay2/5e892d82821e32c380cbbb5410602bc2ce5915f653806d0894fea7a0719d051d/merged","readonlyfs":false,"rootPropagation":278528,"mounts":[{"source":"proc","destination":"/proc","device":"proc","flags":14,"propagation_flags":null,"data":"","relabel":"","premount_cmds":null,"postmount_cmds":null},{"source":"tmpfs","destination":"/dev","device":"tmpfs","flags":16777218,"propagation_flags":null,"data":"mode=755","relabel":"","premount_cmds":null,"postmount_cmds":null},{"source":"devpts","destination":"/dev/pts","device":"devpts","flags":10,"propagation_flags":null,"data":"newinstance,ptmxmode=0666,mode=0620,gid=5","relabel":"","premount_cmds":null,"postmount_cmds":null},{"source":"sysfs","destination":"/sys","device":"sysfs","flags":15,"propagation_flags":null,"data":"","relabel":"","premount_cmds":null,"postmount_cmds":null},{"source":"cgroup","destination":"/sys/fs/cgroup","device":"cgroup","flags":15,"propagation_flags":null,"data":"","relabel":"","premount_cmds":null,"postmount_cmds":null},{"source":"mqueue","destination":"/dev/mqueue","device":"mqueue","flags":14,"propagation_flags":null,"data":"","relabel":"","premount_cmds":null,"postmount_cmds":null},{"source":"/home/docker_rt/containers/c1ccf57dc95c380b5a117bcf1badbc1814c38bc89f32075b12480348638b132c/resolv.conf","destination":"/etc/resolv.conf","device":"bind","flags":20480,"propagation_flags":[278528],"data":"","relabel":"","premount_cmds":null,"postmount_cmds":null},{"source":"/home/docker_rt/containers/c1ccf57dc95c380b5a117bcf1badbc1814c38bc89f32075b12480348638b132c/hostname","destination":"/etc/hostname","device":"bind","flags":20480,"propagation_flags":[278528],"data":"","relabel":"","premount_cmds":null,"postmount_cmds":null},{"source":"/home/docker_rt/containers/c1ccf57dc95c380b5a117bcf1badbc1814c38bc89f32075b12480348638b132c/hosts","destination":"/etc/hosts","device":"bind","flags":20480,"propagation_flags":[278528],"data":"","relabel":"","premount_cmds":null,"postmount_cmds":null},{"source":"/home/docker_rt/containers/c1ccf57dc95c380b5a117bcf1badbc1814c38bc89f32075b12480348638b132c/shm","destination":"/dev/shm","device":"bind","flags":20480,"propagation_flags":[278528],"data":"","relabel":"","premount_cmds":null,"postmount_cmds":null}],"devices":[{"type":99,"path":"/dev/null","major":1,"minor":3,"permissions":"","file_mode":438,"uid":0,"gid":0,"allow":false},{"type":99,"path":"/dev/random","major":1,"minor":8,"permissions":"","file_mode":438,"uid":0,"gid":0,"allow":false},{"type":99,"path":"/dev/full","major":1,"minor":7,"permissions":"","file_mode":438,"uid":0,"gid":0,"allow":false},{"type":99,"path":"/dev/tty","major":5,"minor":0,"permissions":"","file_mode":438,"uid":0,"gid":0,"allow":false},{"type":99,"path":"/dev/zero","major":1,"minor":5,"permissions":"","file_mode":438,"uid":0,"gid":0,"allow":false},{"type":99,"path":"/dev/urandom","major":1,"minor":9,"permissions":"","file_mode":438,"uid":0,"gid":0,"allow":false}],"mount_label":"","hostname":"c1ccf57dc95c","namespaces":[{"type":"NEWNS","path":""},{"type":"NEWNET","path":""},{"type":"NEWUTS","path":""},{"type":"NEWPID","path":""},{"type":"NEWIPC","path":""}],"capabilities":null,"networks":[{"type":"loopback","name":"","bridge":"","mac_address":"","address":"","gateway":"","ipv6_address":"","ipv6_gateway":"","mtu":0,"txqueuelen":0,"host_interface_name":"","hairpin_mode":false}],"routes":null,"cgroups":{"path":"/docker/c1ccf57dc95c380b5a117bcf1badbc1814c38bc89f32075b12480348638b132c","scope_prefix":"","Paths":null,"allowed_devices":[{"type":99,"path":"","major":-1,"minor":-1,"permissions":"m","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":98,"path":"","major":-1,"minor":-1,"permissions":"m","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"/dev/null","major":1,"minor":3,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"/dev/random","major":1,"minor":8,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"/dev/full","major":1,"minor":7,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"/dev/tty","major":5,"minor":0,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"/dev/zero","major":1,"minor":5,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"/dev/urandom","major":1,"minor":9,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"/dev/console","major":5,"minor":1,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"","major":136,"minor":-1,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"","major":5,"minor":2,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"","major":10,"minor":200,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true}],"devices":[{"type":97,"path":"","major":-1,"minor":-1,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":false},{"type":99,"path":"","major":1,"minor":5,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"","major":1,"minor":3,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"","major":1,"minor":9,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"","major":1,"minor":8,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"","major":5,"minor":0,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"","major":5,"minor":1,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"","major":10,"minor":229,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":false},{"type":99,"path":"","major":-1,"minor":-1,"permissions":"m","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":98,"path":"","major":-1,"minor":-1,"permissions":"m","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"/dev/null","major":1,"minor":3,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"/dev/random","major":1,"minor":8,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"/dev/full","major":1,"minor":7,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"/dev/tty","major":5,"minor":0,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"/dev/zero","major":1,"minor":5,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"/dev/urandom","major":1,"minor":9,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"/dev/console","major":5,"minor":1,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"","major":136,"minor":-1,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"","major":5,"minor":2,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true},{"type":99,"path":"","major":10,"minor":200,"permissions":"rwm","file_mode":0,"uid":0,"gid":0,"allow":true}],"memory":0,"memory_reservation":0,"memory_swap":0,"kernel_memory":0,"kernel_memory_tcp":0,"cpu_shares":0,"cpu_quota":0,"cpu_period":0,"cpu_rt_quota":0,"cpu_rt_period":0,"cpuset_cpus":"","cpuset_mems":"","pids_limit":0,"blkio_weight":0,"blkio_leaf_weight":0,"blkio_weight_device":null,"blkio_throttle_read_bps_device":null,"blkio_throttle_write_bps_device":null,"blkio_throttle_read_iops_device":null,"blkio_throttle_write_iops_device":null,"freezer":"","hugetlb_limit":null,"oom_kill_disable":false,"memory_swappiness":-1,"net_prio_ifpriomap":null,"net_cls_classid_u":0},"oom_score_adj":0,"uid_mappings":null,"gid_mappings":null,"mask_paths":["/proc/kcore","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/sys/firmware"],"readonly_paths":["/proc/asound","/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"],"sysctl":null,"seccomp":{"default_action":2,"architectures":["amd64","x86","x32"],"syscalls":[{"name":"accept","action":4,"args":[]},{"name":"accept4","action":4,"args":[]},{"name":"access","action":4,"args":[]},{"name":"alarm","action":4,"args":[]},{"name":"alarm","action":4,"args":[]},{"name":"bind","action":4,"args":[]},{"name":"brk","action":4,"args":[]},{"name":"capget","action":4,"args":[]},{"name":"capset","action":4,"args":[]},{"name":"chdir","action":4,"args":[]},{"name":"chmod","action":4,"args":[]},{"name":"chown","action":4,"args":[]},{"name":"chown32","action":4,"args":[]},{"name":"clock_getres","action":4,"args":[]},{"name":"clock_gettime","action":4,"args":[]},{"name":"clock_nanosleep","action":4,"args":[]},{"name":"close","action":4,"args":[]},{"name":"connect","action":4,"args":[]},{"name":"copy_file_range","action":4,"args":[]},{"name":"creat","action":4,"args":[]},{"name":"dup","action":4,"args":[]},{"name":"dup2","action":4,"args":[]},{"name":"dup3","action":4,"args":[]},{"name":"epoll_create","action":4,"args":[]},{"name":"epoll_create1","action":4,"args":[]},{"name":"epoll_ctl","action":4,"args":[]},{"name":"epoll_ctl_old","action":4,"args":[]},{"name":"epoll_pwait","action":4,"args":[]},{"name":"epoll_wait","action":4,"args":[]},{"name":"epoll_wait_old","action":4,"args":[]},{"name":"eventfd","action":4,"args":[]},{"name":"eventfd2","action":4,"args":[]},{"name":"execve","action":4,"args":[]},{"name":"execveat","action":4,"args":[]},{"name":"exit","action":4,"args":[]},{"name":"exit_group","action":4,"args":[]},{"name":"faccessat","action":4,"args":[]},{"name":"fadvise64","action":4,"args":[]},{"name":"fadvise64_64","action":4,"args":[]},{"name":"fallocate","action":4,"args":[]},{"name":"fanotify_mark","action":4,"args":[]},{"name":"fchdir","action":4,"args":[]},{"name":"fchmod","action":4,"args":[]},{"name":"fchmodat","action":4,"args":[]},{"name":"fchown","action":4,"args":[]},{"name":"fchown32","action":4,"args":[]},{"name":"fchownat","action":4,"args":[]},{"name":"fcntl","action":4,"args":[]},{"name":"fcntl64","action":4,"args":[]},{"name":"fdatasync","action":4,"args":[]},{"name":"fgetxattr","action":4,"args":[]},{"name":"flistxattr","action":4,"args":[]},{"name":"flock","action":4,"args":[]},{"name":"fork","action":4,"args":[]},{"name":"fremovexattr","action":4,"args":[]},{"name":"fsetxattr","action":4,"args":[]},{"name":"fstat","action":4,"args":[]},{"name":"fstat64","action":4,"args":[]},{"name":"fstatat64","action":4,"args":[]},{"name":"fstatfs","action":4,"args":[]},{"name":"fstatfs64","action":4,"args":[]},{"name":"fsync","action":4,"args":[]},{"name":"ftruncate","action":4,"args":[]},{"name":"ftruncate64","action":4,"args":[]},{"name":"futex","action":4,"args":[]},{"name":"futimesat","action":4,"args":[]},{"name":"getcpu","action":4,"args":[]},{"name":"getcwd","action":4,"args":[]},{"name":"getdents","action":4,"args":[]},{"name":"getdents64","action":4,"args":[]},{"name":"getegid","action":4,"args":[]},{"name":"getegid32","action":4,"args":[]},{"name":"geteuid","action":4,"args":[]},{"name":"geteuid32","action":4,"args":[]},{"name":"getgid","action":4,"args":[]},{"name":"getgid32","action":4,"args":[]},{"name":"getgroups","action":4,"args":[]},{"name":"getgroups32","action":4,"args":[]},{"name":"getitimer","action":4,"args":[]},{"name":"getpeername","action":4,"args":[]},{"name":"getpgid","action":4,"args":[]},{"name":"getpgrp","action":4,"args":[]},{"name":"getpid","action":4,"args":[]},{"name":"getppid","action":4,"args":[]},{"name":"getpriority","action":4,"args":[]},{"name":"getrandom","action":4,"args":[]},{"name":"getresgid","action":4,"args":[]},{"name":"getresgid32","action":4,"args":[]},{"name":"getresuid","action":4,"args":[]},{"name":"getresuid32","action":4,"args":[]},{"name":"getrlimit","action":4,"args":[]},{"name":"get_robust_list","action":4,"args":[]},{"name":"getrusage","action":4,"args":[]},{"name":"getsid","action":4,"args":[]},{"name":"getsockname","action":4,"args":[]},{"name":"getsockopt","action":4,"args":[]},{"name":"get_thread_area","action":4,"args":[]},{"name":"gettid","action":4,"args":[]},{"name":"gettimeofday","action":4,"args":[]},{"name":"getuid","action":4,"args":[]},{"name":"getuid32","action":4,"args":[]},{"name":"getxattr","action":4,"args":[]},{"name":"inotify_add_watch","action":4,"args":[]},{"name":"inotify_init","action":4,"args":[]},{"name":"inotify_init1","action":4,"args":[]},{"name":"inotify_rm_watch","action":4,"args":[]},{"name":"io_cancel","action":4,"args":[]},{"name":"ioctl","action":4,"args":[]},{"name":"io_destroy","action":4,"args":[]},{"name":"io_getevents","action":4,"args":[]},{"name":"ioprio_get","action":4,"args":[]},{"name":"ioprio_set","action":4,"args":[]},{"name":"io_setup","action":4,"args":[]},{"name":"io_submit","action":4,"args":[]},{"name":"ipc","action":4,"args":[]},{"name":"kill","action":4,"args":[]},{"name":"lchown","action":4,"args":[]},{"name":"lchown32","action":4,"args":[]},{"name":"lgetxattr","action":4,"args":[]},{"name":"link","action":4,"args":[]},{"name":"linkat","action":4,"args":[]},{"name":"listen","action":4,"args":[]},{"name":"listxattr","action":4,"args":[]},{"name":"llistxattr","action":4,"args":[]},{"name":"_llseek","action":4,"args":[]},{"name":"lremovexattr","action":4,"args":[]},{"name":"lseek","action":4,"args":[]},{"name":"lsetxattr","action":4,"args":[]},{"name":"lstat","action":4,"args":[]},{"name":"lstat64","action":4,"args":[]},{"name":"madvise","action":4,"args":[]},{"name":"memfd_create","action":4,"args":[]},{"name":"mincore","action":4,"args":[]},{"name":"mkdir","action":4,"args":[]},{"name":"mkdirat","action":4,"args":[]},{"name":"mknod","action":4,"args":[]},{"name":"mknodat","action":4,"args":[]},{"name":"mlock","action":4,"args":[]},{"name":"mlock2","action":4,"args":[]},{"name":"mlockall","action":4,"args":[]},{"name":"mmap","action":4,"args":[]},{"name":"mmap2","action":4,"args":[]},{"name":"mprotect","action":4,"args":[]},{"name":"mq_getsetattr","action":4,"args":[]},{"name":"mq_notify","action":4,"args":[]},{"name":"mq_open","action":4,"args":[]},{"name":"mq_timedreceive","action":4,"args":[]},{"name":"mq_timedsend","action":4,"args":[]},{"name":"mq_unlink","action":4,"args":[]},{"name":"mremap","action":4,"args":[]},{"name":"msgctl","action":4,"args":[]},{"name":"msgget","action":4,"args":[]},{"name":"msgrcv","action":4,"args":[]},{"name":"msgsnd","action":4,"args":[]},{"name":"msync","action":4,"args":[]},{"name":"munlock","action":4,"args":[]},{"name":"munlockall","action":4,"args":[]},{"name":"munmap","action":4,"args":[]},{"name":"nanosleep","action":4,"args":[]},{"name":"newfstatat","action":4,"args":[]},{"name":"_newselect","action":4,"args":[]},{"name":"open","action":4,"args":[]},{"name":"openat","action":4,"args":[]},{"name":"pause","action":4,"args":[]},{"name":"pipe","action":4,"args":[]},{"name":"pipe2","action":4,"args":[]},{"name":"poll","action":4,"args":[]},{"name":"ppoll","action":4,"args":[]},{"name":"prctl","action":4,"args":[]},{"name":"pread64","action":4,"args":[]},{"name":"preadv","action":4,"args":[]},{"name":"prlimit64","action":4,"args":[]},{"name":"pselect6","action":4,"args":[]},{"name":"pwrite64","action":4,"args":[]},{"name":"pwritev","action":4,"args":[]},{"name":"read","action":4,"args":[]},{"name":"readahead","action":4,"args":[]},{"name":"readlink","action":4,"args":[]},{"name":"readlinkat","action":4,"args":[]},{"name":"readv","action":4,"args":[]},{"name":"recv","action":4,"args":[]},{"name":"recvfrom","action":4,"args":[]},{"name":"recvmmsg","action":4,"args":[]},{"name":"recvmsg","action":4,"args":[]},{"name":"remap_file_pages","action":4,"args":[]},{"name":"removexattr","action":4,"args":[]},{"name":"rename","action":4,"args":[]},{"name":"renameat","action":4,"args":[]},{"name":"renameat2","action":4,"args":[]},{"name":"restart_syscall","action":4,"args":[]},{"name":"rmdir","action":4,"args":[]},{"name":"rt_sigaction","action":4,"args":[]},{"name":"rt_sigpending","action":4,"args":[]},{"name":"rt_sigprocmask","action":4,"args":[]},{"name":"rt_sigqueueinfo","action":4,"args":[]},{"name":"rt_sigreturn","action":4,"args":[]},{"name":"rt_sigsuspend","action":4,"args":[]},{"name":"rt_sigtimedwait","action":4,"args":[]},{"name":"rt_tgsigqueueinfo","action":4,"args":[]},{"name":"sched_getaffinity","action":4,"args":[]},{"name":"sched_getattr","action":4,"args":[]},{"name":"sched_getparam","action":4,"args":[]},{"name":"sched_get_priority_max","action":4,"args":[]},{"name":"sched_get_priority_min","action":4,"args":[]},{"name":"sched_getscheduler","action":4,"args":[]},{"name":"sched_rr_get_interval","action":4,"args":[]},{"name":"sched_setaffinity","action":4,"args":[]},{"name":"sched_setattr","action":4,"args":[]},{"name":"sched_setparam","action":4,"args":[]},{"name":"sched_setscheduler","action":4,"args":[]},{"name":"sched_yield","action":4,"args":[]},{"name":"seccomp","action":4,"args":[]},{"name":"select","action":4,"args":[]},{"name":"semctl","action":4,"args":[]},{"name":"semget","action":4,"args":[]},{"name":"semop","action":4,"args":[]},{"name":"semtimedop","action":4,"args":[]},{"name":"send","action":4,"args":[]},{"name":"sendfile","action":4,"args":[]},{"name":"sendfile64","action":4,"args":[]},{"name":"sendmmsg","action":4,"args":[]},{"name":"sendmsg","action":4,"args":[]},{"name":"sendto","action":4,"args":[]},{"name":"setfsgid","action":4,"args":[]},{"name":"setfsgid32","action":4,"args":[]},{"name":"setfsuid","action":4,"args":[]},{"name":"setfsuid32","action":4,"args":[]},{"name":"setgid","action":4,"args":[]},{"name":"setgid32","action":4,"args":[]},{"name":"setgroups","action":4,"args":[]},{"name":"setgroups32","action":4,"args":[]},{"name":"setitimer","action":4,"args":[]},{"name":"setpgid","action":4,"args":[]},{"name":"setpriority","action":4,"args":[]},{"name":"setregid","action":4,"args":[]},{"name":"setregid32","action":4,"args":[]},{"name":"setresgid","action":4,"args":[]},{"name":"setresgid32","action":4,"args":[]},{"name":"setresuid","action":4,"args":[]},{"name":"setresuid32","action":4,"args":[]},{"name":"setreuid","action":4,"args":[]},{"name":"setreuid32","action":4,"args":[]},{"name":"setrlimit","action":4,"args":[]},{"name":"set_robust_list","action":4,"args":[]},{"name":"setsid","action":4,"args":[]},{"name":"setsockopt","action":4,"args":[]},{"name":"set_thread_area","action":4,"args":[]},{"name":"set_tid_address","action":4,"args":[]},{"name":"setuid","action":4,"args":[]},{"name":"setuid32","action":4,"args":[]},{"name":"setxattr","action":4,"args":[]},{"name":"shmat","action":4,"args":[]},{"name":"shmctl","action":4,"args":[]},{"name":"shmdt","action":4,"args":[]},{"name":"shmget","action":4,"args":[]},{"name":"shutdown","action":4,"args":[]},{"name":"sigaltstack","action":4,"args":[]},{"name":"signalfd","action":4,"args":[]},{"name":"signalfd4","action":4,"args":[]},{"name":"sigreturn","action":4,"args":[]},{"name":"socket","action":4,"args":[]},{"name":"socketcall","action":4,"args":[]},{"name":"socketpair","action":4,"args":[]},{"name":"splice","action":4,"args":[]},{"name":"stat","action":4,"args":[]},{"name":"stat64","action":4,"args":[]},{"name":"statfs","action":4,"args":[]},{"name":"statfs64","action":4,"args":[]},{"name":"symlink","action":4,"args":[]},{"name":"symlinkat","action":4,"args":[]},{"name":"sync","action":4,"args":[]},{"name":"sync_file_range","action":4,"args":[]},{"name":"syncfs","action":4,"args":[]},{"name":"sysinfo","action":4,"args":[]},{"name":"syslog","action":4,"args":[]},{"name":"tee","action":4,"args":[]},{"name":"tgkill","action":4,"args":[]},{"name":"time","action":4,"args":[]},{"name":"timer_create","action":4,"args":[]},{"name":"timer_delete","action":4,"args":[]},{"name":"timerfd_create","action":4,"args":[]},{"name":"timerfd_gettime","action":4,"args":[]},{"name":"timerfd_settime","action":4,"args":[]},{"name":"timer_getoverrun","action":4,"args":[]},{"name":"timer_gettime","action":4,"args":[]},{"name":"timer_settime","action":4,"args":[]},{"name":"times","action":4,"args":[]},{"name":"tkill","action":4,"args":[]},{"name":"truncate","action":4,"args":[]},{"name":"truncate64","action":4,"args":[]},{"name":"ugetrlimit","action":4,"args":[]},{"name":"umask","action":4,"args":[]},{"name":"uname","action":4,"args":[]},{"name":"unlink","action":4,"args":[]},{"name":"unlinkat","action":4,"args":[]},{"name":"utime","action":4,"args":[]},{"name":"utimensat","action":4,"args":[]},{"name":"utimes","action":4,"args":[]},{"name":"vfork","action":4,"args":[]},{"name":"vmsplice","action":4,"args":[]},{"name":"wait4","action":4,"args":[]},{"name":"waitid","action":4,"args":[]},{"name":"waitpid","action":4,"args":[]},{"name":"write","action":4,"args":[]},{"name":"writev","action":4,"args":[]},{"name":"personality","action":4,"args":[{"index":0,"value":0,"value_two":0,"op":1}]},{"name":"personality","action":4,"args":[{"index":0,"value":8,"value_two":0,"op":1}]},{"name":"personality","action":4,"args":[{"index":0,"value":4294967295,"value_two":0,"op":1}]},{"name":"arch_prctl","action":4,"args":[]},{"name":"modify_ldt","action":4,"args":[]},{"name":"clone","action":4,"args":[{"index":0,"value":2080505856,"value_two":0,"op":7}]},{"name":"chroot","action":4,"args":[]}]},"Hooks":{"poststart":null,"poststop":null,"prestart":[{"path":"/usr/bin/dockerd","args":["libnetwork-setkey","c1ccf57dc95c380b5a117bcf1badbc1814c38bc89f32075b12480348638b132c","4ce282c31f92d8730b131be4c50c14389b78eff2b7a720e2cfd3a2bb27600970"],"env":null,"dir":"","timeout":null}]},"version":"1.0.0-rc2-dev","labels":["bundle=/run/docker/libcontainerd/c1ccf57dc95c380b5a117bcf1badbc1814c38bc89f32075b12480348638b132c"],"no_new_keyring":false},"console":"/dev/pts/4","network":[{"type":"loopback","name":"","bridge":"","mac_address":"","address":"","gateway":"","ipv6_address":"","ipv6_gateway":"","mtu":0,"txqueuelen":0,"host_interface_name":"","hairpin_mode":false,"temp_veth_peer_name":""}],"passed_files_count":0,"containerid":"c1ccf57dc95c380b5a117bcf1badbc1814c38bc89f32075b12480348638b132c","rlimits":null,"start_pipe_path":"/run/runc/c1ccf57dc95c380b5a117bcf1badbc1814c38bc89f32075b12480348638b132c/exec.fifo"}
	if err := populateProcessEnvironment(config.Env); err != nil {
		return nil, err
	}
	switch t {
	case initSetns:
		return &linuxSetnsInit{
			config: config,
		}, nil
	case initStandard:
		return &linuxStandardInit{
			pipe:       pipe,
			parentPid:  syscall.Getppid(),
			config:     config,
			stateDirFD: stateDirFD,
		}, nil
	}
	return nil, fmt.Errorf("unknown init type %q", t)
}

// populateProcessEnvironment loads the provided environment variables into the
// current processes's environment.
func populateProcessEnvironment(env []string) error {
	for _, pair := range env {
		p := strings.SplitN(pair, "=", 2)
		if len(p) < 2 {
			return fmt.Errorf("invalid environment '%v'", pair)
		}
		if err := os.Setenv(p[0], p[1]); err != nil {
			return err
		}
	}
	return nil
}

// finalizeNamespace drops the caps, sets the correct user
// and working dir, and closes any leaked file descriptors
// before executing the command inside the namespace
func finalizeNamespace(config *initConfig) error {
	// Ensure that all unwanted fds we may have accidentally
	// inherited are marked close-on-exec so they stay out of the
	// container
	if err := utils.CloseExecFrom(config.PassedFilesCount + 3); err != nil {
		return err
	}

	capabilities := config.Config.Capabilities
	if config.Capabilities != nil {
		capabilities = config.Capabilities
	}
	w, err := newCapWhitelist(capabilities)
	if err != nil {
		return err
	}
	// drop capabilities in bounding set before changing user
	if err := w.dropBoundingSet(); err != nil {
		return err
	}
	// preserve existing capabilities while we change users
	if err := system.SetKeepCaps(); err != nil {
		return err
	}
	if err := setupUser(config); err != nil {
		return err
	}
	if err := system.ClearKeepCaps(); err != nil {
		return err
	}
	// drop all other capabilities
	if err := w.drop(); err != nil {
		return err
	}
	if config.Cwd != "" {
		if err := syscall.Chdir(config.Cwd); err != nil {
			return fmt.Errorf("chdir to cwd (%q) set in config.json failed: %v", config.Cwd, err)
		}
	}
	return nil
}

// syncParentReady sends to the given pipe a JSON payload which indicates that
// the init is ready to Exec the child process. It then waits for the parent to
// indicate that it is cleared to Exec.
func syncParentReady(pipe io.ReadWriter) error {
	// Tell parent.
	if err := utils.WriteJSON(pipe, syncT{procReady}); err != nil {
		return err
	}
	// Wait for parent to give the all-clear.
	var procSync syncT
	if err := json.NewDecoder(pipe).Decode(&procSync); err != nil {
		if err == io.EOF {
			return fmt.Errorf("parent closed synchronisation channel")
		}
		if procSync.Type != procRun {
			return fmt.Errorf("invalid synchronisation flag from parent")
		}
	}
	return nil
}

// syncParentHooks sends to the given pipe a JSON payload which indicates that
// the parent should execute pre-start hooks. It then waits for the parent to
// indicate that it is cleared to resume.
func syncParentHooks(pipe io.ReadWriter) error {
	// Tell parent.
	if err := utils.WriteJSON(pipe, syncT{procHooks}); err != nil {
		return err
	}
	// Wait for parent to give the all-clear.
	var procSync syncT
	if err := json.NewDecoder(pipe).Decode(&procSync); err != nil {
		if err == io.EOF {
			return fmt.Errorf("parent closed synchronisation channel")
		}
		if procSync.Type != procResume {
			return fmt.Errorf("invalid synchronisation flag from parent")
		}
	}
	return nil
}

// setupUser changes the groups, gid, and uid for the user inside the container
func setupUser(config *initConfig) error {
	// Set up defaults.
	defaultExecUser := user.ExecUser{
		Uid:  syscall.Getuid(),
		Gid:  syscall.Getgid(),
		Home: "/",
	}
	passwdPath, err := user.GetPasswdPath()
	if err != nil {
		return err
	}
	groupPath, err := user.GetGroupPath()
	if err != nil {
		return err
	}
	execUser, err := user.GetExecUserPath(config.User, &defaultExecUser, passwdPath, groupPath)
	if err != nil {
		return err
	}

	var addGroups []int
	if len(config.AdditionalGroups) > 0 {
		addGroups, err = user.GetAdditionalGroupsPath(config.AdditionalGroups, groupPath)
		if err != nil {
			return err
		}
	}
	// before we change to the container's user make sure that the processes STDIO
	// is correctly owned by the user that we are switching to.
	if err := fixStdioPermissions(execUser); err != nil {
		return err
	}
	suppGroups := append(execUser.Sgids, addGroups...)
	if err := syscall.Setgroups(suppGroups); err != nil {
		return err
	}

	if err := system.Setgid(execUser.Gid); err != nil {
		return err
	}
	if err := system.Setuid(execUser.Uid); err != nil {
		return err
	}
	// if we didn't get HOME already, set it based on the user's HOME
	if envHome := os.Getenv("HOME"); envHome == "" {
		if err := os.Setenv("HOME", execUser.Home); err != nil {
			return err
		}
	}
	return nil
}

// fixStdioPermissions fixes the permissions of PID 1's STDIO within the container to the specified user.
// The ownership needs to match because it is created outside of the container and needs to be
// localized.
func fixStdioPermissions(u *user.ExecUser) error {
	var null syscall.Stat_t
	if err := syscall.Stat("/dev/null", &null); err != nil {
		return err
	}
	for _, fd := range []uintptr{
		os.Stdin.Fd(),
		os.Stderr.Fd(),
		os.Stdout.Fd(),
	} {
		var s syscall.Stat_t
		if err := syscall.Fstat(int(fd), &s); err != nil {
			return err
		}
		// skip chown of /dev/null if it was used as one of the STDIO fds.
		if s.Rdev == null.Rdev {
			continue
		}
		if err := syscall.Fchown(int(fd), u.Uid, u.Gid); err != nil {
			return err
		}
	}
	return nil
}

// setupNetwork sets up and initializes any network interface inside the container.
func setupNetwork(config *initConfig) error {
	for _, config := range config.Networks {
		strategy, err := getStrategy(config.Type)
		if err != nil {
			return err
		}
		if err := strategy.initialize(config); err != nil {
			return err
		}
	}
	return nil
}

func setupRoute(config *configs.Config) error {
	for _, config := range config.Routes {
		_, dst, err := net.ParseCIDR(config.Destination)
		if err != nil {
			return err
		}
		src := net.ParseIP(config.Source)
		if src == nil {
			return fmt.Errorf("Invalid source for route: %s", config.Source)
		}
		gw := net.ParseIP(config.Gateway)
		if gw == nil {
			return fmt.Errorf("Invalid gateway for route: %s", config.Gateway)
		}
		l, err := netlink.LinkByName(config.InterfaceName)
		if err != nil {
			return err
		}
		route := &netlink.Route{
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       dst,
			Src:       src,
			Gw:        gw,
			LinkIndex: l.Attrs().Index,
		}
		if err := netlink.RouteAdd(route); err != nil {
			return err
		}
	}
	return nil
}

func setupRlimits(limits []configs.Rlimit, pid int) error {
	for _, rlimit := range limits {
		if err := system.Prlimit(pid, rlimit.Type, syscall.Rlimit{Max: rlimit.Hard, Cur: rlimit.Soft}); err != nil {
			return fmt.Errorf("error setting rlimit type %v: %v", rlimit.Type, err)
		}
	}
	return nil
}

func setOomScoreAdj(oomScoreAdj int, pid int) error {
	path := fmt.Sprintf("/proc/%d/oom_score_adj", pid)

	return ioutil.WriteFile(path, []byte(strconv.Itoa(oomScoreAdj)), 0600)
}

// killCgroupProcesses freezes then iterates over all the processes inside the
// manager's cgroups sending a SIGKILL to each process then waiting for them to
// exit.
func killCgroupProcesses(m cgroups.Manager) error {
	var procs []*os.Process
	if err := m.Freeze(configs.Frozen); err != nil {
		logrus.Warn(err)
	}
	pids, err := m.GetAllPids()
	if err != nil {
		m.Freeze(configs.Thawed)
		return err
	}
	for _, pid := range pids {
		p, err := os.FindProcess(pid)
		if err != nil {
			logrus.Warn(err)
			continue
		}
		procs = append(procs, p)
		if err := p.Kill(); err != nil {
			logrus.Warn(err)
		}
	}
	if err := m.Freeze(configs.Thawed); err != nil {
		logrus.Warn(err)
	}
	for _, p := range procs {
		if _, err := p.Wait(); err != nil {
			logrus.Warn(err)
		}
	}
	return nil
}
