package main

import (
	"os"

	"github.com/urfave/cli"
)

var createCommand = cli.Command{
	Name:  "create",
	Usage: "create a container",
	ArgsUsage: `<container-id>

Where "<container-id>" is your name for the instance of the container that you
are starting. The name you provide for the container instance must be unique on
your host.`,
	Description: `The create command creates an instance of a container for a bundle. The bundle
is a directory with a specification file named "` + specConfig + `" and a root
filesystem.

The specification file includes an args parameter. The args parameter is used
to specify command(s) that get run when the container is started. To change the
command(s) that get executed on start, edit the args parameter of the spec. See
"runc spec --help" for more explanation.`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "bundle, b",
			Value: "",
			Usage: `path to the root of the bundle directory, defaults to the current directory`,
		},
		cli.StringFlag{
			Name:  "console",
			Value: "",
			Usage: "specify the pty slave path for use with the container",
		},
		cli.StringFlag{
			Name:  "pid-file",
			Value: "",
			Usage: "specify the file to write the process id to",
		},
		cli.BoolFlag{
			Name:  "no-pivot",
			Usage: "do not use pivot root to jail process inside rootfs.  This should be used whenever the rootfs is on top of a ramdisk",
		},
		cli.BoolFlag{
			Name:  "no-new-keyring",
			Usage: "do not create a new session keyring for the container.  This will cause the container to inherit the calling processes session key",
		},
	},
	Action: func(context *cli.Context) error {
		spec, err := setupSpec(context)
		stupigLog(context, "stupig-runc: %#v\n", spec)
		// stupig-runc: &specs.Spec{Version:"1.0.0-rc2-dev", Platform:specs.Platform{OS:"linux", Arch:"amd64"}, Process:specs.Process{Terminal:true, ConsoleSize:specs.Box{Height:0x0, Width:0x0}, User:specs.User{UID:0x0, GID:0x0, AdditionalGids:[]uint32(nil), Username:""}, Args:[]string{"bash"}, Env:[]string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOSTNAME=7a2c5bdc8ad2", "TERM=xterm", "NGINX_VERSION=1.17.5", "NJS_VERSION=0.3.6", "PKG_RELEASE=1~buster"}, Cwd:"/", Capabilities:[]string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_MKNOD", "CAP_NET_RAW", "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE"}, Rlimits:[]specs.Rlimit(nil), NoNewPrivileges:false, ApparmorProfile:"", SelinuxLabel:""}, Root:specs.Root{Path:"/home/docker_rt/overlay2/6eae03da6a6bfee053c7b88ee21a3b7448305943e1e7afa64e0a83090f1ca841/merged", Readonly:false}, Hostname:"7a2c5bdc8ad2", Mounts:[]specs.Mount{specs.Mount{Destination:"/proc", Type:"proc", Source:"proc", Options:[]string{"nosuid", "noexec", "nodev"}}, specs.Mount{Destination:"/dev", Type:"tmpfs", Source:"tmpfs", Options:[]string{"nosuid", "strictatime", "mode=755"}}, specs.Mount{Destination:"/dev/pts", Type:"devpts", Source:"devpts", Options:[]string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"}}, specs.Mount{Destination:"/sys", Type:"sysfs", Source:"sysfs", Options:[]string{"nosuid", "noexec", "nodev", "ro"}}, specs.Mount{Destination:"/sys/fs/cgroup", Type:"cgroup", Source:"cgroup", Options:[]string{"ro", "nosuid", "noexec", "nodev"}}, specs.Mount{Destination:"/dev/mqueue", Type:"mqueue", Source:"mqueue", Options:[]string{"nosuid", "noexec", "nodev"}}, specs.Mount{Destination:"/etc/resolv.conf", Type:"bind", Source:"/home/docker_rt/containers/7a2c5bdc8ad29a01ce07e64ee5c602436784b6ab812502557e8b6dd8684ada2b/resolv.conf", Options:[]string{"rbind", "rprivate"}}, specs.Mount{Destination:"/etc/hostname", Type:"bind", Source:"/home/docker_rt/containers/7a2c5bdc8ad29a01ce07e64ee5c602436784b6ab812502557e8b6dd8684ada2b/hostname", Options:[]string{"rbind", "rprivate"}}, specs.Mount{Destination:"/etc/hosts", Type:"bind", Source:"/home/docker_rt/containers/7a2c5bdc8ad29a01ce07e64ee5c602436784b6ab812502557e8b6dd8684ada2b/hosts", Options:[]string{"rbind", "rprivate"}}, specs.Mount{Destination:"/dev/shm", Type:"bind", Source:"/home/docker_rt/containers/7a2c5bdc8ad29a01ce07e64ee5c602436784b6ab812502557e8b6dd8684ada2b/shm", Options:[]string{"rbind", "rprivate"}}}, Hooks:specs.Hooks{Prestart:[]specs.Hook{specs.Hook{Path:"/usr/bin/dockerd", Args:[]string{"libnetwork-setkey", "7a2c5bdc8ad29a01ce07e64ee5c602436784b6ab812502557e8b6dd8684ada2b", "4ce282c31f92d8730b131be4c50c14389b78eff2b7a720e2cfd3a2bb27600970"}, Env:[]string(nil), Timeout:(*int)(nil)}}, Poststart:[]specs.Hook(nil), Poststop:[]specs.Hook(nil)}, Annotations:map[string]string(nil), Linux:(*specs.Linux)(0xc00016d5f0), Solaris:(*specs.Solaris)(nil), Windows:(*specs.Windows)(nil)}
		if err != nil {
			return err
		}
		status, err := startContainer(context, spec, true)
		if err != nil {
			return err
		}
		// exit with the container's exit status so any external supervisor is
		// notified of the exit with the correct exit status.
		os.Exit(status)
		return nil
	},
}
