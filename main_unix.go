// +build linux

package main

import (
	"os"
	"runtime"

	"github.com/opencontainers/runc/libcontainer"
	// 特别注意这个import，nsenter包内部包含init函数，会提前执行C逻辑(进入新命名空间)。go语言init函数是在main函数执行前执行，使得runc init主体逻辑得以在新命名空间内执行
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
	"github.com/urfave/cli"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()
	}
}

var initCommand = cli.Command{
	Name:  "init",
	Usage: `initialize the namespaces and launch the process (do not call it outside of runc)`,
	Action: func(context *cli.Context) error {
		factory, _ := libcontainer.New("")
		if err := factory.StartInitialization(); err != nil {
			// as the error is sent back to the parent there is no need to log
			// or write it to stderr because the parent process will handle this
			os.Exit(1)
		}
		panic("libcontainer: container init failed to exec")
	},
}
