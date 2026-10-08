package cmd

import (
	"os"
	"os/signal"
	"syscall"
)

// waitSignal 阻塞等待中断信号（Ctrl+C / SIGTERM）
func waitSignal(ch chan os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}
