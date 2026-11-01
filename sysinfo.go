package main

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// real size of this VPS (used as the admin's limits)
func vpsInfo() (int, float64, int) {
	ramMB := 0
	cpu := float64(runtime.NumCPU())
	if f, err := os.Open("/proc/meminfo"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l := sc.Text()
			if strings.HasPrefix(l, "MemTotal:") {
				fs := strings.Fields(l)
				if len(fs) >= 2 {
					if kb, e := strconv.Atoi(fs[1]); e == nil {
						ramMB = kb / 1024
					}
				}
				break
			}
		}
	}
	diskGB := 0
	var st syscall.Statfs_t
	if syscall.Statfs(dataDir, &st) == nil {
		diskGB = int((uint64(st.Blocks) * uint64(st.Bsize)) >> 30)
	}
	if ramMB < 512 {
		ramMB = 512
	}
	if diskGB < 1 {
		diskGB = 1
	}
	return ramMB, cpu, diskGB
}
