//go:build !linux

package agent

func diskUsage(string) (uint64, uint64) { return 0, 0 }
