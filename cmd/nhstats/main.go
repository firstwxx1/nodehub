// nhstats prints the stats counters of a local Xray / sing-box API without resetting them (debug tool).
package main

import (
	"fmt"
	"os"

	"nodehub/internal/agent"
)

func main() {
	addr, svc := "127.0.0.1:10086", agent.SingboxStatsService
	if len(os.Args) > 1 && os.Args[1] == "xray" {
		addr, svc = "127.0.0.1:10085", agent.XrayStatsService
	}
	c, err := agent.NewStatsClient(addr, svc)
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}
	m, err := c.Query("", false)
	if err != nil {
		fmt.Println("query:", err)
		os.Exit(1)
	}
	for k, v := range m {
		fmt.Println(k, v)
	}
	fmt.Println("counters:", len(m))
}
