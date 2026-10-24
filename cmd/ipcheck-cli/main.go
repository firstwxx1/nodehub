// ipcheck-cli runs the aggregated IP check from the command line (debug tool).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"nodehub/internal/ipcheck"
)

func main() {
	for _, ip := range os.Args[1:] {
		r := ipcheck.Check(context.Background(), ip, ipcheck.Keys{IPQS: os.Getenv("IPQS_KEY")})
		r.Sources = nil
		b, _ := json.Marshal(r)
		fmt.Println(string(b))
	}
}
