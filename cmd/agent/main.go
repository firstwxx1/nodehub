package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"nodehub/internal/agent"
	"nodehub/internal/proto"
)

func main() {
	cfgPath := flag.String("config", "/etc/nodehub/agent.json", "agent config file")
	master := flag.String("master", "", "master URL (writes config when set together with -token)")
	token := flag.String("token", "", "server token")
	insecure := flag.Bool("insecure", false, "skip TLS verification of the master")
	version := flag.Bool("version", false, "print version")
	initOnly := flag.Bool("init", false, "write the config file and exit")
	flag.Parse()

	if *version {
		fmt.Println("nodehub-agent", proto.AgentVersion)
		return
	}
	var cfg agent.Config
	if b, err := os.ReadFile(*cfgPath); err == nil {
		if err := json.Unmarshal(b, &cfg); err != nil {
			log.Fatalf("parse %s: %v", *cfgPath, err)
		}
	}
	if *master != "" && *token != "" {
		cfg.Master, cfg.Token, cfg.InsecureTLS = *master, *token, *insecure
		cfg.Defaults()
		_ = os.MkdirAll(filepath.Dir(*cfgPath), 0o755)
		b, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(*cfgPath, b, 0o600); err != nil {
			log.Fatalf("write config: %v", err)
		}
		log.Printf("config written to %s", *cfgPath)
		if *initOnly {
			return
		}
	}
	if cfg.Master == "" || cfg.Token == "" {
		log.Fatalf("missing master/token: run with -master https://panel.example.com -token XXX")
	}
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[agent] ")
	a := agent.New(cfg)
	stop := make(chan struct{})
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		close(stop)
	}()
	log.Printf("nodehub-agent %s started, master=%s", proto.AgentVersion, cfg.Master)
	a.Run(stop)
}
