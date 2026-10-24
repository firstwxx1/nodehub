package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/crypto/bcrypt"

	"nodehub/internal/master"
	"nodehub/internal/store"
	"nodehub/web"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	listen := flag.String("listen", env("NODEHUB_LISTEN", ":8080"), "listen address")
	data := flag.String("data", env("NODEHUB_DATA", "./data"), "data directory")
	dist := flag.String("dist", env("NODEHUB_DIST", "./dist"), "directory with agent binaries served at /dl/")
	public := flag.String("public-url", env("NODEHUB_PUBLIC_URL", ""), "public URL of this panel, e.g. https://nodes.example.com")
	flag.Parse()

	// nodehub reset-password <user> <password>
	if flag.Arg(0) == "reset-password" {
		if flag.NArg() != 3 {
			fmt.Println("usage: nodehub reset-password <username> <new-password>")
			os.Exit(2)
		}
		st, err := store.Open(filepath.Join(*data, "nodehub.db"))
		if err != nil {
			log.Fatal(err)
		}
		h, _ := bcrypt.GenerateFromPassword([]byte(flag.Arg(2)), bcrypt.DefaultCost)
		a, err := st.AdminByName(flag.Arg(1))
		if err != nil {
			if err := st.CreateAdmin(flag.Arg(1), string(h)); err != nil {
				log.Fatal(err)
			}
			fmt.Println("admin created")
			return
		}
		if err := st.UpdateAdminPassword(a.ID, string(h)); err != nil {
			log.Fatal(err)
		}
		_ = st.SetAdminTOTP(a.ID, "")
		fmt.Println("password reset, 2FA disabled")
		return
	}

	webFS, err := fs.Sub(web.FS, "dist")
	if err != nil {
		log.Fatal(err)
	}
	srv, err := master.New(master.Options{
		Listen: *listen, DataDir: *data, DistDir: *dist, PublicURL: *public, WebFS: webFS,
		AdminUser: os.Getenv("NODEHUB_ADMIN_USER"), AdminPass: os.Getenv("NODEHUB_ADMIN_PASS"),
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := srv.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
