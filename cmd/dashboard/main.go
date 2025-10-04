package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"firmwareanalyzer/pkg/dashboard"
)

func main() {
	historyDir := flag.String("history-dir", "", "directory containing analyzer history records")
	listen := flag.String("listen", ":8080", "address for the dashboard web server")
	flag.Parse()

	if *historyDir == "" {
		log.Fatal("missing required --history-dir")
	}

	logger := log.New(os.Stdout, "dashboard ", log.LstdFlags)
	store, err := dashboard.NewFileStore(*historyDir, logger)
	if err != nil {
		log.Fatalf("history store: %v", err)
	}
	server := dashboard.NewServer(store, logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := server.Run(ctx, *listen); err != nil {
		log.Fatalf("dashboard server: %v", err)
	}
}
