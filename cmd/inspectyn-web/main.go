package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/cwsecur1ty/inspectyn/internal/webkit"
)

const help = `Inspectyn local web interface

Usage:
  inspectyn-web --cli ./inspectyn
  inspectyn-web --cli ./inspectyn.exe --port 8788

Options:
  --cli   Native Inspectyn executable (default: sibling binary, then PATH)
  --port  Local HTTP port, 0-65535 (default 8788; 0 chooses a free port)
  --help  Show help

Open the printed URL in your browser. Ctrl+C stops the server and active run.
Listens on 127.0.0.1 only. The latest 10 runs are kept in memory until exit.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "inspectyn-web:", err)
		os.Exit(2)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	options := flag.NewFlagSet("inspectyn-web", flag.ContinueOnError)
	options.SetOutput(io.Discard)
	cliPath := options.String("cli", "", "Inspectyn executable")
	port := options.Int("port", 8788, "local port")
	showHelp := options.Bool("help", false, "help")
	options.BoolVar(showHelp, "h", false, "help")
	if err := options.Parse(args); err != nil {
		return err
	}
	if *showHelp {
		_, err := fmt.Fprint(stdout, help)
		return err
	}
	if options.NArg() != 0 || *port < 0 || *port > 65535 {
		return errors.New("use --cli and a --port from 0 to 65535; see --help")
	}
	runner, err := webkit.NewCLIRunner(*cliPath)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	if err != nil {
		return fmt.Errorf("could not listen on the local port; try --port 0: %w", err)
	}
	defer listener.Close()
	app, err := webkit.NewServer(ctx, runner, runner.Version(), listener.Addr().String())
	if err != nil {
		return err
	}
	defer app.Close()
	server := &http.Server{Handler: app, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	if _, err := fmt.Fprintf(stdout, "Inspectyn web: http://%s\nCLI version: %s\nPress Ctrl+C to stop.\n", listener.Addr(), runner.Version()); err != nil {
		_ = server.Close()
		return err
	}
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return err
		}
		return nil
	case err := <-finished:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
