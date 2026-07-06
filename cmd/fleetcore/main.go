// Command fleetcore is the control-plane CLI: serve | keygen | issue.
//
//	fleetcore serve  -c fleet.yaml           run the service (default)
//	fleetcore keygen -o keys/ed25519.key     generate an Ed25519 signing key
//	fleetcore issue  --member nl-1 ...        emit a client SelfHosted config
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"fleetcore/internal/api"
	"fleetcore/internal/config"
	"fleetcore/internal/fleet"
	"fleetcore/internal/sign"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("fleetcore: ")

	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !isFlag(args[0]) {
		cmd, args = args[0], args[1:]
	}

	var err error
	switch cmd {
	case "serve":
		err = runServe(args)
	case "keygen":
		err = runKeygen(args)
	case "issue":
		err = runIssue(args)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "fleetcore: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func isFlag(s string) bool { return len(s) > 0 && s[0] == '-' }

func usage() {
	fmt.Fprint(os.Stderr, `fleetcore — self-hosted VPN fleet control-plane

usage:
  fleetcore serve  -c fleet.yaml [--tls-cert C --tls-key K] [--compress]
  fleetcore keygen -o keys/ed25519.key [--kid ID] [--force]
  fleetcore issue  -c fleet.yaml --member LABEL --endpoint URL [--interval 900]

Run "fleetcore <command> -h" for command flags.
`)
}

// --- serve ---------------------------------------------------------------

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("c", "fleet.yaml", "path to fleet.yaml")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
	tlsKey := fs.String("tls-key", "", "TLS key file")
	compress := fs.Bool("compress", false, "qCompress-frame the vpn:// payload (DESIGN.md D.4)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Signing.KeyFile == "" {
		return errors.New("signing.key_file is required for serve — run `fleetcore keygen -o <file>` first")
	}
	signer, err := sign.LoadSigner(cfg.Signing.KeyFile, cfg.Signing.Kid)
	if err != nil {
		return err
	}
	f, mon, err := fleet.Build(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("warming up health probes for %d member(s)...", len(cfg.Members))
	mon.WarmUp(ctx)
	go mon.Run(ctx)

	handler := api.NewServer(f, signer,
		api.WithHealth(mon),
		api.WithCompress(*compress),
	).Handler()

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("pinned public key: %s", sign.PublicKeyString(signer.PublicKey()))
	log.Printf("serving on %s (strategy=%s, kid=%s)", cfg.Listen, cfg.Selection, cfg.Signing.Kid)

	errCh := make(chan error, 1)
	go func() {
		if *tlsCert != "" || *tlsKey != "" {
			if *tlsCert == "" || *tlsKey == "" {
				errCh <- errors.New("both --tls-cert and --tls-key are required for HTTPS")
				return
			}
			errCh <- httpSrv.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			errCh <- httpSrv.ListenAndServe()
		}
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		log.Print("shutting down...")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutCtx)
	}
}

// --- keygen --------------------------------------------------------------

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("o", "keys/ed25519.key", "output key file (mode 0600)")
	kid := fs.String("kid", "", "key id to print (informational)")
	force := fs.Bool("force", false, "overwrite an existing key file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if _, err := os.Stat(*out); err == nil && !*force {
		return fmt.Errorf("key file %q already exists (use --force to overwrite)", *out)
	}
	if dir := filepath.Dir(*out); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	seed, err := sign.GenerateSeed()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(sign.EncodeKeyFile(seed)), 0o600); err != nil {
		return err
	}
	// WriteFile only applies 0600 when creating; enforce it on the --force
	// overwrite path too, so the key is never left group/world-readable.
	if err := os.Chmod(*out, 0o600); err != nil {
		return fmt.Errorf("set key file mode 0600: %w", err)
	}
	signer, err := sign.NewSignerFromSeed(seed, *kid)
	if err != nil {
		return err
	}
	fmt.Printf("wrote private key to %s (mode 0600)\n", *out)
	fmt.Printf("public key: %s\n", sign.PublicKeyString(signer.PublicKey()))
	fmt.Println("embed this as update_pubkey when issuing a client config; it is also served at GET /v1/pubkey")
	return nil
}

// --- issue ---------------------------------------------------------------

func runIssue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	cfgPath := fs.String("c", "fleet.yaml", "path to fleet.yaml")
	member := fs.String("member", "", "member label whose config to emit (required)")
	endpoint := fs.String("endpoint", "", "update_endpoint URL to embed (required)")
	interval := fs.Int("interval", 900, "update_interval_sec to embed")
	keyFile := fs.String("key", "", "signing key file (default: signing.key_file from config)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *member == "" || *endpoint == "" {
		return errors.New("--member and --endpoint are required")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	m := cfg.Member(*member)
	if m == nil {
		return fmt.Errorf("no member %q in %s", *member, *cfgPath)
	}
	blob, err := os.ReadFile(m.ConfigFile)
	if err != nil {
		return fmt.Errorf("read member config_file: %w", err)
	}

	kf := *keyFile
	if kf == "" {
		kf = cfg.Signing.KeyFile
	}
	if kf == "" {
		return errors.New("no signing key: set signing.key_file or pass --key")
	}
	signer, err := sign.LoadSigner(kf, cfg.Signing.Kid)
	if err != nil {
		return err
	}

	var obj map[string]any
	if err := json.Unmarshal(blob, &obj); err != nil {
		return fmt.Errorf("member config_file is not valid JSON: %w", err)
	}
	// The proposed additive fields the client honours for SelfHosted configs
	// (DESIGN.md §8). They are extra top-level keys today's parser ignores.
	obj["update_endpoint"] = *endpoint
	obj["update_pubkey"] = sign.PublicKeyString(signer.PublicKey())
	obj["update_interval_sec"] = *interval

	// Disable HTML escaping so AmneziaWG's I1 junk blob ("<r 2><b 0x…>") stays
	// byte-faithful instead of turning into </>.
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(obj)
}
