package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"platform-agent/internal/app"
	"platform-agent/internal/config"
	"platform-agent/internal/identity"
	agentlog "platform-agent/internal/logging"
	winservice "platform-agent/internal/platform/windows/service"
	"platform-agent/internal/protocol"
	"platform-agent/internal/security"
	"platform-agent/internal/users"
)

func main() {
	once := flag.Bool("once", false, "run one enroll/heartbeat/command iteration and exit")
	version := flag.Bool("version", false, "print agent version and exit")
	serviceRunName := flag.String("service-run-name", winservice.DefaultName, "internal Windows service name")
	flag.Parse()

	cfg := config.LoadFromEnv()
	if *version {
		fmt.Printf("%s %s\n", cfg.AgentName, cfg.AgentVersion)
		return
	}
	if len(flag.Args()) > 0 && flag.Args()[0] == "service" {
		handleServiceCommand(flag.Args()[1:])
		return
	}
	if len(flag.Args()) > 0 && flag.Args()[0] == "diagnose" {
		handleDiagnoseCommand(flag.Args()[1:])
		return
	}

	runningAsService, err := winservice.IsWindowsService()
	if err != nil {
		log.Fatalf("service detection failed: %v", err)
	}
	loggerBundle, err := agentlog.New(agentlog.Options{
		AgentName:     cfg.AgentName,
		LogDir:        cfg.LogDir,
		IncludeStdout: !runningAsService,
	})
	if err != nil {
		log.Fatalf("logger init failed: %v", err)
	}
	defer loggerBundle.Close()
	logger := loggerBundle.Logger
	logger.Printf("logger initialized logPath=%s serviceMode=%t", loggerBundle.LogPath, runningAsService)

	if runningAsService {
		if err := winservice.Run(*serviceRunName, func(ctx context.Context) error {
			runner, err := newRunner(cfg, logger)
			if err != nil {
				return err
			}
			return runner.RunLoop(ctx)
		}); err != nil {
			logger.Fatalf("service run failed: %v", err)
		}
		return
	}

	runner, err := newRunner(cfg, logger)
	if err != nil {
		logger.Fatalf("agent init failed: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *once {
		if err := runner.RunOnce(ctx); err != nil {
			logger.Fatalf("agent run failed: %v", err)
		}
		return
	}
	if err := runner.RunLoop(ctx); err != nil && err != context.Canceled {
		logger.Fatalf("agent loop failed: %v", err)
	}
}

func newRunner(cfg config.Config, logger *log.Logger) (*app.Runner, error) {
	client, err := protocol.NewClient(cfg.APIURL, cfg.SigningPathPrefix, &http.Client{Timeout: cfg.CommandTimeout})
	if err != nil {
		return nil, fmt.Errorf("client init failed: %w", err)
	}
	client.SetIdentity(cfg.CredentialID, cfg.Secret, cfg.DeviceID)
	return app.NewRunner(cfg, client, logger), nil
}

func handleServiceCommand(args []string) {
	if len(args) == 0 {
		printServiceUsage()
		os.Exit(2)
	}

	action := args[0]
	options := winservice.DefaultOptions()
	flags := flag.NewFlagSet("service "+action, flag.ExitOnError)
	flags.StringVar(&options.Name, "name", options.Name, "Windows service name")
	flags.StringVar(&options.DisplayName, "display-name", options.DisplayName, "Windows service display name")
	flags.StringVar(&options.Description, "description", options.Description, "Windows service description")
	maintenanceToken := flags.String("maintenance-token", "", "maintenance token for stop/uninstall when ENDPOINT_AGENT_MAINTENANCE_TOKEN_SHA256 is configured")
	maintenanceTokenHash := flags.String("maintenance-token-sha256", "", "expected maintenance token sha256 hash override")
	if err := flags.Parse(args[1:]); err != nil {
		log.Fatalf("service command parse failed: %v", err)
	}

	var err error
	switch action {
	case "install":
		err = winservice.Install(options)
	case "uninstall":
		err = requireMaintenanceToken(*maintenanceToken, *maintenanceTokenHash)
		if err != nil {
			break
		}
		err = winservice.Uninstall(options)
	case "start":
		err = winservice.Start(options)
	case "stop":
		err = requireMaintenanceToken(*maintenanceToken, *maintenanceTokenHash)
		if err != nil {
			break
		}
		err = winservice.Stop(options)
	case "status":
		var status winservice.StatusSnapshot
		status, err = winservice.QueryStatus(options)
		if err == nil {
			fmt.Println(status.String())
		}
	default:
		printServiceUsage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("service %s failed: %v", action, err)
	}
	if action != "status" {
		fmt.Printf("service %s ok: %s\n", action, options.Normalized().Name)
	}
}

func printServiceUsage() {
	fmt.Fprintln(os.Stderr, "usage: endpoint-agent service <install|uninstall|start|stop|status> [--name name] [--display-name label] [--description text] [--maintenance-token token]")
}

func requireMaintenanceToken(token string, hashOverride string) error {
	expectedHash := hashOverride
	if expectedHash == "" {
		expectedHash = os.Getenv("ENDPOINT_AGENT_MAINTENANCE_TOKEN_SHA256")
	}
	if err := security.RequireMaintenanceToken(token, expectedHash); err != nil {
		return fmt.Errorf("%w: stop/uninstall requires --maintenance-token", err)
	}
	return nil
}

func handleDiagnoseCommand(args []string) {
	if len(args) == 0 {
		printDiagnoseUsage()
		os.Exit(2)
	}

	switch args[0] {
	case "identity":
		snapshot := identity.Collect(time.Now())
		if err := json.NewEncoder(os.Stdout).Encode(snapshot); err != nil {
			log.Fatalf("diagnose identity encode failed: %v", err)
		}
	case "local-users":
		localUsers, err := users.ListLocal()
		if err != nil {
			log.Fatalf("diagnose local-users failed: %v", err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(localUsers); err != nil {
			log.Fatalf("diagnose local-users encode failed: %v", err)
		}
	default:
		printDiagnoseUsage()
		os.Exit(2)
	}
}

func printDiagnoseUsage() {
	fmt.Fprintln(os.Stderr, "usage: endpoint-agent diagnose <identity|local-users>")
}
