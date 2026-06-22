package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"platform-agent/internal/app"
	"platform-agent/internal/autoenroll"
	"platform-agent/internal/config"
	winservice "platform-agent/internal/platform/windows/service"
	"platform-agent/internal/selfupdate"
)

func handleSelfUpdateCommand(args []string) {
	if len(args) == 0 {
		printSelfUpdateUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "activate":
		handleSelfUpdateActivate(args[1:])
	case "status":
		handleSelfUpdateStatus(args[1:])
	default:
		printSelfUpdateUsage()
		os.Exit(2)
	}
}

func handleSelfUpdateActivate(args []string) {
	defaults := config.Default()
	flags := flag.NewFlagSet("self-update activate", flag.ExitOnError)
	stagingRoot := flags.String("staging-root", defaultSelfUpdateStagingRoot(), "self-update staging root")
	stagingID := flags.String("staging-id", "", "opaque staging / activation plan id")
	maxBytes := flags.Int64("max-bytes", defaults.SelfUpdateHardMaxBytes, "maximum binary bytes to verify")
	timeout := flags.Duration("timeout", defaults.SelfUpdateActivationTimeout, "activation timeout")
	serviceName := flags.String("service-name", defaults.SelfUpdateServiceName, "Windows service name")
	highWaterPath := flags.String("high-water-path", defaultSelfUpdateHighWaterPath(), "activated-version high-water path")
	if err := flags.Parse(args); err != nil {
		log.Fatalf("self-update activate parse failed: %v", err)
	}
	if *stagingRoot == "" || *stagingID == "" {
		log.Fatalf("self-update activate requires --staging-root and --staging-id")
	}
	if *timeout <= 0 {
		*timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	service := serviceController{name: *serviceName}
	var highWater selfupdate.HighWaterWriter
	if *highWaterPath != "" {
		highWater = selfupdate.FileHighWaterStore{Path: *highWaterPath}
	}
	out := selfupdate.ActivatePreparedUpdate(ctx, *stagingRoot, *stagingID, *maxBytes, service, highWater)
	printJSON(out)
	if out.Status != selfupdate.ActivationActivated {
		os.Exit(1)
	}
}

func handleSelfUpdateStatus(args []string) {
	defaults := config.Default()
	flags := flag.NewFlagSet("self-update status", flag.ExitOnError)
	stagingRoot := flags.String("staging-root", defaultSelfUpdateStagingRoot(), "self-update staging root")
	stagingID := flags.String("staging-id", "", "opaque staging / activation plan id")
	maxBytes := flags.Int64("max-bytes", defaults.SelfUpdateHardMaxBytes, "maximum binary bytes to verify")
	if err := flags.Parse(args); err != nil {
		log.Fatalf("self-update status parse failed: %v", err)
	}
	if *stagingRoot == "" || *stagingID == "" {
		log.Fatalf("self-update status requires --staging-root and --staging-id")
	}
	report := map[string]interface{}{}
	if ready, code, reason := selfupdate.VerifyActivationPlanReady(*stagingRoot, *stagingID, *maxBytes); code == "" {
		report["readiness"] = ready
	} else {
		report["readinessError"] = map[string]string{"code": string(code), "reason": reason}
	}
	if outcome, code, reason := selfupdate.LoadActivationOutcome(*stagingRoot, *stagingID); code == "" {
		report["outcome"] = outcome
	} else {
		report["outcomeError"] = map[string]string{"code": string(code), "reason": reason}
	}
	printJSON(report)
}

func configureSelfUpdateActivationHook(runner *app.Runner, cfg config.Config, logger *log.Logger) {
	if runner == nil {
		return
	}
	runner.SelfUpdateActivationHook = makeSelfUpdateActivationHook(cfg, logger)
}

func configureAutoEnrollSelfUpdateActivationHook(runner *autoenroll.Runner, cfg config.Config, logger *log.Logger) {
	if runner == nil {
		return
	}
	runner.SelfUpdateActivationHook = makeSelfUpdateActivationHook(cfg, logger)
}

func makeSelfUpdateActivationHook(cfg config.Config, logger *log.Logger) func(context.Context, selfupdate.StageResult) error {
	if !cfg.SelfUpdateAutoActivate {
		return nil
	}
	executable := currentExecutablePath()
	stagingRoot := defaultSelfUpdateStagingRoot()
	timeout := cfg.SelfUpdateActivationTimeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	maxBytes := cfg.SelfUpdateHardMaxBytes
	if maxBytes <= 0 {
		maxBytes = selfupdate.DefaultMaxUpdateBytes
	}
	serviceName := cfg.SelfUpdateServiceName
	if serviceName == "" {
		serviceName = winservice.DefaultName
	}
	return func(ctx context.Context, stage selfupdate.StageResult) error {
		if executable == "" {
			return fmt.Errorf("self-update activation helper executable path is empty")
		}
		if stagingRoot == "" {
			return fmt.Errorf("self-update staging root is empty")
		}
		helperExecutable, code, reason := selfupdate.PrepareActivationHelper(ctx, executable, stagingRoot, stage.ActivationPlanID, maxBytes)
		if code != "" {
			return fmt.Errorf("prepare self-update activation helper failed code=%s reason=%s", code, reason)
		}
		args := []string{
			"self-update", "activate",
			"--staging-root", stagingRoot,
			"--staging-id", stage.ActivationPlanID,
			"--max-bytes", fmt.Sprintf("%d", maxBytes),
			"--timeout", timeout.String(),
			"--service-name", serviceName,
		}
		if logger != nil {
			logger.Printf("launching self-update activation helper activationPlanId=%s", stage.ActivationPlanID)
		}
		return startActivationHelperProcess(ctx, helperExecutable, args)
	}
}

func startActivationHelperProcess(ctx context.Context, executable string, args []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd := exec.Command(executable, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Start()
}

func currentExecutablePath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return exe
}

type serviceController struct {
	name string
}

func (s serviceController) Stop(_ context.Context, serviceName string) error {
	if serviceName == "" {
		serviceName = s.name
	}
	return winservice.Stop(winservice.Options{Name: serviceName})
}

func (s serviceController) Start(_ context.Context, serviceName string) error {
	if serviceName == "" {
		serviceName = s.name
	}
	return winservice.Start(winservice.Options{Name: serviceName})
}

func defaultSelfUpdateStagingRoot() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	root := os.Getenv("ProgramData")
	if root == "" {
		root = `C:\ProgramData`
	}
	return filepath.Join(root, "EndpointAgent", "self-update", "staging")
}

func defaultSelfUpdateHighWaterPath() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	root := os.Getenv("ProgramData")
	if root == "" {
		root = `C:\ProgramData`
	}
	return filepath.Join(root, "EndpointAgent", "self-update", "max-activated-version.txt")
}

func printSelfUpdateUsage() {
	fmt.Fprintln(os.Stderr, "usage: endpoint-agent self-update <activate|status> [options]")
}

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Fatalf("json encode failed: %v", err)
	}
}
