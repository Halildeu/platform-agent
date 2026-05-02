//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"platform-agent/internal/security"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const stopWaitTimeout = 30 * time.Second

func IsWindowsService() (bool, error) {
	return svc.IsWindowsService()
}

func Run(name string, run func(context.Context) error) error {
	options := DefaultOptions()
	options.Name = name
	options = options.Normalized()
	return svc.Run(options.Name, &handler{name: options.Name, run: run})
}

func Install(options Options) error {
	options = options.Normalized()
	executablePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer manager.Disconnect()

	if existing, err := manager.OpenService(options.Name); err == nil {
		existing.Close()
		return fmt.Errorf("service %q already exists", options.Name)
	}

	service, err := manager.CreateService(options.Name, executablePath, mgr.Config{
		DisplayName: options.DisplayName,
		Description: options.Description,
		StartType:   mgr.StartAutomatic,
	}, "--service-run-name", options.Name)
	if err != nil {
		return fmt.Errorf("create service %q: %w", options.Name, err)
	}
	defer service.Close()

	if err := eventlog.InstallAsEventCreate(options.Name, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		return fmt.Errorf("install event log source: %w", err)
	}
	return nil
}

func Uninstall(options Options) error {
	options = options.Normalized()
	manager, service, err := open(options)
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	defer service.Close()

	status, err := service.Query()
	if err == nil && status.State != svc.Stopped {
		if err := stopService(service); err != nil {
			return err
		}
	}
	if err := service.Delete(); err != nil {
		return fmt.Errorf("delete service %q: %w", options.Name, err)
	}
	if err := eventlog.Remove(options.Name); err != nil {
		return fmt.Errorf("remove event log source: %w", err)
	}
	return nil
}

func Start(options Options) error {
	options = options.Normalized()
	manager, service, err := open(options)
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	defer service.Close()

	status, err := service.Query()
	if err != nil {
		return fmt.Errorf("query service %q: %w", options.Name, err)
	}
	if status.State == svc.Running {
		return nil
	}
	if err := service.Start(); err != nil {
		return fmt.Errorf("start service %q: %w", options.Name, err)
	}
	return waitForState(service, svc.Running, stopWaitTimeout)
}

func Stop(options Options) error {
	options = options.Normalized()
	manager, service, err := open(options)
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	defer service.Close()

	return stopService(service)
}

func QueryStatus(options Options) (StatusSnapshot, error) {
	options = options.Normalized()
	manager, service, err := open(options)
	if err != nil {
		return StatusSnapshot{Name: options.Name}, err
	}
	defer manager.Disconnect()
	defer service.Close()

	status, err := service.Query()
	if err != nil {
		return StatusSnapshot{Name: options.Name}, fmt.Errorf("query service %q: %w", options.Name, err)
	}
	return StatusSnapshot{Name: options.Name, State: stateName(status.State)}, nil
}

func open(options Options) (*mgr.Mgr, *mgr.Service, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, nil, fmt.Errorf("connect service manager: %w", err)
	}
	service, err := manager.OpenService(options.Name)
	if err != nil {
		manager.Disconnect()
		return nil, nil, fmt.Errorf("open service %q: %w", options.Name, err)
	}
	return manager, service, nil
}

func stopService(service *mgr.Service) error {
	status, err := service.Query()
	if err != nil {
		return fmt.Errorf("query service before stop: %w", err)
	}
	if status.State == svc.Stopped {
		return nil
	}
	if _, err := service.Control(svc.Stop); err != nil {
		return fmt.Errorf("send stop control: %w", err)
	}

	deadline := time.Now().Add(stopWaitTimeout)
	for time.Now().Before(deadline) {
		status, err = service.Query()
		if err != nil {
			return fmt.Errorf("query service during stop: %w", err)
		}
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service did not stop within %s", stopWaitTimeout)
}

func waitForState(service *mgr.Service, target svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, err := service.Query()
		if err != nil {
			return fmt.Errorf("query service state: %w", err)
		}
		if status.State == target {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service did not reach %s within %s", stateName(target), timeout)
}

func stateName(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "STOPPED"
	case svc.StartPending:
		return "START_PENDING"
	case svc.StopPending:
		return "STOP_PENDING"
	case svc.Running:
		return "RUNNING"
	case svc.ContinuePending:
		return "CONTINUE_PENDING"
	case svc.PausePending:
		return "PAUSE_PENDING"
	case svc.Paused:
		return "PAUSED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", state)
	}
}

type handler struct {
	name string
	run  func(context.Context) error
}

func (h *handler) Execute(_ []string, changes <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}
	h.info("service starting")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		if h.run == nil {
			errCh <- errors.New("service runner is nil")
			return
		}
		errCh <- h.run(ctx)
	}()

	status <- svc.Status{State: svc.Running, Accepts: accepts}
	h.info("service running")
	for {
		select {
		case err := <-errCh:
			status <- svc.Status{State: svc.Stopped}
			if err != nil && !errors.Is(err, context.Canceled) {
				h.error("service runner failed: " + err.Error())
				return true, 1
			}
			h.info("service stopped")
			return false, 0
		case change := <-changes:
			switch change.Cmd {
			case svc.Interrogate:
				status <- change.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				h.info("service stopping")
				cancel()
				if err := waitRunner(errCh); err != nil {
					h.error("service stop failed: " + err.Error())
					return true, 2
				}
				status <- svc.Status{State: svc.Stopped}
				h.info("service stopped")
				return false, 0
			default:
				status <- svc.Status{State: svc.Running, Accepts: accepts}
			}
		}
	}
}

func (h *handler) info(message string) {
	h.writeEvent(func(logger *eventlog.Log, redacted string) error {
		return logger.Info(1, redacted)
	}, message)
}

func (h *handler) error(message string) {
	h.writeEvent(func(logger *eventlog.Log, redacted string) error {
		return logger.Error(1, redacted)
	}, message)
}

func (h *handler) writeEvent(write func(*eventlog.Log, string) error, message string) {
	logger, err := eventlog.Open(h.name)
	if err != nil {
		return
	}
	defer logger.Close()
	_ = write(logger, security.RedactText(message))
}

func waitRunner(errCh <-chan error) error {
	select {
	case err := <-errCh:
		if err == nil || errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	case <-time.After(stopWaitTimeout):
		return fmt.Errorf("service runner did not stop within %s", stopWaitTimeout)
	}
}
