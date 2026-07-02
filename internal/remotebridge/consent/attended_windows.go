//go:build windows

package consent

import (
	"context"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wtsNoActiveSession = 0xFFFFFFFF
	messageBoxYes      = 6
)

var (
	wtsapi32           = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSSendMessage = wtsapi32.NewProc("WTSSendMessageW")
)

func defaultViewOnlyUserPrompt(ctx context.Context, req PromptRequest) (PromptDecision, error) {
	if err := ctx.Err(); err != nil {
		return PromptDecision{}, err
	}
	sessionID, interactiveSession := activePromptSession()
	if sessionID == wtsNoActiveSession {
		return PromptDecision{Granted: false, InteractiveSession: "no-active-windows-session"}, nil
	}
	title := "Endpoint Agent VIEW_ONLY Consent"
	message := promptMessage(req)
	timeoutSecondsFloat := req.Timeout.Seconds()
	timeoutSeconds := uint32(timeoutSecondsFloat)
	if timeoutSecondsFloat < 1 {
		timeoutSeconds = 1
	}
	if timeoutSecondsFloat > float64(^uint32(0)) {
		timeoutSeconds = ^uint32(0)
	}
	response, ok, callErr := wtsSendMessage(sessionID, title, message, windows.MB_YESNO|windows.MB_ICONWARNING|windows.MB_DEFBUTTON2, timeoutSeconds)
	if !ok {
		if callErr != nil && callErr != syscall.Errno(0) {
			return PromptDecision{Granted: false, InteractiveSession: interactiveSession + "-prompt-failed"}, nil
		}
		return PromptDecision{Granted: false, InteractiveSession: interactiveSession + "-prompt-unavailable"}, nil
	}
	return PromptDecision{Granted: response == messageBoxYes, InteractiveSession: interactiveSession}, nil
}

func activePromptSession() (uint32, string) {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err == nil && sessions != nil {
		defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
		for _, session := range unsafe.Slice(sessions, count) {
			if session.SessionID != 0 && session.State == windows.WTSActive {
				return session.SessionID, fmt.Sprintf("wts-session-%d-active", session.SessionID)
			}
		}
		return wtsNoActiveSession, "no-active-windows-session"
	}
	consoleID := windows.WTSGetActiveConsoleSessionId()
	if consoleID == wtsNoActiveSession {
		return wtsNoActiveSession, "no-active-windows-session"
	}
	// Fallback only when enumeration is unavailable; WTSSendMessage remains the
	// final arbiter and returns denied/fail-closed when no user can answer.
	return consoleID, fmt.Sprintf("wts-session-%d-console", consoleID)
}

func wtsSendMessage(sessionID uint32, title string, message string, style uint32, timeoutSeconds uint32) (uint32, bool, error) {
	title16 := windows.StringToUTF16(strings.TrimSpace(title))
	message16 := windows.StringToUTF16(message)
	var response uint32
	r1, _, err := procWTSSendMessage.Call(
		0,
		uintptr(sessionID),
		uintptr(unsafe.Pointer(&title16[0])),
		uintptr((len(title16)-1)*2),
		uintptr(unsafe.Pointer(&message16[0])),
		uintptr((len(message16)-1)*2),
		uintptr(style),
		uintptr(timeoutSeconds),
		uintptr(unsafe.Pointer(&response)),
		uintptr(1),
	)
	return response, r1 != 0, err
}
