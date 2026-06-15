// Package cmdline is the single source of Windows command-line quoting for the remote-bridge agent. The
// quoting is security-relevant (a mis-quote is a command-line injection vector), so both the session-launcher
// (dataplane) and the CONSTRAINED_PTY executor (ptyexec) share THIS one implementation — never a per-package
// copy that could drift. OS-agnostic pure string logic, so it is unit-testable on any platform.
package cmdline

import "strings"

// BuildCommandLine assembles a Windows command line: argv[0] is the (quoted) exe path, followed by quoted
// args. The result is CommandLineToArgvW-compatible, so the target process's CRT re-parses exactly
// exe + args (the no-shell invariant — the binary is spawned directly, never via a shell string).
func BuildCommandLine(exe string, args []string) string {
	var b strings.Builder
	b.WriteString(QuoteArg(exe))
	for _, a := range args {
		b.WriteByte(' ')
		b.WriteString(QuoteArg(a))
	}
	return b.String()
}

// QuoteArg applies minimal CommandLineToArgvW-compatible quoting: wrap when the arg is empty or contains
// whitespace/quote; backslashes are doubled only when they precede a quote (or the closing quote), matching
// the Windows parser.
func QuoteArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n\v\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	bs := 0
	for _, r := range s {
		switch r {
		case '\\':
			bs++
		case '"':
			for i := 0; i < bs*2+1; i++ {
				b.WriteByte('\\')
			}
			bs = 0
			b.WriteByte('"')
		default:
			for i := 0; i < bs; i++ {
				b.WriteByte('\\')
			}
			bs = 0
			b.WriteRune(r)
		}
	}
	for i := 0; i < bs*2; i++ {
		b.WriteByte('\\')
	}
	b.WriteByte('"')
	return b.String()
}
