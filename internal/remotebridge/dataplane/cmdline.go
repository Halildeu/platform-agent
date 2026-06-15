package dataplane

import "strings"

// buildCommandLine assembles a Windows command line: argv[0] is the (quoted)
// exe path, followed by quoted args. Kept OS-agnostic (pure string logic) so
// the quoting — which is security-relevant (a mis-quote is a command-line
// injection vector) — is unit-testable on any platform.
func buildCommandLine(exe string, args []string) string {
	var b strings.Builder
	b.WriteString(quoteArg(exe))
	for _, a := range args {
		b.WriteByte(' ')
		b.WriteString(quoteArg(a))
	}
	return b.String()
}

// quoteArg applies minimal CommandLineToArgvW-compatible quoting: wrap when the
// arg is empty or contains whitespace/quote; backslashes are doubled only when
// they precede a quote (or the closing quote), matching the Windows parser.
func quoteArg(s string) string {
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
