package cmdline

import "testing"

func TestQuoteArg(t *testing.T) {
	cases := []struct{ in, want string }{
		{"simple", "simple"},
		{"", `""`},
		{"has space", `"has space"`},
		{`with"quote`, `"with\"quote"`},
		{`trailing\`, `trailing\`},
		{`path\with space`, `"path\with space"`},
		{`ends\\`, `ends\\`},
		{`a\\"b`, `"a\\\\\"b"`},
		{"tab\there", "\"tab\there\""},
	}
	for _, c := range cases {
		if got := QuoteArg(c.in); got != c.want {
			t.Errorf("QuoteArg(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuildCommandLine(t *testing.T) {
	got := BuildCommandLine(`C:\Win\cmd.exe`, []string{"/c", "exit 0"})
	want := `C:\Win\cmd.exe /c "exit 0"`
	if got != want {
		t.Fatalf("BuildCommandLine = %q, want %q", got, want)
	}
}
