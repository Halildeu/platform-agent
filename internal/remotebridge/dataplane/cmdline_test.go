package dataplane

import "testing"

func TestQuoteArg(t *testing.T) {
	cases := []struct{ in, want string }{
		{"simple", "simple"},
		{"", `""`},
		{"has space", `"has space"`},
		{`with"quote`, `"with\"quote"`},
		{`C:\Program Files\x.exe`, `"C:\Program Files\x.exe"`}, // space → quoted, backslashes kept
		{`tab\there`, "tab\\there"},                            // no space/quote → unquoted, backslash literal
		{`ends\`, `ends\`},                                     // trailing backslash, no quote → unquoted
		{`a\\"b`, `"a\\\\\"b"`},                                // 2 backslashes before quote → doubled (4) + escaped quote
	}
	for _, c := range cases {
		if got := quoteArg(c.in); got != c.want {
			t.Errorf("quoteArg(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuildCommandLine(t *testing.T) {
	got := buildCommandLine(`C:\Win\cmd.exe`, []string{"/c", "exit 0"})
	want := `C:\Win\cmd.exe /c "exit 0"`
	if got != want {
		t.Fatalf("buildCommandLine = %q, want %q", got, want)
	}
}
