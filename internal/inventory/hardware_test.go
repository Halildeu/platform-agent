package inventory

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestCollectHardwareUsesImpl asserts the cross-platform entry point
// delegates to the package-level seam variable rather than picking a
// hard-coded implementation. The build-tagged init() in
// hardware_windows.go installs the production collector on Windows;
// tests use this seam to inject deterministic fakes.
func TestCollectHardwareUsesImpl(t *testing.T) {
	original := collectHardwareImpl
	t.Cleanup(func() { collectHardwareImpl = original })

	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	sentinel := Hardware{
		SchemaVersion: HardwareSchemaVersion,
		Supported:     true,
		CPUModel:      "test-cpu",
		CollectedAt:   now,
	}
	collectHardwareImpl = func(invokedAt time.Time) Hardware {
		if !invokedAt.Equal(now) {
			t.Fatalf("collectHardwareImpl invoked with %v, want %v", invokedAt, now)
		}
		return sentinel
	}

	got := CollectHardware(now)
	if got.CPUModel != "test-cpu" {
		t.Fatalf("CollectHardware did not return the seam value: %+v", got)
	}
}

func TestCollectHardwareUnsupportedShape(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	hw := collectHardwareUnsupported(now)

	if hw.Supported {
		t.Fatalf("unsupported stub must return Supported=false, got true")
	}
	if hw.SchemaVersion != HardwareSchemaVersion {
		t.Fatalf("unsupported stub schemaVersion=%d, want %d", hw.SchemaVersion, HardwareSchemaVersion)
	}
	if hw.OSName != runtime.GOOS {
		t.Fatalf("unsupported stub osName=%q, want %q", hw.OSName, runtime.GOOS)
	}
	if hw.OSArch != runtime.GOARCH {
		t.Fatalf("unsupported stub osArch=%q, want %q", hw.OSArch, runtime.GOARCH)
	}
	if !hw.CollectedAt.Equal(now) {
		t.Fatalf("unsupported stub collectedAt=%v, want %v", hw.CollectedAt, now)
	}
	if len(hw.ProbeErrors) != 1 {
		t.Fatalf("unsupported stub probeErrors len=%d, want 1", len(hw.ProbeErrors))
	}
	if hw.ProbeErrors[0].Code != "UNSUPPORTED_PLATFORM" {
		t.Fatalf("unsupported stub probeError.code=%q, want UNSUPPORTED_PLATFORM",
			hw.ProbeErrors[0].Code)
	}
	// The stub must not leak any identifying material.
	if hw.CPUModel != "" || hw.Manufacturer != "" || hw.DomainName != "" || len(hw.Disks) != 0 || len(hw.NetworkInterfaces) != 0 {
		t.Fatalf("unsupported stub leaked identifying fields: %+v", hw)
	}
}

func TestNormalizeMACCanonicalForms(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"already canonical", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"},
		{"uppercase canonical", "AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"},
		{"dash separator", "AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff"},
		{"whitespace padded", "  aa:bb:cc:dd:ee:ff  ", "aa:bb:cc:dd:ee:ff"},
		{"empty input", "", ""},
		{"non-hex octet", "aa:bb:cc:dd:ee:zz", ""},
		{"wrong length octet", "aa:bb:cc:dd:ee:f", ""},
		{"too few octets", "aa:bb:cc:dd:ee", ""},
		{"too many octets", "aa:bb:cc:dd:ee:ff:gg", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeMAC(tc.in)
			if got != tc.want {
				t.Fatalf("normalizeMAC(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestClampNonNegative(t *testing.T) {
	if clampNonNegative(-1) != 0 {
		t.Fatalf("clampNonNegative(-1) must be 0")
	}
	if clampNonNegative(0) != 0 {
		t.Fatalf("clampNonNegative(0) must be 0")
	}
	if clampNonNegative(42) != 42 {
		t.Fatalf("clampNonNegative(42) must be 42")
	}
	if clampNonNegative64(int64(-9999)) != 0 {
		t.Fatalf("clampNonNegative64 negative must be 0")
	}
	if clampNonNegative64(int64(1<<40)) != int64(1<<40) {
		t.Fatalf("clampNonNegative64 large positive must round-trip")
	}
}

func TestBound256(t *testing.T) {
	if got := bound256(""); got != "" {
		t.Fatalf("bound256 empty must return empty")
	}
	if got := bound256("short"); got != "short" {
		t.Fatalf("bound256 short string must round-trip")
	}
	big := strings.Repeat("x", 300)
	got := bound256(big)
	if len(got) != 256 {
		t.Fatalf("bound256(300x) length=%d, want 256", len(got))
	}
	if !strings.HasPrefix(big, got) {
		t.Fatalf("bound256 must truncate from the start")
	}
}

func TestClassifyProbeError(t *testing.T) {
	// CIM_BINARY_MISSING — powershell not on PATH.
	if got := classifyProbeError(context.Background(), exec.ErrNotFound); got != "CIM_BINARY_MISSING" {
		t.Fatalf("classifyProbeError(ErrNotFound) = %q, want CIM_BINARY_MISSING", got)
	}
	// CIM_TIMEOUT — wrapped DeadlineExceeded on the context surfaces.
	expired, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	// Allow the past deadline to register.
	<-expired.Done()
	if got := classifyProbeError(expired, errors.New("anything")); got != "CIM_TIMEOUT" {
		t.Fatalf("classifyProbeError(expired ctx) = %q, want CIM_TIMEOUT", got)
	}
	// CIM_EXEC_FAILED — any other error.
	if got := classifyProbeError(context.Background(), errors.New("boom")); got != "CIM_EXEC_FAILED" {
		t.Fatalf("classifyProbeError(generic) = %q, want CIM_EXEC_FAILED", got)
	}
}

func TestMapWMIPayloadCanonicalFolding(t *testing.T) {
	lastBoot := "2026-05-28T08:15:00Z"
	p := wmiPayload{
		CS: &wmiCS{
			Manufacturer:        "  ContosoCo  ",
			Model:               "  AcmePro 9000  ",
			Domain:              " corp.example.com ",
			PartOfDomain:        true,
			TotalPhysicalMemory: 17179869184, // 16 GiB
		},
		OS: &wmiOS{
			Caption:               "Microsoft Windows 11 Pro",
			Version:               "10.0.22631",
			OSArch:                "64-bit",
			LastBootUpTime:        lastBoot,
			TotalVisibleMemoryKiB: 16777216, // 16 GiB in KiB
			FreePhysicalMemoryKiB: 8388608,  // 8 GiB in KiB
		},
		CPU: &wmiCPU{
			Name:          " Intel(R) Core(TM) i7-12700H ",
			NumberOfCores: 14,
			MaxClockSpeed: 2300,
		},
		BIOS: &wmiBIOS{
			Manufacturer:      "Acme BIOS",
			SMBIOSBIOSVersion: "1.42.0",
		},
		Disks: []wmiDisk{
			{DevicePath: "C:", FileSystem: "NTFS", CapacityBytes: 500_000_000_000, FreeBytes: 250_000_000_000},
		},
		NetworkInterfaces: []wmiNIC{
			{Description: "Intel(R) Wi-Fi 6", MAC: "AA-BB-CC-DD-EE-FF", IPAddresses: []string{"10.0.0.5", ""}},
		},
	}
	hw := Hardware{SchemaVersion: HardwareSchemaVersion}
	mapWMIPayload(&hw, p)

	if hw.Manufacturer != "ContosoCo" || hw.SystemModel != "AcmePro 9000" {
		t.Fatalf("CS fold did not trim: %+v", hw)
	}
	if !hw.DomainJoined || hw.DomainName != "corp.example.com" {
		t.Fatalf("domain fold incorrect: joined=%v domain=%q", hw.DomainJoined, hw.DomainName)
	}
	if hw.RAMTotalBytes != int64(17179869184) {
		t.Fatalf("CS RAM total must win over OS KiB: got %d", hw.RAMTotalBytes)
	}
	if hw.RAMAvailableBytes != int64(8388608)*1024 {
		t.Fatalf("OS free RAM bytes = %d, want %d", hw.RAMAvailableBytes, int64(8388608)*1024)
	}
	if hw.CPUModel != "Intel(R) Core(TM) i7-12700H" || hw.CPUCores != 14 || hw.CPUFrequencyMHz != 2300 {
		t.Fatalf("CPU fold incorrect: %+v", hw)
	}
	if hw.BIOSVendor != "Acme BIOS" || hw.BIOSVersion != "1.42.0" {
		t.Fatalf("BIOS fold incorrect: vendor=%q version=%q", hw.BIOSVendor, hw.BIOSVersion)
	}
	if hw.LastBootAt == nil || !hw.LastBootAt.Equal(time.Date(2026, 5, 28, 8, 15, 0, 0, time.UTC)) {
		t.Fatalf("LastBootAt incorrect: %v", hw.LastBootAt)
	}
	if len(hw.Disks) != 1 || hw.Disks[0].DevicePath != "C:" || hw.Disks[0].MediaType != "UNKNOWN" {
		t.Fatalf("Disk fold incorrect: %+v", hw.Disks)
	}
	if len(hw.NetworkInterfaces) != 1 {
		t.Fatalf("NIC count = %d, want 1", len(hw.NetworkInterfaces))
	}
	nic := hw.NetworkInterfaces[0]
	if nic.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("NIC MAC not normalised: %q", nic.MAC)
	}
	if len(nic.IPAddresses) != 1 || nic.IPAddresses[0] != "10.0.0.5" {
		t.Fatalf("NIC IPAddresses filtered empty string incorrectly: %+v", nic.IPAddresses)
	}
	if nic.InterfaceType != "UNKNOWN" || nic.LinkState != "UNKNOWN" {
		t.Fatalf("NIC enum defaults missing: %+v", nic)
	}
}

func TestMapWMIPayloadDomainWorkgroup(t *testing.T) {
	// PartOfDomain=false (workgroup) must not surface the workgroup
	// label as DomainName — the backend would treat it as a join.
	p := wmiPayload{
		CS: &wmiCS{
			Domain:       "WORKGROUP",
			PartOfDomain: false,
		},
	}
	hw := Hardware{SchemaVersion: HardwareSchemaVersion}
	mapWMIPayload(&hw, p)
	if hw.DomainJoined {
		t.Fatalf("workgroup must not be domain-joined")
	}
	if hw.DomainName != "" {
		t.Fatalf("workgroup label must not become DomainName: %q", hw.DomainName)
	}
}

func TestMapWMIPayloadClampsNegativeSentinels(t *testing.T) {
	p := wmiPayload{
		CPU: &wmiCPU{NumberOfCores: -1, MaxClockSpeed: -1},
		Disks: []wmiDisk{
			{DevicePath: "C:", CapacityBytes: -100, FreeBytes: -1},
		},
	}
	hw := Hardware{SchemaVersion: HardwareSchemaVersion}
	mapWMIPayload(&hw, p)
	if hw.CPUCores != 0 || hw.CPUFrequencyMHz != 0 {
		t.Fatalf("CPU sentinels not clamped: %+v", hw)
	}
	if hw.Disks[0].CapacityBytes != 0 || hw.Disks[0].FreeBytes != 0 {
		t.Fatalf("disk sentinels not clamped: %+v", hw.Disks[0])
	}
}

func TestMapWMIPayloadOSMemoryFallback(t *testing.T) {
	// When CS.TotalPhysicalMemory is zero, OS.TotalVisibleMemoryKiB
	// (in KiB) must back-fill RAMTotalBytes.
	p := wmiPayload{
		CS: &wmiCS{TotalPhysicalMemory: 0},
		OS: &wmiOS{TotalVisibleMemoryKiB: 4194304}, // 4 GiB in KiB
	}
	hw := Hardware{SchemaVersion: HardwareSchemaVersion}
	mapWMIPayload(&hw, p)
	if hw.RAMTotalBytes != int64(4194304)*1024 {
		t.Fatalf("OS fallback RAM = %d, want %d", hw.RAMTotalBytes, int64(4194304)*1024)
	}
}
