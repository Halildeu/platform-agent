package harness

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"

	"platform-agent/internal/remotebridge/operation"
	pb "platform-agent/internal/remotebridge/pb"
	"platform-agent/internal/remotebridge/ptyexec"
)

type noopPTYDispatcher struct{}

func (noopPTYDispatcher) Handle(context.Context, operation.OperationPermit, string, string,
	func(*pb.DataFrame) error, int64) (ptyexec.ExecResult, error) {
	return ptyexec.ExecResult{}, nil
}

func TestOperationDispatchRequiresOutboundMTLSClientCert(t *testing.T) {
	_, err := New(Config{
		BrokerAddr:       "broker.example.com:443",
		DeviceIDProvider: func() string { return "device" },
		PTYDispatcher:    noopPTYDispatcher{},
	}, nil)
	if err == nil {
		t.Fatal("operation-capable remote bridge must require outbound mTLS client certificate material")
	}
	if !strings.Contains(err.Error(), "mTLS client certificate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOperationDispatchRejectsPlaintextEvenOnLoopback(t *testing.T) {
	_, err := New(Config{
		BrokerAddr:        "127.0.0.1:9444",
		InsecurePlaintext: true,
		DeviceIDProvider:  func() string { return "device" },
		PTYDispatcher:     noopPTYDispatcher{},
	}, nil)
	if err == nil {
		t.Fatal("operation-capable remote bridge must not run over plaintext")
	}
	if !strings.Contains(err.Error(), "requires TLS/mTLS") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOperationDispatchAllowsClientCertProvider(t *testing.T) {
	h, err := New(Config{
		BrokerAddr:       "broker.example.com:443",
		DeviceIDProvider: func() string { return "device" },
		PTYDispatcher:    noopPTYDispatcher{},
		TLSConfig: &tls.Config{
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return &tls.Certificate{}, nil
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("operation-capable remote bridge with client cert provider must be allowed: %v", err)
	}
	if h == nil {
		t.Fatal("nil harness")
	}
}

func TestOperationDispatchRejectsInsecureSkipVerify(t *testing.T) {
	_, err := New(Config{
		BrokerAddr:       "broker.example.com:443",
		DeviceIDProvider: func() string { return "device" },
		TLSConfig:        &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // deliberate negative test.
	}, nil)
	if err == nil {
		t.Fatal("TLS config with InsecureSkipVerify must be rejected")
	}
	if !strings.Contains(err.Error(), "InsecureSkipVerify") {
		t.Fatalf("unexpected error: %v", err)
	}
}
