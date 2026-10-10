package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/edr-platform/connection-manager/config"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type revocationFixture struct {
	revoked bool
	err     error
}

func (r *revocationFixture) IsCertRevoked(context.Context, string) (bool, error) {
	return r.revoked, r.err
}
func certContext(id string) context.Context {
	cert := &x509.Certificate{Raw: []byte(id), Subject: pkix.Name{CommonName: id}}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}}})
}

func TestRevocationCacheIsPerCertificateAndRecovers(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	i := NewInterceptor(&config.Config{}, logger, nil, nil)
	check := func(id string, code codes.Code) {
		t.Helper()
		got, err := i.validateClientCertificate(certContext(id))
		if status.Code(err) != code {
			t.Fatalf("%s: %v, want %v", id, err, code)
		}
		if code == codes.OK && got != id {
			t.Fatalf("wrong authenticated identity %q", got)
		}
	}
	check("first", codes.Unavailable) // boot is NOT a successful check
	r := &revocationFixture{}
	i.redis = r
	check("first", codes.OK)
	r.err = errors.New("Redis unavailable")
	check("first", codes.OK)           // recently verified certificate retains bounded grace
	check("second", codes.Unavailable) // another certificate's check cannot grant access
	i.checkedCerts[generateFingerprint([]byte("first"))] = time.Now().Add(-revocationCacheMaxAge - time.Second)
	check("first", codes.Unavailable)
	r.err = nil
	check("first", codes.OK) // recovered Redis clears the outage
	r.revoked = true
	check("first", codes.Unauthenticated)
	r.err = errors.New("Redis unavailable")
	check("first", codes.Unauthenticated) // revocation survives the outage
}

func TestRevocationGraceCacheIsBounded(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	i := NewInterceptor(&config.Config{}, logger, nil, nil)
	for n := 0; n < 4096; n++ {
		i.checkedCerts[time.Unix(int64(n), 0).String()] = time.Now()
	}
	i.redis = &revocationFixture{}
	if _, err := i.validateClientCertificate(certContext("new")); err != nil {
		t.Fatal(err)
	}
	if len(i.checkedCerts) > 4096 {
		t.Fatal("unbounded grace cache")
	}
}
