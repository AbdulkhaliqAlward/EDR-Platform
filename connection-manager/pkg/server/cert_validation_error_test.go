package server

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCertValidationError(t *testing.T) {
	tests := []struct {
		name string
		in   error
		want codes.Code
	}{
		{"revocation check unavailable stays retryable", status.Error(codes.Unavailable, "certificate revocation check unavailable — try again later"), codes.Unavailable},
		{"revoked certificate is rejected", status.Error(codes.Unauthenticated, "certificate revoked"), codes.Unauthenticated},
		{"missing chain is rejected", status.Error(codes.Unauthenticated, "no verified certificate chain"), codes.Unauthenticated},
		{"plain error is rejected", errors.New("bad cert"), codes.Unauthenticated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := status.Code(certValidationError(tt.in)); got != tt.want {
				t.Errorf("certValidationError(%v) code = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
