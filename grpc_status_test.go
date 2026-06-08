package main

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestGrpcToHTTPStatus は gRPC error code → HTTP status の mapping を
// table-driven で検証する (Refs #30)。gRPC error でない素の error が
// 従来互換の 502 に倒れることも合わせて確認する。
func TestGrpcToHTTPStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"PermissionDenied->403", status.Error(codes.PermissionDenied, "x"), http.StatusForbidden},
		{"Unauthenticated->401", status.Error(codes.Unauthenticated, "x"), http.StatusUnauthorized},
		{"NotFound->404", status.Error(codes.NotFound, "x"), http.StatusNotFound},
		{"AlreadyExists->409", status.Error(codes.AlreadyExists, "x"), http.StatusConflict},
		{"InvalidArgument->400", status.Error(codes.InvalidArgument, "x"), http.StatusBadRequest},
		{"DeadlineExceeded->504", status.Error(codes.DeadlineExceeded, "x"), http.StatusGatewayTimeout},
		{"Unavailable->503", status.Error(codes.Unavailable, "x"), http.StatusServiceUnavailable},
		// default に倒れる gRPC code 群はすべて 502。
		{"Internal->502", status.Error(codes.Internal, "x"), http.StatusBadGateway},
		{"Unknown->502", status.Error(codes.Unknown, "x"), http.StatusBadGateway},
		{"Aborted->502", status.Error(codes.Aborted, "x"), http.StatusBadGateway},
		{"ResourceExhausted->502", status.Error(codes.ResourceExhausted, "x"), http.StatusBadGateway},
		// gRPC でない素の error は status.FromError が ok=false → 502。
		{"plain-error->502", errors.New("boom"), http.StatusBadGateway},
		{"wrapped-plain-error->502", fmt.Errorf("ctx: %w", errors.New("boom")), http.StatusBadGateway},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := grpcToHTTPStatus(tc.err)
			if got != tc.want {
				t.Fatalf("grpcToHTTPStatus(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}
