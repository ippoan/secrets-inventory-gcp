package main

import (
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// grpcToHTTPStatus は gRPC error の code を HTTP status に mapping する。
//
// 動機 (Refs #30): Secret Manager / IAM Admin を gRPC で叩く handler は
// 従来 upstream error を一律 502 (StatusBadGateway) で包んでいたため、
// PermissionDenied / NotFound / InvalidArgument / DeadlineExceeded が全部
// 502 に潰れ、原因切り分けに毎回 Cloud Logging が要った。code を HTTP status
// に対応付けて caller (= 親 worker) 側でも一次切り分けできるようにする。
//
// gRPC error でない場合 (status.FromError が ok=false、例えば素の errors.New)
// は従来互換で 502 を返す。response body 自体は呼び出し側で generic 文字列に
// 固定し、値や error 詳細は echo しない方針を維持する。
func grpcToHTTPStatus(err error) int {
	st, ok := status.FromError(err)
	if !ok {
		return http.StatusBadGateway
	}
	switch st.Code() {
	case codes.PermissionDenied:
		return http.StatusForbidden // 403
	case codes.Unauthenticated:
		return http.StatusUnauthorized // 401
	case codes.NotFound:
		return http.StatusNotFound // 404
	case codes.AlreadyExists:
		return http.StatusConflict // 409
	case codes.InvalidArgument:
		return http.StatusBadRequest // 400
	case codes.DeadlineExceeded:
		return http.StatusGatewayTimeout // 504
	case codes.Unavailable:
		return http.StatusServiceUnavailable // 503
	default:
		// Internal / Unknown / その他、および codes.OK (= err==nil 前提なので
		// 通常ここには来ないが念のため) は現状互換の 502 に倒す。
		return http.StatusBadGateway
	}
}
