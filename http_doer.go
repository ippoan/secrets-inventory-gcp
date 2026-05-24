package main

import (
	"net/http"
	"regexp"
)

// httpDoer は `*http.Client` の interface 抽象化。test では fake transport を
// 差し込んで CF / GitHub API call をモックする。production は default の
// `http.DefaultClient` を使う。
//
// `Do` 1 method の最小 surface に絞っており、`Get` / `Post` 等の sugar は
// 提供しない (= handler 側で常に `http.NewRequestWithContext` を組み立てる
// 規約に従わせる)。
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// mustCompile は regexp.MustCompile の薄い alias。`var _ = mustCompile(...)`
// で global pattern 定義に使う。
func mustCompile(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}
