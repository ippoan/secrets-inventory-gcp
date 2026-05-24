package main

import (
	"io"
	"net/http"
	"strings"
	"sync"
)

// fakeHTTPDoer は httpDoer の test 用 fake。`responder` で req → resp の
// マッピングを fully 制御する。本物の network 呼び出しを一切しない。
//
// 簡易使い方:
//
//	doer := &fakeHTTPDoer{}
//	doer.respond("GET https://api.example.com/foo", 200, `{"ok":true}`)
//	doer.respond("POST https://api.example.com/bar", 204, "")
//
// 呼ばれなかった req は `doer.calls` で確認できる。
type fakeHTTPDoer struct {
	mu        sync.Mutex
	responses map[string]fakeResponse
	calls     []*http.Request
}

type fakeResponse struct {
	status int
	body   string
}

func (f *fakeHTTPDoer) respond(key string, status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.responses == nil {
		f.responses = map[string]fakeResponse{}
	}
	f.responses[key] = fakeResponse{status: status, body: body}
}

func (f *fakeHTTPDoer) Do(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.calls = append(f.calls, req)
	key := req.Method + " " + req.URL.String()
	resp, ok := f.responses[key]
	f.mu.Unlock()
	if !ok {
		// match 失敗時は 599 を返して test を fail させる (= responder 漏れの
		// 露呈)。caller が body を読む path を担保する。
		return &http.Response{
			StatusCode: 599,
			Body:       io.NopCloser(strings.NewReader("no fake response for " + key)),
			Header:     make(http.Header),
		}, nil
	}
	return &http.Response{
		StatusCode: resp.status,
		Body:       io.NopCloser(strings.NewReader(resp.body)),
		Header:     make(http.Header),
	}, nil
}
