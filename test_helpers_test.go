package main

import "net/http"

// newMuxWithTest は既存テスト用の thin shim。CF / GH 系の新 dependency を
// nil / zero value で埋め、旧 signature 相当で呼べるようにする。
// CF / GH endpoint を扱うテストは個別に newMuxWith を直接呼ぶ。
func newMuxWithTest(
	l secretLister,
	iamL iamLister,
	actL saActivityLister,
	projectID, apiKey string,
) *http.ServeMux {
	return newMuxWith(
		l, iamL, actL,
		&fakeSecretValueGetter{},
		cfConfig{accountID: "test-account", storeID: "test-store", tokenSecret: "test-cf-token"},
		ghConfig{org: "test-org", tokenSecret: "test-gh-token"},
		&fakeHTTPDoer{},
		projectID, apiKey,
	)
}
