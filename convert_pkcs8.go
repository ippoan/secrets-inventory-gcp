package main

import (
	cloudrunproxy "github.com/ippoan/go-cloudrun-proxy"

	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// `POST /convert-pkcs8/{src}?dst_name=NAME&targets=gcp,gh&gh_name=NAME`
//
// GCP Secret Manager にある RSA 秘密鍵 (PKCS#1 形式、= GitHub App が download
// させる `-----BEGIN RSA PRIVATE KEY-----` 鍵) を **PKCS#8** に変換し、
// **別名 dst_name** の secret として GCP に作成 (既存なら新 version を投入) し、
// 任意で GitHub Actions org secret にも propagate する。
//
// 動機:
//   `actions/create-github-app-token@v2` は内部で WebCrypto を使い、private key
//   が PKCS#8 (`-----BEGIN PRIVATE KEY-----`) でないと "Invalid keyData" で
//   落ちる。GitHub が App 用に download させる鍵は PKCS#1 なので変換が要る。
//
// 値の物理経路:
//   GCP Secret Manager (src) → proxy memory で PEM 変換 → GCP (dst) / GitHub
//   呼び出し元 (worker) も LLM context も値を一度も見ない。proxy 内で完結。
//
// src 読み出しは sync-from-gcp と同じ srcGetter (TTL ≤ 10 分の self temp-grant
// accessor) を使う。dst 書き込みは create-secret と同じ secretLister
// (secretCreator + secretVersionAdder) を再利用する。

// convertPkcs1ToPkcs8 は PEM の RSA 秘密鍵を PKCS#1 → PKCS#8 に変換する。
// 既に PKCS#8 (`PRIVATE KEY`) ならそのまま返す (idempotent)。値は返り値として
// のみ扱い、log には絶対に出さない。
func convertPkcs1ToPkcs8(in []byte) (out []byte, converted bool, err error) {
	block, _ := pem.Decode(in)
	if block == nil {
		return nil, false, fmt.Errorf("input is not a PEM block")
	}
	switch block.Type {
	case "PRIVATE KEY":
		// 既に PKCS#8。passthrough (idempotent)。
		return in, false, nil
	case "RSA PRIVATE KEY":
		key, perr := x509.ParsePKCS1PrivateKey(block.Bytes)
		if perr != nil {
			return nil, false, fmt.Errorf("parse pkcs1: %w", perr)
		}
		der, merr := x509.MarshalPKCS8PrivateKey(key)
		if merr != nil {
			return nil, false, fmt.Errorf("marshal pkcs8: %w", merr)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), true, nil
	default:
		return nil, false, fmt.Errorf("unsupported PEM type %q (want RSA PRIVATE KEY or PRIVATE KEY)", block.Type)
	}
}

type convertPkcs8Response struct {
	Ok        bool                        `json:"ok"`
	Source    string                      `json:"source"`
	DstName   string                      `json:"dst_name"`
	Converted bool                        `json:"converted"` // false = source was already PKCS#8 (passthrough)
	Results   map[string]syncTargetResult `json:"results"`
}

func handleConvertPkcs8(
	l secretLister,
	srcGetter secretValueGetter,
	valueGetter secretValueGetter,
	ghCfg ghConfig,
	httpClient httpDoer,
	projectID string,
) http.Handler {
	if srcGetter == nil {
		srcGetter = valueGetter
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		srcName := strings.TrimPrefix(r.URL.Path, "/convert-pkcs8/")
		if srcName == "" || strings.Contains(srcName, "/") || !secretNamePattern.MatchString(srcName) {
			http.Error(w, "invalid src name", http.StatusBadRequest)
			return
		}
		q := r.URL.Query()
		dstName := q.Get("dst_name")
		if dstName == "" || !secretNamePattern.MatchString(dstName) {
			http.Error(w, "invalid or missing dst_name", http.StatusBadRequest)
			return
		}
		if dstName == srcName {
			http.Error(w, "dst_name must differ from src (use a new name to keep the PKCS#1 original intact)", http.StatusBadRequest)
			return
		}

		// targets: default "gcp"。変換結果は必ず GCP に dst_name で残すため gcp 必須。
		wantGcp, wantGh := true, false
		if raw := strings.TrimSpace(q.Get("targets")); raw != "" {
			wantGcp = false
			for _, t := range strings.Split(raw, ",") {
				switch strings.TrimSpace(t) {
				case "gcp":
					wantGcp = true
				case "gh":
					wantGh = true
				case "":
					// trailing comma
				default:
					http.Error(w, "invalid targets (only gcp/gh allowed)", http.StatusBadRequest)
					return
				}
			}
		}
		if !wantGcp {
			http.Error(w, "targets must include gcp", http.StatusBadRequest)
			return
		}
		if wantGh && !ghCfg.configured() {
			http.Error(w, "gh target requested but GitHub config is missing", http.StatusServiceUnavailable)
			return
		}
		ghName := q.Get("gh_name")
		if ghName == "" {
			ghName = dstName
		}
		if wantGh && !secretNamePattern.MatchString(ghName) {
			http.Error(w, "invalid gh_name", http.StatusBadRequest)
			return
		}

		actor := sanitizeLogValue(r.Header.Get("X-Actor-Email"))
		log.Printf("CONVERT_PKCS8 requested actor=%q src=%q dst=%q gcp=%v gh=%v gh_name=%q",
			actor, sanitizeLogValue(srcName), sanitizeLogValue(dstName), wantGcp, wantGh,
			sanitizeLogValue(ghName))

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		// 1. read source (PKCS#1 PEM) via temp-grant accessor。
		value, err := srcGetter.Get(ctx, srcName)
		if err != nil {
			log.Printf("CONVERT_PKCS8 source read failed actor=%q src=%q err=%v",
				actor, sanitizeLogValue(srcName), err)
			http.Error(w, "upstream error (gcp read)", cloudrunproxy.StatusFromGRPC(err))
			return
		}
		if value == "" {
			log.Printf("CONVERT_PKCS8 source empty actor=%q src=%q", actor, sanitizeLogValue(srcName))
			http.Error(w, "upstream error (empty source)", http.StatusBadGateway)
			return
		}

		// 2. convert PKCS#1 -> PKCS#8 (idempotent)。値は log に出さない。
		pkcs8, converted, err := convertPkcs1ToPkcs8([]byte(value))
		if err != nil {
			log.Printf("CONVERT_PKCS8 convert failed actor=%q src=%q err=%v",
				actor, sanitizeLogValue(srcName), err)
			http.Error(w, fmt.Sprintf("convert failed: %v", err), http.StatusBadRequest)
			return
		}

		results := map[string]syncTargetResult{}
		ok := true

		// 3. write to GCP under dst_name (create、既存なら version-up)。
		parent := fmt.Sprintf("projects/%s", projectID)
		fullName, alreadyExists, cerr := l.CreateSecret(ctx, parent, dstName)
		if cerr != nil {
			log.Printf("CONVERT_PKCS8 gcp create failed actor=%q dst=%q err=%v",
				actor, sanitizeLogValue(dstName), cerr)
			results["gcp"] = syncTargetResult{Status: "fail", Error: "gcp create"}
			ok = false
		} else {
			ver, aerr := l.AddSecretVersion(ctx, fullName, pkcs8)
			if aerr != nil {
				log.Printf("CONVERT_PKCS8 gcp add-version failed actor=%q dst=%q err=%v",
					actor, sanitizeLogValue(dstName), aerr)
				results["gcp"] = syncTargetResult{Status: "fail", Error: "gcp add-version"}
				ok = false
			} else {
				results["gcp"] = syncTargetResult{Status: "ok", SecretName: dstName, Created: !alreadyExists}
				log.Printf("CONVERT_PKCS8 gcp ok actor=%q dst=%q created=%v new_version=%q",
					actor, sanitizeLogValue(dstName), !alreadyExists, sanitizeLogValue(ver))
			}
		}

		// 4. optional GitHub propagate (upsert: fail_if_exists=false)。
		if wantGh {
			gr := propagateToGh(ctx, ghName, string(pkcs8), "all", false,
				ghCfg, valueGetter, httpClient, actor)
			results["gh"] = gr
			if gr.Status != "ok" {
				ok = false
			}
		}

		// value / pkcs8 は scope を抜けて GC に任せる (zeroize 標準 API は無い)。
		_ = value
		_ = pkcs8

		log.Printf("CONVERT_PKCS8 done actor=%q src=%q dst=%q converted=%v ok=%v",
			actor, sanitizeLogValue(srcName), sanitizeLogValue(dstName), converted, ok)
		w.Header().Set("Content-Type", "application/json")
		status := http.StatusOK
		if !ok {
			status = http.StatusBadGateway
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(convertPkcs8Response{
			Ok:        ok,
			Source:    srcName,
			DstName:   dstName,
			Converted: converted,
			Results:   results,
		})
	})
}
