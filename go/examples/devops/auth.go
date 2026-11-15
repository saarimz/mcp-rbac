// Demo bearer tokens (examples/servers/README.md "Tokens"): compact JWS, HS256 only, iss/aud/exp/nbf/iat/jti, a 1-hour
// maximum lifetime and jti revocation. Same rules as examples/servers/shared/auth.ts and auth.py. A real deployment
// verifies its IdP's JWTs instead.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"regexp"
	"strings"
	"time"
)

const (
	issuer      = "mcp-guard-demo-idp"
	maxLifetime = 3600
	leeway      = 5
)

var b64 = base64.RawURLEncoding.Strict()
var segment = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// mint signs claims (iss, iat, exp = iat+900 and jti are defaulted).
func mint(secret string, claims map[string]any) string {
	now := time.Now().Unix()
	body := map[string]any{"iss": issuer, "iat": now, "exp": now + 900, "jti": randomID()}
	for k, v := range claims {
		body[k] = v
	}
	h, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	p, _ := json.Marshal(body)
	in := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(in))
	return in + "." + b64.EncodeToString(m.Sum(nil))
}

func num(v any) (float64, bool) {
	f, ok := v.(float64)
	return f, ok && !math.IsInf(f, 0) && !math.IsNaN(f)
}

// verify returns the claims, or "" claims and an error code (malformed, alg, signature, claims, issuer, audience,
// exp, iat, expired, not_yet_valid, lifetime, revoked).
func verify(token, secret, audience string, revoked func(string) bool) (map[string]any, string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, "malformed"
	}
	for _, p := range parts {
		if !segment.MatchString(p) {
			return nil, "malformed"
		}
	}
	hb, err1 := b64.DecodeString(parts[0])
	pb, err2 := b64.DecodeString(parts[1])
	sig, err3 := b64.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, "malformed"
	}
	var head map[string]any
	if json.Unmarshal(hb, &head) != nil || head == nil {
		return nil, "malformed"
	}
	if head["alg"] != "HS256" {
		return nil, "alg" // no "none", no alg confusion
	}
	if _, ok := head["crit"]; ok {
		return nil, "alg"
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(sig, m.Sum(nil)) {
		return nil, "signature"
	}
	var claims map[string]any
	d := json.NewDecoder(bytes.NewReader(pb))
	if d.Decode(&claims) != nil || claims == nil {
		return nil, "claims"
	}
	if claims["iss"] != issuer {
		return nil, "issuer"
	}
	audOK := false
	switch a := claims["aud"].(type) {
	case string:
		audOK = a == audience
	case []any:
		for _, x := range a {
			audOK = audOK || x == audience
		}
	}
	if !audOK {
		return nil, "audience"
	}
	exp, ok := num(claims["exp"])
	if !ok {
		return nil, "exp"
	}
	iat, ok := num(claims["iat"])
	if !ok {
		return nil, "iat"
	}
	now := float64(time.Now().UnixMilli()) / 1000
	if exp <= now-leeway {
		return nil, "expired"
	}
	if nbfRaw, has := claims["nbf"]; iat > now+leeway || has && func() bool { n, ok := num(nbfRaw); return !ok || n > now+leeway }() {
		return nil, "not_yet_valid"
	}
	if exp-iat > maxLifetime {
		return nil, "lifetime"
	}
	sub, _ := claims["sub"].(string)
	jti, _ := claims["jti"].(string)
	if sub == "" || jti == "" {
		return nil, "claims"
	}
	if revoked(jti) {
		return nil, "revoked"
	}
	return claims, ""
}

// identityOf maps token claims to an mcp-rbac identity. Actors: outermost `act` first.
func identityOf(c map[string]any) map[string]any {
	id := map[string]any{"id": c["sub"], "roles": []any{}}
	if r, ok := c["roles"].([]any); ok {
		id["roles"] = r
	}
	if s, ok := c["rscope"].(map[string]any); ok {
		id["scope"] = s
	}
	if t, ok := c["tenant"].(string); ok {
		id["tenant"] = t
	}
	if s, ok := c["scope"].(string); ok {
		scopes := []any{} // split on " " exactly like auth.ts / auth.py
		for _, x := range strings.Split(s, " ") {
			if x != "" {
				scopes = append(scopes, x)
			}
		}
		id["scopes"] = scopes
	}
	if s, ok := c["client_id"].(string); ok {
		id["clientId"] = s
	}
	if r, ok := c["org_roles"].([]any); ok {
		id["orgRoles"] = r
	}
	var actors []any
	a, _ := c["act"].(map[string]any)
	for n := 0; a != nil && n < 8; n++ {
		s, ok := a["sub"].(string)
		if !ok {
			break
		}
		actors = append(actors, s)
		a, _ = a["act"].(map[string]any)
	}
	if len(actors) > 0 {
		id["actors"] = actors
	}
	return id
}
