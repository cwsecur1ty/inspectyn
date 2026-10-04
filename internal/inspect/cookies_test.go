package inspect

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestCaptureCookiesRetainsAttributesWithoutSecrets(t *testing.T) {
	ob := CaptureCookies(http.Header{"Set-Cookie": {
		"__Host-session=VERY_SECRET_SESSION; Secure; HttpOnly; Path=/; SameSite=Lax",
		"preference=VERY_SECRET_PREFERENCE; Secure; SameSite=None; Domain=private-domain.example; Path=/private-path; Partitioned; Priority=High",
		"plain=VERY_SECRET_PLAIN; Expires=Wed, 21 Oct 2037 07:28:00 GMT",
	}})
	if ob.Status != "ok" || ob.Total != 3 || ob.Invalid != 0 || len(ob.Items) != 3 {
		t.Fatalf("unexpected cookie summary: %#v", ob)
	}
	if got := ob.Items[0]; got.Index != 1 || got.Name != "__Host-session" || !got.Secure || !got.HTTPOnly || !got.PathRoot || got.DomainScoped || got.SameSite != "lax" {
		t.Fatalf("host cookie attributes: %#v", got)
	}
	if got := ob.Items[1]; !got.DomainScoped || got.PathRoot || !got.Partitioned || got.SameSite != "none" {
		t.Fatalf("scoped cookie attributes: %#v", got)
	}
	if ob.Items[2].SameSite != "unspecified" {
		t.Fatal("missing SameSite must be distinguished from a rejected value")
	}
	encoded, err := json.Marshal(ob)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"VERY_SECRET", "private-domain", "private-path", "Expires=", "Set-Cookie", "Priority=High"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("cookie output contains excluded data: %s", secret)
		}
	}
}

func TestCaptureCookiesRejectsAmbiguousAttributes(t *testing.T) {
	for _, raw := range []string{
		"missing-equals",
		"session=one; Secure; secure",
		"session=one; HttpOnly; HTTPONLY",
		"session=one; SameSite=Lax; SameSite=None",
		"session=one; Domain=example.com; DOMAIN=sub.example.com",
		"session=one; Path=/; Path=/private",
		"session=one; Partitioned; partitioned",
		"session=one; SameSite=Unexpected",
		"session=one; SameSite",
		"session=one; Secure =true",
		"session=one; Secure=\"invalid\"",
		"session=one; Domain=invalid_domain.example",
		"session=one; Domain=",
		"session=one; Path",
		"session=one, second=two; Secure",
		"session=one; Expires=Wed, 21 Oct 2037 07:28:00 GMT, second=two",
		strings.Repeat("x", 257) + "=one; Secure",
		"session=" + strings.Repeat("v", 4096),
	} {
		t.Run(fmt.Sprintf("case-%d", len(raw))+"/"+strings.Split(raw, ";")[0], func(t *testing.T) {
			ob := CaptureCookies(http.Header{"Set-Cookie": {raw, "safe=two; Secure; HttpOnly; SameSite=Strict"}})
			if ob.Status != "error" || ob.Total != 2 || ob.Invalid != 1 || len(ob.Items) != 1 || ob.Items[0].Index != 2 || ob.Items[0].Name != "safe" {
				t.Fatalf("ambiguous field was not isolated: %#v", ob)
			}
		})
	}
}

func TestCaptureCookiesLimitsAndMixedHeaderCase(t *testing.T) {
	headers := http.Header{"set-cookie": {}, "Set-Cookie": {strings.Repeat("n", 256) + "=first; Secure"}}
	for i := 0; i < 64; i++ {
		headers["set-cookie"] = append(headers["set-cookie"], fmt.Sprintf("cookie%d=value; Secure", i))
	}
	ob := CaptureCookies(headers)
	if ob.Total != 65 || ob.Invalid != 1 || ob.Status != "error" || len(ob.Items) != 64 {
		t.Fatalf("cookie limit summary: %#v", ob)
	}
	if len(ob.Items[0].Name) != 256 {
		t.Fatal("maximum length cookie name was rejected")
	}
	if len(headers["set-cookie"]) != 64 {
		t.Fatal("input mutated")
	}
	empty := CaptureCookies(nil)
	if empty.Status != "ok" || empty.Total != 0 || empty.Invalid != 0 || empty.Items == nil {
		t.Fatalf("empty response cookies: %#v", empty)
	}
}

func TestCaptureCookiesExtensionAttributesRemainBenign(t *testing.T) {
	ob := CaptureCookies(http.Header{"Set-Cookie": {"session=value; Secure; HttpOnly; SameSite=sTrIcT; Priority=High; FutureExtension=arbitrary; FutureExtension=more; Expires=invalid; Max-Age=invalid"}})
	if ob.Status != "ok" || len(ob.Items) != 1 || ob.Items[0].SameSite != "strict" {
		t.Fatalf("extension attributes incorrectly invalidate metadata: %#v", ob)
	}
}

func TestCaptureCookiesFlagAssignmentsMeanPresence(t *testing.T) {
	ob := CaptureCookies(http.Header{"Set-Cookie": {"session=value; Secure=false; HttpOnly=0; SameSite=Lax; Domain=.example.com; Path=/; Max-Age=0"}})
	if ob.Status != "ok" || len(ob.Items) != 1 || !ob.Items[0].Secure || !ob.Items[0].HTTPOnly || !ob.Items[0].DomainScoped {
		t.Fatalf("flag presence should not interpret an assigned boolean: %#v", ob)
	}
}
