package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// SigningKeyEnvNames must return whatever the policy NAMES as the signing env
// var(s) — the seed-isolation strip is config-driven, not a hardcoded variable
// name. Ed25519 and HMAC names are both returned when configured.
func TestSigningKeyEnvNames(t *testing.T) {
	write := func(t *testing.T, body string) *Engine {
		t.Helper()
		path := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		e, err := Load(path)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		return e
	}

	cases := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "ed25519 custom name",
			body: "agents:\n  kit:\n    allow: [\"*\"]\naudit:\n  enabled: true\n  sign_ed25519_key_env: MY_CUSTOM_SEED_VAR\n",
			want: []string{"MY_CUSTOM_SEED_VAR"},
		},
		{
			name: "hmac custom name",
			body: "agents:\n  kit:\n    allow: [\"*\"]\naudit:\n  enabled: true\n  sign_key_env: MY_HMAC_VAR\n",
			want: []string{"MY_HMAC_VAR"},
		},
		{
			name: "both configured",
			body: "agents:\n  kit:\n    allow: [\"*\"]\naudit:\n  enabled: true\n  sign_ed25519_key_env: SEED_VAR\n  sign_key_env: HMAC_VAR\n",
			want: []string{"SEED_VAR", "HMAC_VAR"},
		},
		{
			name: "no audit block",
			body: "agents:\n  kit:\n    allow: [\"*\"]\n",
			want: nil,
		},
		{
			name: "audit without signing",
			body: "agents:\n  kit:\n    allow: [\"*\"]\naudit:\n  enabled: true\n",
			want: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := write(t, tc.body).SigningKeyEnvNames()
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}
