package evidence

import (
	"bytes"
	"encoding/json"
	"html/template"
)

// RenderJSON serializes a Pack for machine consumption (indented for diff/audit
// friendliness).
func RenderJSON(p Pack) ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// RenderHTML renders a self-contained, inline-CSS HTML evidence pack (per Mira's
// "HTML reports over markdown" rule — no external assets, opens anywhere). The
// Integrity Attestation is rendered FIRST and PROMINENTLY: a green PASS banner
// when the chain is intact, a red FAILED banner the instant any trail is broken.
func RenderHTML(p Pack) ([]byte, error) {
	var buf bytes.Buffer
	if err := htmlTmpl.Execute(&buf, p); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// htmlTmpl is parsed once at init. html/template auto-escapes all interpolated
// values, so attacker-controlled audit content (agent/tool/reason strings) can
// never break out into markup.
var htmlTmpl = template.Must(template.New("evidence").Funcs(template.FuncMap{
	"modeUpper": func(m VerifyMode) string {
		if m == ModeEd25519 {
			return "Ed25519 (non-repudiable)"
		}
		return "HMAC-SHA256 (tamper-evident)"
	},
}).Parse(htmlSource))

const htmlSource = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NockGuard Compliance Evidence Pack — {{.FrameworkName}}</title>
<style>
  :root { --ink:#1a1d24; --muted:#5b6472; --line:#e3e7ee; --bg:#f6f8fb;
          --pass:#0f7b46; --pass-bg:#e6f6ec; --fail:#b21f2d; --fail-bg:#fdeced;
          --accent:#1f3a5f; }
  * { box-sizing:border-box; }
  body { margin:0; font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
         color:var(--ink); background:var(--bg); }
  .wrap { max-width:980px; margin:0 auto; padding:40px 28px 80px; }
  header.cover { border-bottom:3px solid var(--accent); padding-bottom:24px; margin-bottom:8px; }
  .brand { font-size:13px; letter-spacing:.14em; text-transform:uppercase; color:var(--accent); font-weight:700; }
  h1 { font-size:28px; margin:6px 0 4px; }
  h2 { font-size:20px; margin:38px 0 14px; padding-bottom:6px; border-bottom:1px solid var(--line); }
  h3 { font-size:16px; margin:24px 0 6px; }
  .meta { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:10px 24px; margin-top:18px; }
  .meta .k { font-size:12px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); }
  .meta .v { font-weight:600; word-break:break-word; }
  .banner { margin:22px 0; padding:18px 22px; border-radius:10px; border:1px solid; display:flex;
            align-items:center; gap:16px; }
  .banner.pass { background:var(--pass-bg); border-color:var(--pass); color:var(--pass); }
  .banner.fail { background:var(--fail-bg); border-color:var(--fail); color:var(--fail); }
  .banner .badge { font-size:26px; font-weight:800; letter-spacing:.04em; }
  .banner .desc { color:var(--ink); font-size:14px; }
  table { width:100%; border-collapse:collapse; margin-top:10px; font-size:14px; background:#fff; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { background:#eef2f8; font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); }
  .ctrl-head { display:flex; align-items:baseline; gap:10px; flex-wrap:wrap; }
  .ctrl-id { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-weight:700; color:var(--accent); }
  .count { background:var(--accent); color:#fff; border-radius:20px; padding:1px 10px; font-size:12px; font-weight:600; }
  .count.zero { background:#9aa4b2; }
  .desc-block { color:var(--muted); font-size:13.5px; margin:2px 0 4px; }
  .pill { display:inline-block; padding:1px 8px; border-radius:4px; font-size:12px; font-weight:600;
          font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .pill.allow { background:#e6f6ec; color:var(--pass); }
  .pill.deny, .pill.block, .pill.approval-denied { background:var(--fail-bg); color:var(--fail); }
  .pill.ratelimit, .pill.hide, .pill.approval-granted { background:#fff4e0; color:#9a5b00; }
  .empty { color:var(--muted); font-style:italic; padding:8px 0; }
  code, .mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .filevr { font-size:13px; }
  .filevr .ok { color:var(--pass); font-weight:600; }
  .filevr .bad { color:var(--fail); font-weight:600; }
  footer { margin-top:50px; padding-top:16px; border-top:1px solid var(--line); color:var(--muted); font-size:12.5px; }
</style>
</head>
<body>
<div class="wrap">

  <header class="cover">
    <div class="brand">NockGuard · Compliance Evidence Pack</div>
    <h1>{{.FrameworkName}}</h1>
    <div class="meta">
      <div><div class="k">Framework</div><div class="v mono">{{.Framework}}</div></div>
      <div><div class="k">Generated</div><div class="v">{{.GeneratedAt}}</div></div>
      <div><div class="k">Agent scope</div><div class="v">{{if .Agent}}{{.Agent}}{{else}}all agents{{end}}</div></div>
      <div><div class="k">Range from</div><div class="v">{{if .From}}{{.From}}{{else}}beginning{{end}}</div></div>
      <div><div class="k">Range to</div><div class="v">{{if .To}}{{.To}}{{else}}now{{end}}</div></div>
      <div><div class="k">Agents in evidence</div><div class="v">{{if .Agents}}{{range $i,$a := .Agents}}{{if $i}}, {{end}}{{$a}}{{end}}{{else}}—{{end}}</div></div>
    </div>
  </header>

  <h2>Integrity Attestation</h2>
  {{with .Verification}}
  {{if .ChainIntact}}
  <div class="banner pass">
    <span class="badge">PASS</span>
    <span class="desc">The signed audit chain is <strong>intact</strong>. {{.EntriesVerified}} entr{{if eq .EntriesVerified 1}}y{{else}}ies{{end}} verified end-to-end via {{modeUpper .Mode}}. No edit, deletion, insertion, or reorder was detected.</span>
  </div>
  {{else}}
  <div class="banner fail">
    <span class="badge">FAILED</span>
    <span class="desc">The signed audit chain is <strong>BROKEN</strong> — this evidence is NOT trustworthy. {{.EntriesVerified}} entr{{if eq .EntriesVerified 1}}y{{else}}ies{{end}} verified before the break. {{if .Detail}}Detail: <span class="mono">{{.Detail}}</span>{{end}}</span>
  </div>
  {{end}}
  <table>
    <tr><th>Mode</th><td>{{modeUpper .Mode}}</td></tr>
    <tr><th>Entries verified</th><td>{{.EntriesVerified}}</td></tr>
    <tr><th>Chain intact</th><td>{{if .ChainIntact}}<span class="pill allow">true</span>{{else}}<span class="pill deny">false</span>{{end}}</td></tr>
    {{if .PubKeyHex}}<tr><th>Public key</th><td class="mono" style="word-break:break-all">{{.PubKeyHex}}</td></tr>{{end}}
    <tr><th>Verified at</th><td>{{.VerifiedAt}}</td></tr>
  </table>
  <h3>Per-file verification</h3>
  <table class="filevr">
    <tr><th>Audit file</th><th>Entries</th><th>Status</th></tr>
    {{range .FileResults}}
    <tr>
      <td class="mono">{{.Path}}</td>
      <td>{{.EntriesVerified}}</td>
      <td>{{if .Intact}}<span class="ok">intact</span>{{else}}<span class="bad">BROKEN — {{.Error}}</span>{{end}}</td>
    </tr>
    {{end}}
  </table>
  {{end}}

  <h2>Control Evidence</h2>
  {{if .Controls}}
  {{range .Controls}}
  <div class="control">
    <div class="ctrl-head">
      <h3 style="margin:18px 0 2px"><span class="ctrl-id">{{.Control.ID}}</span> {{.Control.Name}}</h3>
      <span class="count{{if eq (len .Events) 0}} zero{{end}}">{{len .Events}} event{{if ne (len .Events) 1}}s{{end}}</span>
    </div>
    <div class="desc-block">{{.Control.Description}}</div>
    {{if .Events}}
    <table>
      <tr><th>Timestamp</th><th>Agent</th><th>Tool</th><th>Decision</th><th>Reason</th></tr>
      {{range .Events}}
      <tr>
        <td class="mono">{{.Time}}</td>
        <td>{{.Agent}}</td>
        <td class="mono">{{.Tool}}</td>
        <td><span class="pill {{.Decision}}">{{.Decision}}</span></td>
        <td>{{if .Reason}}{{.Reason}}{{else}}—{{end}}</td>
      </tr>
      {{end}}
    </table>
    {{else}}
    <div class="empty">No matching events in the selected range.</div>
    {{end}}
  </div>
  {{end}}
  {{else}}
  <div class="empty">This framework has no control mappings yet (stub). Add controls in internal/evidence/frameworks.go.</div>
  {{end}}

  <h2>Raw Evidence Appendix</h2>
  <div class="desc-block">Every audit entry in the selected scope, in original file and line order. This is the unbucketed source the control tables draw from.</div>
  {{if .AllEvents}}
  <table>
    <tr><th>Timestamp</th><th>Agent</th><th>Tool</th><th>Decision</th><th>Reason</th></tr>
    {{range .AllEvents}}
    <tr>
      <td class="mono">{{.Time}}</td>
      <td>{{.Agent}}</td>
      <td class="mono">{{.Tool}}</td>
      <td><span class="pill {{.Decision}}">{{.Decision}}</span></td>
      <td>{{if .Reason}}{{.Reason}}{{else}}—{{end}}</td>
    </tr>
    {{end}}
  </table>
  {{else}}
  <div class="empty">No audit entries in the selected scope.</div>
  {{end}}

  <footer>
    Generated by NockGuard — the MCP firewall for AI agent fleets. The Integrity Attestation above is produced by
    the same cryptographic verifier (<span class="mono">nockguard audit verify</span>) that signs the trail; a PASS
    means the chain was checked end-to-end and is unbroken. Align. Decide. Deploy.
  </footer>

</div>
</body>
</html>
`
