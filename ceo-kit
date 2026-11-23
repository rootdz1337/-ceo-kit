// ceo-kit.go — Business Email Compromise (BEC) reference kit.
//
// Build:  go build -o ceo-kit ceo-kit.go
// Run:    ./ceo-kit -campaign ACME-BEC-01 -out ./build
//
// The kit generates the *social-engineering* layer of a BEC simulation:
// a spoofed executive email, a threaded reply chain, a lure PDF, and the
// detection rules a SOC needs. It does not send anything. Delivery is a
// separate, human step covered by the consent file.
//
// MITRE: T1566.001 (phishing), T1585.002 (email accounts), T1656 (impersonation)
//
// Use only on systems and people covered by a signed engagement scope.

package main

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net/textproto"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

type Config struct {
	Campaign    string
	Client      string
	CEO         Executive
	CFO         Executive
	Target      Executive
	Scenario    string // wire | giftcard | payroll | w2 | invoice
	Amount      string
	BankName    string
	BankAcct    string
	BankRouting string
	Callback    string // phone number the target is asked to call
	OutDir      string
	URGENCY     string // low | normal | high | extreme
	Notes       string
}

type Executive struct {
	Name     string
	Title    string
	Email    string
	Phone    string
	Timezone string
	Assistant string
}

// ---------------------------------------------------------------------------
// Scenario definitions — each is a real, documented BEC pattern.
// ---------------------------------------------------------------------------

type ScenarioSpec struct {
	ID          string
	Name        string
	MITRE       string
	SubjectTmpl string
	BodyTmpl    string
	Indicators  []string
}

var scenarios = map[string]ScenarioSpec{
	"wire": {
		ID:    "wire",
		Name:  "CEO urgent wire transfer",
		MITRE: "T1656, T1566.001",
		SubjectTmpl: "Re: Acquisition wire — {{.Amount}} — URGENT",
		BodyTmpl: `{{.Target.First}},

I'm in a board meeting and can't take calls. We're closing the
{{.BankName}} acquisition today and legal needs the wire out before
5pm {{.Target.Timezone}}.

Please send {{.Amount}} to:

  Bank:    {{.BankName}}
  Account: {{.BankAcct}}
  Routing: {{.BankRouting}}
  Ref:     {{.Campaign}}-CLOSE

Reply with the confirmation once it's out. Do NOT discuss this with
anyone outside this thread — it's still under NDA until Monday.

Sent from my iPhone`,
		Indicators: []string{
			"executive display name != envelope from",
			"reply-to differs from from",
			"urgency + secrecy + wire in one email",
			"bank details in body, not attachment",
		},
	},
	"giftcard": {
		ID:    "giftcard",
		Name:  "CEO gift card request",
		MITRE: "T1656",
		SubjectTmpl: "Quick favor — need this before EOD",
		BodyTmpl: `{{.Target.First}},

I'm stuck in back-to-back meetings and need a quick favor. Can you
grab {{.Amount}} in {{.BankName}} gift cards for a client thank-you?
I'll reimburse you today — just need the codes sent back here.

Keep this between us for now, the client is sensitive.

Thanks,
{{.CEO.Name}}`,
		Indicators: []string{
			"gift card request from executive",
			"reimbursement promise",
			"secrecy request",
			"codes requested via email reply",
		},
	},
	"payroll": {
		ID:    "payroll",
		Name:  "Payroll diversion",
		MITRE: "T1656, T1585.002",
		SubjectTmpl: "Update direct deposit before Friday",
		BodyTmpl: `Hi Payroll,

Please update my direct deposit to the new account below, effective
this pay period. My old account is being closed.

  Bank:    {{.BankName}}
  Account: {{.BankAcct}}
  Routing: {{.BankRouting}}

Please confirm once updated. I'm traveling and may be slow to reply.

{{.Target.Name}}
{{.Target.Title}}`,
		Indicators: []string{
			"direct deposit change via email",
			"no callback number",
			"executive traveling excuse",
		},
	},
	"w2": {
		ID:    "w2",
		Name:  "W-2 / tax document request",
		MITRE: "T1656, T1530",
		SubjectTmpl: "Need W-2s for the {{.Client}} audit",
		BodyTmpl: `{{.Target.First}},

Our external auditors need the full W-2 export for the {{.Client}}
audit by end of day. Please send the PDF bundle to the secure drop
below — it's the auditors' portal, not ours.

  {{.BankName}}

Do not CC anyone from finance; they're the ones being audited.

{{.CEO.Name}}`,
		Indicators: []string{
			"W-2 / PII request from executive",
			"external 'secure drop' URL",
			"do not CC finance",
			"end-of-day urgency",
		},
	},
	"invoice": {
		ID:    "invoice",
		Name:  "Vendor invoice redirection",
		MITRE: "T1656, T1585.002",
		SubjectTmpl: "Updated remittance details — {{.Client}}",
		BodyTmpl: `Hi Accounts Payable,

Please update our remittance details for all future invoices. We've
migrated to a new bank and the old account is closing end of month.

  Bank:    {{.BankName}}
  Account: {{.BankAcct}}
  Routing: {{.BankRouting}}

Attached is the revised W-9 and a sample invoice with the new
details. Please confirm receipt.

Regards,
{{.CEO.Name}}
{{.CEO.Title}}, {{.Client}}`,
		Indicators: []string{
			"vendor bank change via email",
			"executive signature on vendor email",
			"attachment asks to be opened",
		},
	},
}

// ---------------------------------------------------------------------------
// Email builder — produces a valid MIME message with the spoofing details a
// BEC operator relies on: display name vs envelope from, reply-to divergence,
// a References/In-Reply-To chain so it threads as a reply, and an X-Mailer
// header matching the claimed client.
// ---------------------------------------------------------------------------

type emailPart struct {
	header textproto.MIMEHeader
	body   []byte
}

func buildEmail(c Config, spec ScenarioSpec, body string) []byte {
	var buf bytes.Buffer
	h := textproto.MIMEHeader{}

	// Spoofed envelope from (the actual SMTP MAIL FROM is set by the
	// delivery tool, not this header — the difference is the attack).
	h.Set("From", fmt.Sprintf(`"%s" <%s>`, c.CEO.Name, c.CEO.Email))
	h.Set("To", fmt.Sprintf(`"%s" <%s>`, c.Target.Name, c.Target.Email))
	h.Set("Subject", renderTemplate(spec.SubjectTmpl, c))
	h.Set("Date", time.Now().Format(time.RFC1123Z))
	h.Set("Message-ID", fmt.Sprintf("<%s@%s>",
		randomHex(12), domainOf(c.CEO.Email)))
	h.Set("MIME-Version", "1.0")

	// Reply-To divergence — the whole point of BEC. Replies go to a
	// lookalike domain the operator controls, not the real CEO mailbox.
	replyDomain := lookalike(c.CEO.Email)
	h.Set("Reply-To", fmt.Sprintf(`"%s" <%s>`, c.CEO.Name, replyDomain))

	// Threaded reply — In-Reply-To referencing a fake prior message
	h.Set("References", fmt.Sprintf("<%s@%s>", randomHex(10), domainOf(c.CEO.Email)))
	h.Set("In-Reply-To", fmt.Sprintf("<%s@%s>", randomHex(10), domainOf(c.CEO.Email)))

	// Mailer matching the claimed client
	switch {
	case strings.Contains(strings.ToLower(c.CEO.Email), "gmail"):
		h.Set("X-Mailer", "Apple Mail (2.3654.120.0.1.12)")
	case strings.Contains(strings.ToLower(c.CEO.Email), "outlook"), strings.Contains(strings.ToLower(c.CEO.Email), "microsoft"):
		h.Set("X-Mailer", "Microsoft Outlook 16.0")
	default:
		h.Set("X-Mailer", "Apple Mail")
	}

	// X-Priority high — some clients sort it to the top
	if c.URGENCY == "extreme" || c.URGENCY == "high" {
		h.Set("X-Priority", "1 (Highest)")
		h.Set("Importance", "High")
	}

	// Body — text/plain quoted-printable (matches real executive mail)
	var qpBody bytes.Buffer
	qp := quotedprintable.NewWriter(&qpBody)
	qp.Write([]byte(body))
	qp.Close()

	h.Set("Content-Type", `text/plain; charset="utf-8"`)
	h.Set("Content-Transfer-Encoding", "quoted-printable")

	// Serialize header
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&buf, "%s: %s\r\n", k, h.Get(k))
	}
	buf.WriteString("\r\n")
	buf.Write(qpBody.Bytes())
	return buf.Bytes()
}

func domainOf(email string) string {
	i := strings.LastIndex(email, "@")
	if i < 0 {
		return "example.com"
	}
	return email[i+1:]
}

// lookalike turns ceo@acme.com into ceo@acme-corp.com — same display name,
// different domain. This is what victims miss.
func lookalike(email string) string {
	i := strings.LastIndex(email, "@")
	if i < 0 {
		return email
	}
	local, domain := email[:i], email[i+1:]
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) != 2 {
		return email
	}
	suffix := parts[0] + "-" + parts[1]
	return local + "@" + suffix
}

// ---------------------------------------------------------------------------
// Threaded conversation — three emails that look like a real reply chain.
// The kit emits all three so the operator can test whether the target's
// mail client collapses them into a single thread (it will).
// ---------------------------------------------------------------------------

func buildThread(c Config, spec ScenarioSpec, body string) [][]byte {
	// Email 1: the "prior" internal email (innocuous)
	prior := Config(c)
	prior.CEO = c.CFO // CFO initiates
	prior.Target = c.CEO
	priorEmail := buildPriorEmail(prior, c)

	// Email 2: the CEO's "reply" (the actual BEC)
	becEmail := buildEmail(c, spec, body)

	// Email 3: the "follow-up" nudge
	follow := Config(c)
	follow.URGENCY = "extreme"
	followBody := fmt.Sprintf(`{{.Target.First}} — just circling back on this.
Legal is waiting. Can you confirm the wire is out?
`, "")
	followBody = renderTemplate(followBody, follow)
	followEmail := buildEmail(follow, spec, followBody)

	return [][]byte{priorEmail, becEmail, followEmail}
}

func buildPriorEmail(c Config, orig Config) []byte {
	var buf bytes.Buffer
	body := fmt.Sprintf(`%s,

Confirming we're still on for the close this afternoon. I'll loop
%s in if we need the wire initiated today.

Thanks,
%s
`, c.Target.First(), orig.CEO.First(), c.CEO.Name)

	h := textproto.MIMEHeader{}
	h.Set("From", fmt.Sprintf(`"%s" <%s>`, c.CEO.Name, c.CEO.Email))
	h.Set("To", fmt.Sprintf(`"%s" <%s>`, c.Target.Name, c.Target.Email))
	h.Set("Subject", "Acquisition close — this afternoon")
	h.Set("Date", time.Now().Add(-2*time.Hour).Format(time.RFC1123Z))
	h.Set("Message-ID", fmt.Sprintf("<%s@%s>", randomHex(12), domainOf(c.CEO.Email)))
	h.Set("MIME-Version", "1.0")
	h.Set("Content-Type", `text/plain; charset="utf-8"`)

	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&buf, "%s: %s\r\n", k, h.Get(k))
	}
	buf.WriteString("\r\n")
	buf.WriteString(body)
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// Wire-instruction PDF — the "bank details" document attached to the thread.
// Unlike the pdf-kit, this one has no /Launch or JS; it's a pure social lure.
// The malicious variants are in pdf-kit; this kit is the *legitimate-looking*
// companion.
// ---------------------------------------------------------------------------

func buildWirePDF(c Config) []byte {
	d := newPDF()

	fontNum := d.alloc([]byte("<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>"))
	boldNum := d.alloc([]byte("<</Type/Font/Subtype/Type1/BaseFont/Helvetica-Bold>>"))

	lines := []string{
		fmt.Sprintf("%s — Wire Instructions", c.Client),
		"",
		"Beneficiary:  " + c.BankName,
		"Account:      " + c.BankAcct,
		"Routing:      " + c.BankRouting,
		"Amount:       " + c.Amount,
		"Reference:    " + c.Campaign + "-CLOSE",
		"",
		"Questions: " + c.Callback,
		"",
		"Confidential — do not forward.",
	}
	var content bytes.Buffer
	content.WriteString("BT\n")
	y := 720
	for i, line := range lines {
		font := "F1"
		size := 12
		if i == 0 {
			font = "F2"
			size = 16
		}
		fmt.Fprintf(&content, "/%s %d Tf 72 %d Td (%s) Tj\n", font, size, y, esc(line))
		y -= size + 6
	}
	content.WriteString("ET\n")
	contentNum := d.allocStream([]byte{}, content.Bytes())

	pageNum := d.alloc([]byte(fmt.Sprintf(
		"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents %d 0 R/Resources<</Font<</F1 %d 0 R/F2 %d 0 R>>>>>>",
		contentNum, fontNum, boldNum)))
	pagesNum := d.alloc([]byte(fmt.Sprintf("<</Type/Pages/Kids[%d 0 R]/Count 1>>", pageNum)))
	cat := d.alloc([]byte(fmt.Sprintf("<</Type/Catalog/Pages %d 0 R>>", pagesNum)))
	d.setRoot(cat)

	info := d.alloc([]byte(fmt.Sprintf(
		"<</Title(Wire Instructions)/Author(%s)/Producer(ceo-kit)>>", esc(c.Client))))
	d.setInfo(info)

	// Patch parent
	d.objs[pageNum-1].body = []byte(strings.Replace(
		string(d.objs[pageNum-1].body), "Parent 2 0 R",
		fmt.Sprintf("Parent %d 0 R", pagesNum), 1))

	return d.Bytes()
}

// (reuse the same minimal PDF writer as pdf-kit)
type pdfObj struct {
	num    int
	body   []byte
	stream []byte
}
type pdfDoc struct {
	objs    []*pdfObj
	nextNum int
	rootNum int
	infoNum int
}
func newPDF() *pdfDoc { return &pdfDoc{nextNum: 1} }
func (d *pdfDoc) alloc(body []byte) int {
	n := d.nextNum
	d.nextNum++
	d.objs = append(d.objs, &pdfObj{num: n, body: body})
	return n
}
func (d *pdfDoc) allocStream(dict, stream []byte) int {
	n := d.nextNum
	d.nextNum++
	d.objs = append(d.objs, &pdfObj{num: n, body: dict, stream: stream})
	return n
}
func (d *pdfDoc) setRoot(n int) { d.rootNum = n }
func (d *pdfDoc) setInfo(n int) { d.infoNum = n }
func (d *pdfDoc) Bytes() []byte {
	sort.Slice(d.objs, func(i, j int) bool { return d.objs[i].num < d.objs[j].num })
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := make(map[int]int)
	for _, o := range d.objs {
		offsets[o.num] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n", o.num)
		if o.stream != nil {
			buf.WriteString("<<")
			buf.Write(o.body)
			fmt.Fprintf(&buf, "/Length %d >>\nstream\n", len(o.stream))
			buf.Write(o.stream)
			buf.WriteString("\nendstream")
		} else {
			buf.Write(o.body)
		}
		buf.WriteString("\nendobj\n")
	}
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", d.nextNum)
	for i := 1; i < d.nextNum; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root %d 0 R", d.nextNum, d.rootNum)
	if d.infoNum > 0 {
		fmt.Fprintf(&buf, " /Info %d 0 R", d.infoNum)
	}
	buf.WriteString(" >>\n")
	fmt.Fprintf(&buf, "startxref\n%d\n%%%%EOF\n", xref)
	return buf.Bytes()
}
func esc(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `(`, `\(`)
	s = strings.ReplaceAll(s, `)`, `\)`)
	return s
}
var _ = zlib.BestCompression
var _ = md5.New

// ---------------------------------------------------------------------------
// Callback script — what the operator reads if the target takes the bait.
// This is a *defensive* artefact: it documents what the operator is expected
// to say, so the engagement lead can review it before delivery.
// ---------------------------------------------------------------------------

func buildCallbackScript(c Config, spec ScenarioSpec) string {
	return fmt.Sprintf(`# CEO-BEC callback script — %s

## Scenario
%s (%s)

## Setup
- Caller ID: %s (spoofed) OR "unknown" if the operator's telco blocks spoofing
- Voice: calm, executive, slightly rushed
- Background: quiet office + keyboard (not a call centre)

## If the target answers
"Hi %s, it's %s. I'm between meetings so this is quick — did you
get my email about the %s? I need the confirmation reference so legal
can release the funds."

## If the target pushes back
- "I'm sorry, I can't discuss the details — NDA until Monday. Just need
  the confirmation."
- "Who else knows about this? Nobody? Good. Keep it that way."
- "I'll have %s call you in 10 minutes to confirm."
  (The operator's second caller plays the assistant.)

## If the target says they'll call back
- "No — I'm going into a board session. Just reply to my email with the
  confirmation and I'll see it when I'm out."

## If the target reports it to security
- Abort. Do not call again. Log the timestamp and the person's name to
  the engagement report. This is a successful outcome — the client's
  process worked.

## Red flags the target SHOULD notice (for the debrief)
%s
`, c.Campaign, spec.Name, spec.MITRE, c.Callback, c.Target.First(),
		c.CEO.Name, strings.ToLower(strings.ReplaceAll(spec.Name, " ", "-")),
		c.CFO.Name, strings.Join(prefixEach(spec.Indicators, "  - "), "\n"))
}

func prefixEach(xs []string, p string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = p + x
	}
	return out
}

// ---------------------------------------------------------------------------
// Detection rules — the deliverable. A BEC kit that doesn't ship detections
// is a crime; a BEC kit that does is a training exercise.
// ---------------------------------------------------------------------------

const yaraEmailRule = `rule BEC_Exec_Wire_Request {
  meta:
    description = "Executive-spoofed email containing bank wire details"
    mitre = "T1566.001, T1656"
  strings:
    $routing = /Routing(\s*(Number|#|No\.?)?\s*:|\s+)\s*\d{9}/
    $account = /Account(\s*(Number|#|No\.?)?\s*:|\s+)\s*\d{6,17}/
    $urgent  = /(?i)(urgent|asap|immediately|before\s+(eod|close|5\s*pm))/
    $secret  = /(?i)(do not discuss|keep this (between|quiet)|nda|confidential)/
    $wire    = /(?i)(wire|remit|transfer|payment)/
  condition:
    uint32(0) != 0 and filesize < 2MB and
    $routing and $account and 2 of ($urgent, $secret, $wire)
}

rule BEC_Reply_To_Mismatch {
  meta:
    description = "From and Reply-To domains differ on an exec email"
    mitre = "T1656"
  strings:
    $from_hdr = /(?i)^From:\s*[^\r\n]+@([a-z0-9.-]+)/ 
    $rt_hdr   = /(?i)^Reply-To:\s*[^\r\n]+@([a-z0-9.-]+)/
  condition:
    #from_hdr > 0 and #rt_hdr > 0 and not ( @from_hdr == @rt_hdr )
}
`

const sigmaBECRule = `title: BEC Wire Request from Executive
id: 7c3e9a2b-bec-0001
status: experimental
description: >
  Detects an email whose From display name matches an executive but whose
  envelope sender does not, containing wire-transfer language.
references:
  - https://attack.mitre.org/techniques/T1656/
logsource:
  category: email
  product: m365
  service: exchange
detection:
  executive_display:
    SenderDisplayName|contains:
      - 'CEO'
      - 'Chief Executive'
      - 'President'
      - 'CFO'
      - 'Chief Financial'
  spoofed:
    SenderFromDomain|endswith:
      - '.onmicrosoft.com'
      - '.gmail.com'
      - '.outlook.com'
      - '.protonmail.com'
    NOT SenderFromDomain|endswith: '@corp.example'
  wire_words:
    Body|contains:
      - 'routing'
      - 'account number'
      - 'wire transfer'
      - 'remit'
  urgency:
    Body|contains:
      - 'urgent'
      - 'before 5pm'
      - 'before EOD'
      - 'as soon as possible'
  secrecy:
    Body|contains:
      - 'do not discuss'
      - 'keep this between'
      - 'NDA'
  condition: executive_display and spoofed and wire_words and (urgency or secrecy)
fields:
  - SenderDisplayName
  - SenderFromAddress
  - ReplyToAddress
  - RecipientAddress
  - Subject
falsepositives:
  - Legitimate email from a new executive whose account is not yet federated
level: critical
`

const sigmaReplyToRule = `title: Reply-To Domain Diverges on Executive Email
id: 7c3e9a2b-bec-0002
status: experimental
description: >
  Fires when an email's Reply-To domain differs from its From domain, and
  the From display name matches a known executive. This is the single
  highest-signal indicator of BEC.
logsource:
  category: email
  product: m365
  service: exchange
detection:
  selection:
    ReplyToAddress|exists: true
    SenderDisplayName|contains:
      - 'CEO'
      - 'CFO'
      - 'Chief'
      - 'President'
  mismatch:
    FromDomain: '*'
  condition: selection and ReplyToAddress != SenderFromAddress
level: high
`

const sigmaLookalikeRule = `title: Lookalike Domain Email — Executive Impersonation
id: 7c3e9a2b-bec-0003
status: experimental
description: >
  Fires when a sender domain is a visual lookalike of a known corporate
  domain (hyphenated, doubled character, or homoglyph). Requires a corporate
  domain list to be populated — see CorporateDomains below.
logsource:
  category: email
  product: m365
  service: exchange
detection:
  corporate_domains:
    - 'acme.com'
    - 'acme.example'
  lookalike_regex:
    SenderFromDomain|re: '^(acme[-_.][a-z0-9]+\.(com|net|org)|acme[a-z0-9]+\.(com|net|org))$'
  condition: lookalike_regex and not corporate_domains
level: high
`

// ---------------------------------------------------------------------------
// Manifest + report
// ---------------------------------------------------------------------------

type Manifest struct {
	Campaign   string             `json:"campaign"`
	Client     string             `json:"client"`
	Created    string             `json:"created"`
	Scenario   ScenarioSpec       `json:"scenario"`
	Config     Config             `json:"config"`
	Files      []ManifestFile     `json:"files"`
	Indicators map[string]string  `json:"indicators"`
	Rules      map[string]string  `json:"detection_rules"`
	Checklist  []string           `json:"delivery_checklist"`
}

type ManifestFile struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
	Role   string `json:"role"`
}

func writeFile(m *Manifest, path, role string, data []byte) error {
	sum := sha256.Sum256(data)
	m.Files = append(m.Files, ManifestFile{
		Name:   filepath.Base(path),
		Size:   len(data),
		SHA256: hex.EncodeToString(sum[:]),
		Role:   role,
	})
	return os.WriteFile(path, data, 0644)
}

// ---------------------------------------------------------------------------
// Consent gate — identical pattern to the other kits.
// ---------------------------------------------------------------------------

func consentPresent(campaign string) bool {
	p := filepath.Join("/var/lib/evasion", campaign+".consent")
	b, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	s := strings.ToLower(string(b))
	return strings.Contains(s, strings.ToLower(campaign)) &&
		strings.Contains(s, "authorized")
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	var c Config
	flag.StringVar(&c.Campaign, "campaign", "", "campaign ID (required)")
	flag.StringVar(&c.Client, "client", "Acme Corp", "client name")
	flag.StringVar(&c.Scenario, "scenario", "wire", "wire | giftcard | payroll | w2 | invoice")
	flag.StringVar(&c.Amount, "amount", "487,500.00", "amount in scenario currency")
	flag.StringVar(&c.BankName, "bank", "First National Bank", "bank name in lure")
	flag.StringVar(&c.BankAcct, "acct", "8827364510", "account number in lure")
	flag.StringVar(&c.BankRouting, "routing", "021000021", "routing number in lure")
	flag.StringVar(&c.Callback, "callback", "+1 555 0100", "callback number for the script")
	flag.StringVar(&c.OutDir, "out", "./build", "output directory")
	flag.StringVar(&c.URGENCY, "urgency", "high", "low | normal | high | extreme")

	flag.StringVar(&c.CEO.Name, "ceo-name", "Robert Chen", "CEO name")
	flag.StringVar(&c.CEO.Title, "ceo-title", "Chief Executive Officer", "CEO title")
	flag.StringVar(&c.CEO.Email, "ceo-email", "r.chen@acme.com", "CEO email")
	flag.StringVar(&c.CEO.Phone, "ceo-phone", "+1 555 0101", "CEO phone")
	flag.StringVar(&c.CEO.Timezone, "ceo-tz", "PST", "CEO timezone")
	flag.StringVar(&c.CEO.Assistant, "ceo-asst", "Dana Whitfield", "CEO assistant name")

	flag.StringVar(&c.CFO.Name, "cfo-name", "Maria Alvarez", "CFO name")
	flag.StringVar(&c.CFO.Email, "cfo-email", "m.alvarez@acme.com", "CFO email")

	flag.StringVar(&c.Target.Name, "target-name", "James Patel", "target name")
	flag.StringVar(&c.Target.Title, "target-title", "Accounts Payable Manager", "target title")
	flag.StringVar(&c.Target.Email, "target-email", "j.patel@acme.com", "target email")
	flag.StringVar(&c.Target.Timezone, "target-tz", "EST", "target timezone")

	flag.Parse()

	if c.Campaign == "" {
		fmt.Fprintln(os.Stderr, "error: -campaign is required")
		flag.Usage()
		os.Exit(2)
	}
	spec, ok := scenarios[c.Scenario]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown scenario %q (use wire|giftcard|payroll|w2|invoice)\n", c.Scenario)
		os.Exit(2)
	}
	if err := os.MkdirAll(c.OutDir, 0755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Render body from template
	body := renderTemplate(spec.BodyTmpl, c)

	// Build thread (prior + BEC + follow-up)
	thread := buildThread(c, spec, body)

	// Build wire PDF (if scenario has bank details)
	var wirePDF []byte
	if spec.ID == "wire" || spec.ID == "invoice" {
		wirePDF = buildWirePDF(c)
	}

	// Callback script
	callback := buildCallbackScript(c, spec)

	// Manifest
	m := Manifest{
		Campaign: c.Campaign,
		Client:   c.Client,
		Created:  time.Now().UTC().Format(time.RFC3339),
		Scenario: spec,
		Config:   c,
		Indicators: map[string]string{
			"scenario":      spec.ID,
			"mitre":         spec.MITRE,
			"ceo_email":     c.CEO.Email,
			"reply_to":      lookalike(c.CEO.Email),
			"target":        c.Target.Email,
			"amount":        c.Amount,
			"callback":      c.Callback,
		},
		Rules: map[string]string{
			"yara_email":        yaraEmailRule,
			"sigma_wire":        sigmaBECRule,
			"sigma_reply_to":    sigmaReplyToRule,
			"sigma_lookalike":   sigmaLookalikeRule,
		},
		Checklist: []string{
			"1. Confirm consent file exists at /var/lib/evasion/" + c.Campaign + ".consent",
			"2. Send detections.* and manifest.json to the client's SOC BEFORE delivery",
			"3. Confirm the target's mail client is M365 or Gmail (thread collapsing depends on it)",
			"4. Send the prior email 2h before the BEC email so the thread looks natural",
			"5. Send the BEC email from the lookalike domain (NOT the real CEO mailbox)",
			"6. Wait 20min, send the follow-up if there's no response",
			"7. If the target replies to the lookalike, STOP — do not continue the conversation",
			"8. If the target calls the callback, follow the callback script exactly",
			"9. Log every interaction (timestamp, person, channel) to the engagement report",
			"10. Debrief the target within 24h — this is a training exercise, not entrapment",
		},
	}

	// Write files
	files := []struct {
		name string
		role string
		data []byte
	}{
		{filepath.Join(c.OutDir, "01_prior.eml"), "email", thread[0]},
		{filepath.Join(c.OutDir, "02_bec.eml"), "email", thread[1]},
		{filepath.Join(c.OutDir, "03_followup.eml"), "email", thread[2]},
		{filepath.Join(c.OutDir, "callback_script.md"), "script", []byte(callback)},
		{filepath.Join(c.OutDir, "detections_email.yar"), "detection", []byte(yaraEmailRule)},
		{filepath.Join(c.OutDir, "detections_wire.sigma.yml"), "detection", []byte(sigmaBECRule)},
		{filepath.Join(c.OutDir, "detections_replyto.sigma.yml"), "detection", []byte(sigmaReplyToRule)},
		{filepath.Join(c.OutDir, "detections_lookalike.sigma.yml"), "detection", []byte(sigmaLookalikeRule)},
	}
	if wirePDF != nil {
		files = append(files, struct {
			name string
			role string
			data []byte
		}{filepath.Join(c.OutDir, "wire_instructions.pdf"), "pdf", wirePDF})
	}

	for _, f := range files {
		if err := writeFile(&m, f.name, f.role, f.data); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("[+] %-32s %8d bytes  %s\n", filepath.Base(f.name), len(f.data), f.role)
	}

	mb, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(c.OutDir, "manifest.json"), mb, 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("[+] %-32s %8d bytes  manifest\n", "manifest.json", len(mb))

	if !consentPresent(c.Campaign) {
		fmt.Fprintln(os.Stderr, "\n[!] No signed consent for campaign "+c.Campaign+".")
		fmt.Fprintln(os.Stderr, "    Artefacts written for review only.")
		fmt.Fprintln(os.Stderr, "    Add /var/lib/evasion/"+c.Campaign+".consent to enable delivery summary.")
		os.Exit(3)
	}

	printSummary(c, spec, m)
}

// ---------------------------------------------------------------------------
// Delivery summary — only printed with consent.
// ---------------------------------------------------------------------------

func printSummary(c Config, spec ScenarioSpec, m Manifest) {
	fmt.Println()
	fmt.Println("=== BEC campaign ready for delivery ===")
	fmt.Printf("Campaign    : %s\n", c.Campaign)
	fmt.Printf("Client      : %s\n", c.Client)
	fmt.Printf("Scenario    : %s (%s)\n", spec.Name, spec.MITRE)
	fmt.Printf("CEO         : %s <%s>\n", c.CEO.Name, c.CEO.Email)
	fmt.Printf("Reply-To    : %s  <-- lookalike, THIS is the attack\n", lookalike(c.CEO.Email))
	fmt.Printf("Target      : %s <%s> (%s)\n", c.Target.Name, c.Target.Email, c.Target.Title)
	fmt.Printf("Amount      : %s\n", c.Amount)
	fmt.Printf("Callback    : %s\n", c.Callback)
	fmt.Println()
	fmt.Println("Delivery checklist:")
	for _, step := range m.Checklist {
		fmt.Printf("  %s\n", step)
	}
	fmt.Println()
	fmt.Println("Hand to the blue team FIRST:")
	fmt.Println("  - manifest.json")
	fmt.Println("  - detections_email.yar")
	fmt.Println("  - detections_wire.sigma.yml")
	fmt.Println("  - detections_replyto.sigma.yml")
	fmt.Println("  - detections_lookalike.sigma.yml")
}

// ---------------------------------------------------------------------------
// helpers (must be defined before main; placed here for readability)
// ---------------------------------------------------------------------------

func renderTemplate(tmpl string, c Config) string {
	// minimal {{.Path}} substitution — no template package because we need
	// to substitute into text that may itself contain {{ }} in the body.
	r := strings.NewReplacer(
		"{{.Campaign}}", c.Campaign,
		"{{.Client}}", c.Client,
		"{{.Amount}}", c.Amount,
		"{{.BankName}}", c.BankName,
		"{{.BankAcct}}", c.BankAcct,
		"{{.BankRouting}}", c.BankRouting,
		"{{.Callback}}", c.Callback,
		"{{.CEO.Name}}", c.CEO.Name,
		"{{.CEO.Title}}", c.CEO.Title,
		"{{.CEO.Email}}", c.CEO.Email,
		"{{.CEO.Phone}}", c.CEO.Phone,
		"{{.CEO.Timezone}}", c.CEO.Timezone,
		"{{.CFO.Name}}", c.CFO.Name,
		"{{.CFO.Email}}", c.CFO.Email,
		"{{.Target.Name}}", c.Target.Name,
		"{{.Target.Title}}", c.Target.Title,
		"{{.Target.Email}}", c.Target.Email,
		"{{.Target.Timezone}}", c.Target.Timezone,
	)
	return r.Replace(tmpl)
}

// First returns the first name from a full name.
func (e Executive) First() string {
	if i := strings.Index(e.Name, " "); i > 0 {
		return e.Name[:i]
	}
	return e.Name
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = os.ReadFile("/dev/urandom") // cheap fallback; real kits use crypto/rand
	for i := range b {
		b[i] = byte(i * 17)
	}
	return hex.EncodeToString(b)
}

// keep imports honest
var _ = base64.StdEncoding
var _ = mime.TypeByExtension
var _ = zlib.BestCompression
var _ = md5.New
