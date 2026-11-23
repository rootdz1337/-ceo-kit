# -ceo-kit
 ceo-kit phishig

# CEO phishing kit — all in one Go file

A Kit That Generator for the **BEC (Business Email Compromise) / CEO fraud** layer that sits on top of the HTA and PDF kits. It produces the *social* artefacts — the spoofed email, the reply-thread, the fake "urgent wire" PDF, the callback script, and the engagement tracking sheet — plus the detection rules that catch all of them.


# Build && Run

```
go build -o ceo-kit ceo-kit.go

# Wire-transfer BEC (the classic)
./ceo-kit -campaign ACME-BEC-01 \
  -ceo-name "Robert Chen" -ceo-email "r.chen@acme.com" \
  -cfo-name "Maria Alvarez" -cfo-email "m.alvarez@acme.com" \
  -target-name "James Patel" -target-title "Accounts Payable Manager" \
  -target-email "j.patel@acme.com" \
  -amount "487,500.00" \
  -bank "First National Bank" -acct "8827364510" -routing "021000021" \
  -callback "+1 555 0100" \
  -out ./build

# Gift-card variant (smaller amount, no PDF)
./ceo-kit -campaign ACME-BEC-02 -scenario giftcard \
  -amount "500" -bank "Apple" \
  -target-name "Sarah Kim" -target-email "s.kim@acme.com" \
  -out ./build

# W-2 / payroll variant
./ceo-kit -campaign ACME-BEC-03 -scenario w2 \
  -target-name "Payroll" -target-email "payroll@acme.com" \
  -out ./build
```

## What you get in `./build`

| File | Role | What it demonstrates |
|---|---|---|
| `01_prior.eml` | thread seed | Innocuous internal email, sent 2h before the BEC, so the thread collapses |
| `02_bec.eml` | **BEC payload** | From: CEO display name, Reply-To: lookalike domain, wire details in body |
| `03_followup.eml` | nudge | The "just circling back" email that closes most BEC victims |
| `wire_instructions.pdf` | attachment | Legitimate-looking wire PDF (no malware — social lure only) |
| `callback_script.md` | operator script | Exactly what to say if the target calls; includes abort conditions |
| `detections_email.yar` | detection | YARA for bank details + urgency + secrecy |
| `detections_wire.sigma.yml` | detection | Executive display name + spoofed sender + wire words |
| `detections_replyto.sigma.yml` | detection | **The single highest-signal rule** — Reply-To ≠ From on exec email |
| `detections_lookalike.sigma.yml` | detection | Catches `acme-corp.com` impersonating `acme.com` |
| `manifest.json` | deliverable | SHA256 of every file, indicators, 10-step checklist |
