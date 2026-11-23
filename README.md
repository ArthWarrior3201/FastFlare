# FastFlare

Image-free bot protection and a precise time server in one zero-dependency Node.js service.

## Protect a Site

1. Get a site key on the [Quick Start](https://arthwarrior3201.github.io/FastFlare/quickstart.html) page.
2. Run the gate backend anywhere Node.js 18+ runs:

```sh
node docs/kit/fastflare-gate.mjs --sitekey=YOUR_SITE_KEY --secret=YOUR_SECRET --redirect=/dashboard
```

Visitors click "I'm not a robot", the FastFlare server decides to let them through, challenge them or block them, and the gate sends those who pass to the redirect page. Add `--upstream=http://localhost:8080` to put the gate in front of an existing site.

## Run a FastFlare Server

```sh
curl -fsSL https://raw.githubusercontent.com/ArthWarrior3201/FastFlare/main/deploy/install.sh | sudo bash
```

Ubuntu or Debian; open UDP 123 and TCP 8787 first. macOS: `deploy/install.command`. Windows (administrator PowerShell): `irm https://raw.githubusercontent.com/ArthWarrior3201/FastFlare/main/deploy/install.ps1 | iex`. HTTPS: `deploy/enable-https.sh`.

Time API: `GET /time?tz=Asia/Kolkata`. NTP on UDP 123 works as a Windows time server.

## Layout

| Path | What |
| --- | --- |
| `src/captcha.js`, `src/puzzle.js` | Challenges, scoring, puzzles, tokens, siteverify |
| `src/sites.js` | Self-serve site keys |
| `src/ntp.js`, `src/envtime.js` | NTP client and server, consensus clock |
| `docs/` | Documentation site and the widget `fastflare.js` |
| `docs/kit/fastflare-gate.mjs` | Gate backend for developers |

```sh
npm test
```
