# FastFlare

Three tools in one zero-dependency Node service (Node 20+):

1. **Bot protection** without picture puzzles: proof-of-work in Web Workers plus behaviour signals, verified by your server.
2. **Speed test**: choose a provider, then a city that provider has a server in, and measure download, upload, latency, jitter and packet loss against that server, with graphs.
3. **EnvTime**: asks Google, Apple, Windows and other NTP servers, kicks any that disagree with the majority, and serves precise time over HTTP (any time zone) and NTP (usable as a Windows time server).

Documentation and integration guides: **https://arthwarrior3201.github.io/FastFlare/**

## Install on a server (one command)

On Ubuntu or Debian (for example a free Oracle Cloud VM), open inbound **UDP 123** and **TCP 8787** in the cloud firewall, then:

```sh
curl -fsSL https://raw.githubusercontent.com/ArthWarrior3201/FastFlare/main/deploy/install.sh | sudo bash
```

It installs Node.js, swap (on small servers), firewall rules and a boot-time service, then prints the Windows commands. macOS: `curl -fsSL https://raw.githubusercontent.com/ArthWarrior3201/FastFlare/main/deploy/install.command | bash`. Windows (administrator PowerShell): `irm https://raw.githubusercontent.com/ArthWarrior3201/FastFlare/main/deploy/install.ps1 | iex` (or double-click `deploy/install.cmd`). Full walkthrough: the [EnvTime setup guide](https://arthwarrior3201.github.io/FastFlare/envtime.html).

## Run manually

```sh
FF_SECRET=$(openssl rand -hex 32) node src/server.js
```

HTTP listens on `:8787` and also serves the docs, `/fastflare.js` (widget) and `/fastflare-speedtest.js` (speed test client). NTP listens on UDP 123, which needs privileges; use `NTP_PORT=1230` to try it unprivileged or `FF_NTP=0` to disable it. Docker: `docker build -t fastflare . && docker run -p 8787:8787 -p 123:123/udp -e FF_SECRET=... fastflare`.

```sh
npm test
```

## Quick integration

CAPTCHA, in your page and your backend:

```html
<script src="https://YOUR-HOST/fastflare.js" async defer></script>
<div class="ff-captcha" data-sitekey="YOUR_SITE_KEY"></div>
```

```js
const out = await (await fetch('https://YOUR-HOST/captcha/siteverify', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ secret: SECRET, response: req.body['ff-token'] }),
})).json(); // { success: true, ... }
```

Time: `GET /time?tz=Asia/Kolkata`.

Full guides (options, speed test embedding, node registry, Windows time server setup) are in [`docs/`](docs/) and on the site above.

## Layout

| Path | What |
| --- | --- |
| `src/captcha.js` | Challenges, proof check, scoring, tokens, siteverify |
| `src/speedtest.js` | Ping, download and upload endpoints, server registry |
| `src/ntp.js`, `src/envtime.js` | NTP client and server, consensus clock |
| `docs/` | GitHub Pages site, plus the browser libraries `fastflare.js` and `fastflare-speedtest.js` |
| `config/*.example.json` | Site keys and speed test node list templates |

## Limits worth knowing

- No CAPTCHA is unbeatable. This raises the cost of abuse and stops lazy automation; the behaviour signals come from the client and can be forged. Rate-limit sensitive endpoints too.
- The speed test provider/city list is whatever nodes you deploy and list in `config/servers.json`.
- EnvTime accuracy is typically a few milliseconds over normal internet; each reply includes `uncertaintyMs`.
