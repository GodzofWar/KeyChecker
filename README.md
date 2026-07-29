# KeyChecker

[![CI](https://github.com/GodzofWar/KeyChecker/actions/workflows/ci.yml/badge.svg)](https://github.com/GodzofWar/KeyChecker/actions/workflows/ci.yml)

Quickly check whether your recon / OSINT **API keys are still valid** — and see
the plan and remaining quota for each — across services like Shodan, Censys,
FOFA, and more. If you juggle a pile of keys across tools, KeyChecker tells you
in one run which are live, which are dead, and how much quota is left.

## Supported services

| Service | Credential fields | Environment variables |
| --- | --- | --- |
| Shodan | `key` | `SHODAN_API_KEY` |
| Censys | `id`, `secret` | `CENSYS_API_ID`, `CENSYS_API_SECRET` |
| FOFA | `email`, `key` | `FOFA_EMAIL`, `FOFA_KEY` |
| SecurityTrails | `key` | `SECURITYTRAILS_API_KEY` |
| VirusTotal | `key` | `VT_API_KEY` |
| BinaryEdge | `key` | `BINARYEDGE_API_KEY` |
| ZoomEye | `key` | `ZOOMEYE_API_KEY` |
| Hunter.io | `key` | `HUNTER_API_KEY` |
| GreyNoise | `key` | `GREYNOISE_API_KEY` |
| IPinfo | `token` | `IPINFO_TOKEN` |
| Onyphe | `key` | `ONYPHE_API_KEY` |
| PassiveTotal | `username`, `key` | `PASSIVETOTAL_USERNAME`, `PASSIVETOTAL_API_KEY` |
| WhoisXML API | `key` | `WHOISXML_API_KEY` |
| FullHunt | `key` | `FULLHUNT_API_KEY` |
| Intelligence X | `key` | `INTELX_API_KEY` |
| urlscan.io | `key` | `URLSCAN_API_KEY` |
| Have I Been Pwned | `key` | `HIBP_API_KEY` |

Run `keychecker --list` for the current list.

## Install

```bash
git clone https://github.com/GodzofWar/KeyChecker
cd KeyChecker
pip install -e .
# or, without installing:
pip install -r requirements.txt
python -m keychecker --help
```

Requires Python 3.9+.

## Usage

Keys can come from three places — mix and match freely:

**1. Config file** (best for many keys):

```bash
cp config.example.yaml config.yaml   # then edit
keychecker --config config.yaml
```

**2. Environment variables:**

```bash
export SHODAN_API_KEY=xxxx
export CENSYS_API_ID=aaa CENSYS_API_SECRET=bbb
keychecker
```

**3. CLI flags** (best for one-offs). Multi-field services take
colon-separated values:

```bash
keychecker --shodan XXXX --censys API_ID:API_SECRET --fofa you@example.com:KEY
```

### Handy options

```
--only SERVICE      check only the named service(s); repeatable
--no-env            ignore environment variables
--json              machine-readable output
--concurrency N     max parallel checks (default 10)
--timeout SECONDS   per-request timeout (default 15)
--list              list supported services and exit
```

### Example output

```
SERVICE   ACCOUNT           STATUS  DETAILS
--------  ----------------  ------  ----------------------------------------
Shodan    ************abcd  OK      plan=dev query_credits=100 scan_credits=0
Censys    ************wxyz  BAD     unauthorized (HTTP 403)
FOFA      you@example.com   OK      vip_level=1 points=1000 remain_api_query=300

3 checked: 2 valid, 1 invalid, 0 error
```

Exit code is `0` when every checked key is valid, and `1` if any are invalid
or errored — convenient for cron jobs and CI.

## Adding a new service

Each service is a small self-contained checker. Create
`keychecker/checkers/<name>.py`:

```python
import httpx
from ..models import CheckResult
from .base import BaseChecker

class ExampleChecker(BaseChecker):
    name = "example"
    display_name = "Example"
    fields = ("key",)
    env_vars = {"key": "EXAMPLE_API_KEY"}
    help = "Example API key"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        resp = await client.get(
            "https://api.example.com/account",
            headers={"Authorization": self.credentials["key"]},
        )
        if resp.status_code == 200:
            return self.valid("account ok", **resp.json())
        if resp.status_code in (401, 403):
            return self.invalid(f"unauthorized (HTTP {resp.status_code})")
        return self.error(f"unexpected HTTP {resp.status_code}")
```

Then register it in `keychecker/checkers/__init__.py`. The config key, env-var
wiring, and `--example` CLI flag are all generated from that metadata.

## Notes

- KeyChecker only calls each service's lightweight account/quota endpoint —
  it does not run searches or consume meaningful credits.
- `config.yaml` and `.env` are git-ignored so your keys stay local. Only ever
  check keys you own or are authorized to use.
- API endpoints occasionally change; a service returning `ERR` may indicate an
  upstream change rather than a bad key. Open an issue or PR if you spot one.

## License

MIT — see [LICENSE](LICENSE).
