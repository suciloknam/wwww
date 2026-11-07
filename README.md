# LogLens — LLM Incident Triage API

Paste a log, get structured triage: **severity, component, probable cause, 3 read-only next commands, confidence**.
Claude is primary, OpenAI is fallback, everything is redacted before it leaves the box, and every call logs tokens, cost and latency.

```
client ──► nginx :80  (basic auth · 10 req/min/IP · 256 KB body cap)
              │
              ▼
          api :8000  (not published to host)
              │  1. redact (keys, tokens, passwords, emails, IPs, long numbers)
              │  2. keep last 8000 chars (errors live at the tail)
              │  3. Claude ──fail──► OpenAI         (temperature 0, 30s timeout each)
              │  4. Pydantic-validated output
              ▼
          JSON log line: provider, tokens, cost_usd, latency_ms, fallback_used, prompt_version
```

## Runbook — Amazon Linux 2023 (4 vCPU / 16 GB)

### 1. Security group first
Inbound **TCP 80 from your own IP /32 only**. Do not open 8000. Do not use 0.0.0.0/0.

### 2. Docker + Compose plugin
AL2023 ships Docker but not the Compose plugin, so install that manually.
```bash
sudo dnf install -y docker git httpd-tools
sudo systemctl enable --now docker
sudo usermod -aG docker $USER && newgrp docker

sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo curl -sSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$(uname -m)" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
docker compose version
```

### 3. Configure
```bash
cd loglens
cp .env.example .env && chmod 600 .env
vi .env                                   # keys, model IDs, prices
htpasswd -Bc nginx/.htpasswd suvodip      # bcrypt password for basic auth
```

### 4. Run
```bash
docker compose up -d --build
docker compose ps                          # api should become "healthy"
curl -s localhost/health
```

### 5. Smoke test
```bash
curl -s -u suvodip -X POST localhost/triage \
  -H 'Content-Type: application/json' \
  -d '{"log":"java.lang.OutOfMemoryError: Java heap space\nkernel: Out of memory: Killed process 2114 (java)"}' | jq
```

### 6. Prove fallback works (do this, it's your interview story)
```bash
sed -i 's/^ANTHROPIC_API_KEY=.*/ANTHROPIC_API_KEY=broken/' .env
docker compose up -d                       # recreate with bad key
# re-run the smoke test → meta.provider = "openai", meta.fallback_used = true
docker compose logs api | grep provider_failed
# restore the real key afterwards
```

### 7. Evals
```bash
docker compose exec api python -m evals.run_evals          # all providers
docker compose exec api python -m evals.run_evals openai   # one provider
```
Reports severity accuracy, component accuracy, **unsafe command suggestions**, p50 latency and total cost per provider.
Case `prompt-injection` checks the model ignores instructions hidden inside a log.

### 8. Observe
```bash
docker compose logs -f api | grep triage_ok
# cost so far today:
docker compose logs --since 24h api | grep triage_ok | sed 's/^[^{]*//' | jq -s 'map(.cost_usd) | add'
# fallback rate:
docker compose logs --since 24h api | grep -c '"fallback_used": true'
```

## Design decisions (the "why")

| Decision | Why |
|---|---|
| Pydantic output contract | The model's answer becomes an API, not prose. Downstream tools (Slack bot, ticketing) can rely on fields. |
| `include_raw=True` | Structured output alone hides token usage. Keeping the raw message is what makes cost observability possible. |
| Fallback in app code, not `with_fallbacks()` | We need to *know* which provider answered and why the first one failed. That's the metric that matters in production. |
| Redact before send | Third-party APIs are an egress boundary. Treat it like a firewall rule: deny by default. |
| Tail truncation | Bounds cost per request and the root error is usually at the end. |
| Models & prices in `.env` | Models change monthly. Swapping is a config change with an eval run, not a code deploy. |
| `PROMPT_VERSION` | Prompts are code. Version them, eval every change, compare numbers. |
| `<log>` tags + "untrusted DATA" | Logs contain user input → prompt injection is a real attack path. |
| API not published, nginx in front | Auth, rate limit and body cap stop an exposed endpoint from becoming a bill. |
| read-only container, non-root user | Same hardening you'd do for any prod service. |

## Next iterations
1. `/metrics` with `prometheus-client` → Grafana panels: cost/req, p95 latency, fallback rate.
2. Redis semantic cache for repeated errors.
3. Prompt v2 → run evals → compare against v1 before switching.
4. RAG over your own runbooks so `next_commands` match your environment.
5. TLS via certbot once you put a domain on it.
