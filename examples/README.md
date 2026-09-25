# Examples

Files in this directory:

## `suggested-minimum-filter-for-windows-clients`

If you are protecting MS Windows clients, this is the minimum
suggested filter. You might want to use a stronger filter.

## `stream-by-domain-filter`

An example showing how to use the `stream_by_domain` function.

## `example-filter-with-async-checks`

An example filter using `Mail::MIMEDefang::Async` to run DNS blacklist,
sender-domain, virus, and spam checks in parallel rather than sequentially.

Requires: `AnyEvent`, `AnyEvent::DNS`, `AnyEvent::Socket`, `AnyEvent::Handle`

- `filter_relay` - fires DNSBL lookups (Spamhaus ZEN, SpamCop, SURBL) and a
  reverse DNS (PTR) lookup in parallel at SMTP connect time.
- `filter_sender` - fires SPF, MX, and DMARC lookups in parallel for the
  sender's domain when `MAIL FROM:` arrives.
- `filter_begin` - runs a non-blocking clamd virus scan.
- `filter_end` - runs a non-blocking SpamAssassin (or optionally Rspamd)
  spam check.

## `example-filter-with-ml`

An example filter using `Mail::MIMEDefang::ML` to get ham/spam/phishing
verdicts from a machine-learning model, in addition to the usual SPF, DKIM, DMARC,
and SpamAssassin checks. The backend is chosen through
`$Mail::MIMEDefang::ML::Config{backend}`; the filter code is the same for
every backend:

| Backend    | Model                                     | Server                                       | Typical latency       |
|------------|-------------------------------------------|----------------------------------------------|-----------------------|
| `laya`     | Laya non-autoregressive decision model    | `mimedefang-laya-server` (port 8687)         | tens of ms            |
| `gliclass` | GLiClass zero-shot encoder (ModernBERT)   | `mimedefang-gliclass-server` (port 8688)     | tens of ms            |
| `openai`   | self-hosted generative model (e.g. Qwen3)       | Ollama / llama.cpp / vLLM, OpenAI-compatible API | hundreds of ms to seconds |

Laya and GLiClass answer in a single forward pass and are fast enough for
every message. The `openai` backend runs a generative model, so it is
slower; set `$Mail::MIMEDefang::ML::Config{timeout}` to match.

Backend URLs can use any host name or IP address. The model servers have
no authentication and every request carries message content, so keep them
secure by limiting access with a firewall: only the MIMEDefang host(s)
should be able to reach their ports, and they should never be exposed to
the Internet. `mimedefang-laya-server` and `mimedefang-gliclass-server`
listen on `127.0.0.1` by default; if you pass `--host` to make one listen
on another address, firewall that port.

Requires: `Mail::MIMEDefang::ML`, `LWP::UserAgent`, `JSON::PP`, and a
running backend.

- `filter_sender` - verifies SPF for the envelope sender.
- `filter_begin` - runs DKIM verification and DMARC lookup, and publishes
  an `Authentication-Results` header.
- `filter_end` - runs SpamAssassin, then sends the message together with
  the SPF/DKIM/DMARC results to the model for a second opinion. The
  SpamAssassin score and rules are not passed to `ml_build_state`, so the
  model can't amplify SpamAssassin false positives. To include them,
  uncomment `SAScore`/`SARules` (or pass `RspamdScore`/`RspamdSymbols`).
  The model only acts (subject tagging) on confident verdicts. If the backend can't be reached, or the verdict has
  low confidence, SpamAssassin's own scoring is used. The verdict is
  exposed in the `X-MIMEDefang-ML-Score`, `X-MIMEDefang-ML-Answer`, and
  `X-MIMEDefang-ML-Backend` headers. `X-MIMEDefang-ML-Answer` is
  `phishing` or `spam` when the verdict is confident enough to act on,
  `ham` when the model is confident the message is not spam and doesn't
  lean towards phishing, and `unsure` otherwise. `unsure` covers a model
  that leans spam or phishing below the action thresholds, or that has no
  opinion. Unsure verdicts are also logged, which helps when tuning the
  thresholds.

The Laya and GLiClass model servers, with instructions for installing
their Python modules, downloading the models, running them under systemd,
and sizing them for your multiplexor, are in
[`script/ml-servers/`](../script/ml-servers/README.md).

## `redhat-logrotate-file`

If you log statistics to `/var/log/mimedefang/stats`, you want to rotate
the log file. You can copy `redhat-logrotate-file` to
`/etc/logrotate.d/mimedefang` on Red Hat Linux systems.

## `init-script`

A generic `/etc/init.d` script which should work on most versions
of UNIX. Typically, you'd rename it to `mimedefang-ctrl` and call
it from your startup scripts:

```
mimedefang-ctrl start  -- Start mimedefang
mimedefang-ctrl stop   -- Stop mimedefang
mimedefang-ctrl reread -- Re-read filter rules (if using multiplexor)
```
