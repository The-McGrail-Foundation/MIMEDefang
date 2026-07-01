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
