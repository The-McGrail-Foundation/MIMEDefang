# Contrib

This directory contains user-contributed programs and files. See each
file for copyright information.

## `fang.pl`

A Perl script which attempts to reconstruct a message from the contents
of a quarantine directory. Requires the `MIME::Lite` Perl module.

## `linuxorg`

A collection of files contributed by Michael McLagan
<Michael.McLagan@linux.org> used to implement the filtering in place
within Linux Online and Linux Headquarters.

## `word-to-html`

A simple shell script which converts Word documents to HTML. Requires
`wvHtml`.

## `graphdefang`

Utilities to make pretty graphs of MIMEDefang activity.

## `greylisting`

SQL schemas (MySQL, PostgreSQL, SQLite) for the greylisting table and
a sample `mimedefang-filter` that calls `action_greylist` from
`filter_recipient`.  Requires `DBI` and the matching DBD driver.

## `munin`

A Munin plugin that graphs MIMEDefang performance metrics read from the
multiplexor socket (set `MX_SOCK` to its path).

## `filebeat.yml`

A sample Filebeat input that ships MIMEDefang status in JSON format to an
ELK stack.  It reads `/var/log/mimedefang.json`, which you fill yourself,
e.g. by appending the output of `md-mx-ctrl jsonstatus` from cron.

## `ml-benchmark`

Measures the `Mail::MIMEDefang::ML` backends (Laya, GLiClass and
OpenAI-compatible LLMs) against a corpus: `ml-benchmark HAM_DIR SPAM_DIR`
runs `script/mimedefang-test-mail` on every message with the bundled
`mimedefang-filter`, which asks every backend for a verdict, then reports
false positive / false negative percentages and average processing times
per backend.  Run `ml-benchmark --help` for the options.

`gliclass-train HAM_DIR SPAM_DIR` fine-tunes a GLiClass model on the same
kind of corpus, for `mimedefang-gliclass-server --model`; see "Training a
model" in `script/ml-servers/README.md`.  GLiClass is the only backend
that can be trained this easily.
