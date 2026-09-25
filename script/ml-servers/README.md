# MIMEDefang ML model servers

This directory has two small Python HTTP servers. Each keeps a
machine-learning model loaded in memory and answers classification requests
from `Mail::MIMEDefang::ML`:

| Server                       | Model                                                        | `Mail::MIMEDefang::ML` backend | Default address    |
|------------------------------|--------------------------------------------------------------|--------------------------------|--------------------|
| `mimedefang-laya-server`     | [Laya](https://github.com/NandhaKishorM/laya) decision model | `laya`                         | `127.0.0.1:8687`   |
| `mimedefang-gliclass-server` | [GLiClass](https://github.com/Knowledgator/GLiClass) zero-shot classifier | `gliclass`        | `127.0.0.1:8688`   |

Both models are encoder classifiers. They answer in a single forward pass,
which is fast enough to check every message. You only need the server for
the backend you use. The third backend, `openai`, talks to a server you
already run, such as Ollama, llama.cpp or vLLM, and needs nothing from this
directory.

Files:

- `mimedefang-laya-server`, `mimedefang-gliclass-server`: the servers.
- `requirements-laya.txt`, `requirements-gliclass.txt`: the Python modules
  each server needs.
- The systemd units are in `../../systemd-units/` with the other MIMEDefang units.

## Requirements

- **Python 3.10 or newer**, with the `venv` module. On Debian/Ubuntu that is
  the `python3-venv` package; on Fedora/RHEL it is part of `python3`.
- **pip access to PyPI**, to install the modules, and **network access to
  huggingface.co** for the first model download. After that the servers
  can run offline, see [Offline use](#model-cache-and-offline-use).
- **Memory and disk**, roughly:
  - About 1-2 GB of RAM for each loaded checkpoint. Laya's English and
    multilingual checkpoints have 421M and 322M parameters, and the default
    GLiClass model is ModernBERT-base sized (about 150M).
  - About 1-2 GB of disk for the CPU build of torch and the other modules,
    plus the model files.
- **A GPU is optional.** Both servers run on the CPU. See [GPU](#gpu).

## Installation

The steps below install the modules into a virtualenv at
`/opt/mimedefang-ml/venv`, which is where the systemd units look for them.
Current distributions don't let `pip` install into the system Python
(PEP 668), and a virtualenv also keeps torch and transformers away from the
Python modules your distribution installs.

### 1. Create the virtualenv

```sh
python3 -m venv /opt/mimedefang-ml/venv
/opt/mimedefang-ml/venv/bin/pip install --upgrade pip
```

### 2. Install torch

On a CPU-only host, install torch from PyTorch's CPU wheel index first.
Otherwise pip downloads the CUDA build, which is several GB larger:

```sh
/opt/mimedefang-ml/venv/bin/pip install torch \
    --index-url https://download.pytorch.org/whl/cpu
```

To use a GPU, skip this step and let the next one install the default
(CUDA) torch.

### 3. Install the server's modules

From this directory, install one or both sets:

```sh
# Laya
/opt/mimedefang-ml/venv/bin/pip install -r requirements-laya.txt

# GLiClass
/opt/mimedefang-ml/venv/bin/pip install -r requirements-gliclass.txt
```

To check that they import:

```sh
/opt/mimedefang-ml/venv/bin/python3 -c 'import laya, flask, waitress'
/opt/mimedefang-ml/venv/bin/python3 -c 'import gliclass, transformers, flask, waitress'
```

### 4. Install the server scripts

The servers are not installed by default. To have `make install` put
`mimedefang-laya-server` and `mimedefang-gliclass-server` into the same
`bin` directory as the other MIMEDefang programs (`/usr/bin` for the systemd
units), enable them when configuring the build:

```sh
./configure --enable-ml-servers ...      # autoconf build
perl Makefile.PL ML_SERVERS=1 ...        # ExtUtils::MakeMaker build
```

Or copy them by hand:

```sh
install -m 755 mimedefang-laya-server mimedefang-gliclass-server /usr/bin/
```

The scripts start with `#!/usr/bin/env python3`, so run them with the
virtualenv's Python: either `/opt/mimedefang-ml/venv/bin/python3
/usr/bin/mimedefang-gliclass-server ...`, or with the virtualenv activated.
The systemd units do the former.

### 5. Download the model

Each server downloads its model from Hugging Face the first time it
starts. To do this ahead of time, run as the same user and with the same
cache directory as the systemd units (`defang`,
`/var/lib/MIMEDefang/ml/huggingface`):

```sh
install -d -m 755 /var/lib/MIMEDefang       # if it doesn't exist yet
install -d -o defang -g defang /var/lib/MIMEDefang/ml

# GLiClass (use the model name you will run with --model)
sudo -u defang HF_HOME=/var/lib/MIMEDefang/ml/huggingface \
    /opt/mimedefang-ml/venv/bin/python3 -c \
    'from huggingface_hub import snapshot_download; snapshot_download("knowledgator/gliclass-modern-base-v2.0")'

# Laya (all stock checkpoints)
sudo -u defang HF_HOME=/var/lib/MIMEDefang/ml/huggingface \
    /opt/mimedefang-ml/venv/bin/python3 -c \
    'from laya import Router; Router(preload=True)'
```

## Running

### By hand

```sh
/opt/mimedefang-ml/venv/bin/python3 mimedefang-gliclass-server --port 8688
/opt/mimedefang-ml/venv/bin/python3 mimedefang-laya-server --port 8687 --preload english,multilingual
```

Useful options (both servers; `--help` lists them all):

| Option             | Meaning                                                                |
|--------------------|------------------------------------------------------------------------|
| `--host`, `--port` | Address to listen on (default `127.0.0.1`), see [Security](#security)   |
| `--threads`        | Requests handled at once, see [Sizing](#sizing)                         |
| `--torch-threads`  | CPU threads per request, see [Sizing](#sizing)                          |
| `--min-confidence` | Logging threshold, keep it equal to `$Mail::MIMEDefang::ML::Config{min_confidence}` |
| `--daemon`         | Fork into the background and log to syslog                              |

GLiClass also takes `--model` (a Hugging Face name or a local path; the
default is `knowledgator/gliclass-modern-base-v2.0`, and
`knowledgator/gliclass-modern-large-v2.0` is more accurate but slower) and
`--device` (`cpu`, or e.g. `cuda:0`). Laya also takes `--preload`,
`--checkpoint` and `--attach-language`.

### Under systemd

```sh
cp ../../systemd-units/mimedefang-gliclass-server.service /etc/systemd/system/
cp ../../systemd-units/mimedefang-laya-server.service     /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now mimedefang-gliclass-server   # and/or mimedefang-laya-server
```

The units run the server as the `defang` user. They start it before the
MIMEDefang multiplexor when both are enabled, and keep the model cache in
`/var/lib/MIMEDefang/ml`. systemd creates it, together with
`/var/lib/MIMEDefang` if that doesn't exist yet, and gives only the `ml`
subdirectory to `defang`. Settings can be overridden in
`/etc/sysconfig/mimedefang-<name>-server` (Fedora/RHEL) or
`/etc/default/mimedefang-<name>-server` (Debian/Ubuntu), as `NAME=value`
lines:

| Variable | Default | Unit |
|---|---|---|
| `ML_PYTHON` | `/opt/mimedefang-ml/venv/bin/python3` | both |
| `HF_HOME` | `/var/lib/MIMEDefang/ml/huggingface` | both |
| `HF_HUB_OFFLINE` | unset; `1` stops contacting huggingface.co | both |
| `GLICLASS_HOST`, `GLICLASS_PORT` | `127.0.0.1`, `8688` | gliclass |
| `GLICLASS_THREADS`, `GLICLASS_TORCH_THREADS` | `8`, `2` | gliclass |
| `GLICLASS_MODEL` | `knowledgator/gliclass-modern-base-v2.0` | gliclass |
| `GLICLASS_DEVICE` | `cpu` | gliclass |
| `LAYA_HOST`, `LAYA_PORT` | `127.0.0.1`, `8687` | laya |
| `LAYA_THREADS`, `LAYA_TORCH_THREADS` | `8`, `2` | laya |
| `LAYA_PRELOAD` | unset (all stock checkpoints) | laya |
| `LAYA_CHECKPOINT`, `LAYA_ATTACH_LANGUAGE` | unset | laya |

If you installed the modules another way, point `ML_PYTHON` at the Python
that has them, e.g. `ML_PYTHON=/usr/bin/python3` for distribution packages.

### Checking that it works

```sh
curl http://127.0.0.1:8688/health
curl -s http://127.0.0.1:8688/predict -H 'Content-Type: application/json' -d '{
  "text": "Subject: You won!\n\nClaim your prize, send your bank details today.",
  "labels": {"is_spam": "spam, unsolicited bulk mail, advertising or scam"}
}'

curl http://127.0.0.1:8687/health
curl -s http://127.0.0.1:8687/predict -H 'Content-Type: application/json' -d '{
  "state": {"subject": "You won!", "body": "Claim your prize, send your bank details today."},
  "questions": {"is_spam": {"type": "noul", "instructions": "Is this email spam?"}}
}'
```

The servers load the model before they start listening, so connections
are refused until loading has finished. That can take a minute, longer on
the first start while the model downloads.

## Model cache and offline use

Models are stored in the Hugging Face cache, `$HF_HOME` (the units use
`/var/lib/MIMEDefang/ml/huggingface`; by hand the default is
`~/.cache/huggingface`). Once the model is downloaded, set
`HF_HUB_OFFLINE=1` so the server starts without contacting huggingface.co.
The server then fails to start if the model is missing.

## GPU

- Install the CUDA build of torch (step 2, without the CPU index).
- GLiClass: run with `--device cuda:0` (`GLICLASS_DEVICE=cuda:0` in the unit).
- Laya: the server has no device option; the `laya` library picks the device.
- On a GPU, `--torch-threads` matters less, but `--threads` still limits how
  many requests run at once.

## Sizing

MIMEDefang calls the server synchronously, once per message, from every
worker that reaches `filter_end`. Under a burst of mail, a server can get
as many requests at once as the multiplexor has workers (its
`-x`/`MX_MAXIMUM` setting). So:

- Set `--threads` to about the multiplexor's maximum number of workers.
- Keep `--torch-threads` low (1-2). Otherwise torch uses every CPU core for
  each request, and several `--threads` then oversubscribe the machine
  instead of scaling.

## Security

The servers have **no authentication**, and every request carries message
content. The default `127.0.0.1` address keeps them reachable only from the
same host. If MIMEDefang runs on other hosts, listen on a network address
with `--host` and **limit access with a firewall**, so that only the
MIMEDefang hosts can reach the port. Never expose the servers to the
Internet. The same applies to Ollama, llama.cpp or vLLM when used with the
`openai` backend.

## Configuring MIMEDefang

In `/etc/mail/mimedefang-filter`:

```perl
use Mail::MIMEDefang::ML;

$Mail::MIMEDefang::ML::Config{backend}              = 'gliclass';
$Mail::MIMEDefang::ML::Config{gliclass}{server_url} = 'http://127.0.0.1:8688';
# or
# $Mail::MIMEDefang::ML::Config{backend}          = 'laya';
# $Mail::MIMEDefang::ML::Config{laya}{server_url} = 'http://127.0.0.1:8687';
```

See `examples/example-filter-with-ml` for a complete filter, and
`perldoc Mail::MIMEDefang::ML` for every setting. To try a filter on a
single message without running MIMEDefang:

```sh
mimedefang-test-mail -f /etc/mail/mimedefang-filter message.eml
```
