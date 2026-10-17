#!/bin/sh

# Run the live tests of Mail::MIMEDefang::ML (t/ml.t) against the
# mimedefang/laya and mimedefang/gliclass images.  Run from the top of the
# source tree.  ML_IMAGE_TAG selects the image tag (default: latest),
# ML_KEEP=1 leaves the servers running afterwards.

COMPOSE="docker compose -f t/docker/docker-compose-ml.yml --project-directory ."

cleanup() {
  if [ "${ML_KEEP:-0}" != "1" ]; then
    echo ">>> Stopping the ML servers..."
    $COMPOSE down 1>/dev/null 2>&1
  fi
}
trap cleanup EXIT INT TERM

echo ">>> Starting the ML servers (the first start downloads the models)..."
$COMPOSE up -d || exit 1

# Poll /health rather than relying on the image's healthcheck: on the first
# start Laya downloads several checkpoints, which can outlast the
# healthcheck's start period and mark the container unhealthy meanwhile.
TIMEOUT=${ML_WAIT_TIMEOUT:-1200}
for port in 8687 8688; do
  waited=0
  until curl -sf "http://127.0.0.1:$port/health" >/dev/null; do
    if [ "$waited" -ge "$TIMEOUT" ]; then
      echo "ML server on port $port not ready after ${TIMEOUT}s"
      $COMPOSE logs --tail 20
      exit 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
  echo ">>> Server on port $port is ready"
done

FAILED=""
for backend in laya gliclass; do
  echo ">>> t/ml.t with the $backend backend..."
  env NET_TEST=yes ML_TEST_BACKEND=$backend prove -It/lib -v t/ml.t || FAILED="$FAILED $backend"
done

if [ -n "$FAILED" ]; then
  echo "FAILED:$FAILED"
  exit 1
fi
echo "All ML backends passed"
