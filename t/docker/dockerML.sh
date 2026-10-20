#!/bin/sh

# Run the live tests of Mail::MIMEDefang::ML (t/ml.t) against the
# mimedefang/laya and mimedefang/gliclass servers.  Runs inside the
# mimedefang-ml-ci container of docker-compose-ml.yml; start it with
# "sh t/run-tests.sh ml" from the top of the source tree.

# Poll /health rather than relying on the image's healthcheck: on the first
# start Laya downloads several checkpoints, which can outlast the
# healthcheck's start period and mark the container unhealthy meanwhile.
TIMEOUT=${ML_WAIT_TIMEOUT:-1200}
for server in laya:8687 gliclass:8688; do
  waited=0
  until curl -sf "http://$server/health" >/dev/null; do
    if [ "$waited" -ge "$TIMEOUT" ]; then
      echo "ML server $server not ready after ${TIMEOUT}s"
      exit 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
  echo ">>> Server $server is ready"
done

FAILED=""
for server in laya:8687 gliclass:8688; do
  backend=${server%%:*}
  echo ">>> t/ml.t with the $backend backend..."
  env NET_TEST=yes ML_TEST_BACKEND=$backend ML_TEST_SERVER_URL="http://$server" \
    prove -It/lib -v t/ml.t || FAILED="$FAILED $backend"
done

if [ -n "$FAILED" ]; then
  echo "FAILED:$FAILED"
  exit 1
fi
echo "All ML backends passed"
