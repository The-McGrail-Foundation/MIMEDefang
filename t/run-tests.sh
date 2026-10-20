#!/bin/sh

# Run the test suites in Docker containers: the Postfix and Sendmail CI
# containers and the live ML tests against the Laya/GLiClass servers.
# Run from the top of the source tree.  With arguments, run only the
# named suites (postfix, sendmail, ml).  ML_IMAGE_TAG selects the ML
# image tag (default: latest), ML_KEEP=1 leaves the ML servers running.

run_postfix() {
  docker compose -f t/docker/docker-compose-postfix.yml --project-directory . \
      --profile ci up --exit-code-from mimedefang-postfix-ci
}

run_sendmail() {
  docker compose -f t/docker/docker-compose-sendmail.yml --project-directory . \
      --profile ci up --exit-code-from mimedefang-sendmail-ci
}

run_ml() {
  COMPOSE="docker compose -f t/docker/docker-compose-ml.yml --project-directory ."
  echo ">>> Starting the ML servers (the first start downloads the models)..."
  $COMPOSE up -d || return 1
  $COMPOSE --profile ci run --rm mimedefang-ml-ci
  rc=$?
  if [ "$rc" -ne 0 ]; then
    $COMPOSE logs --tail 20 laya gliclass
  fi
  if [ "${ML_KEEP:-0}" != "1" ]; then
    echo ">>> Stopping the ML servers..."
    $COMPOSE down 1>/dev/null 2>&1
  fi
  return $rc
}

SUITES=${*:-postfix sendmail ml}
FAILED=""
for suite in $SUITES; do
  case $suite in
    postfix|sendmail|ml) "run_$suite" || FAILED="$FAILED $suite" ;;
    *) echo "Unknown test suite: $suite"; exit 2 ;;
  esac
done

if [ -n "$FAILED" ]; then
  echo "FAILED:$FAILED"
  exit 1
fi
echo "All test suites passed"
