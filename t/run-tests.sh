#!/bin/sh

docker compose -f t/docker/docker-compose-postfix.yml --project-directory . \
    --profile ci up --exit-code-from mimedefang-postfix-ci
docker compose -f t/docker/docker-compose-sendmail.yml --project-directory . \
    --profile ci up --exit-code-from mimedefang-sendmail-ci
