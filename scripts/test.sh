# Copyright (C) 2023 Mya Pitzeruse
# SPDX-License-Identifier: MIT

cd integration

echo "initializing supporting services"
trap 'docker compose rm -fs' EXIT
docker compose up -d

echo "waiting for containers"
sleep 30

echo "running tests"
go test -v -race -covermode=atomic \
  -coverprofile=../coverage.integration.txt \
  -coverpkg=go.pitz.tech/gorm/encryption/... \
  ./...
