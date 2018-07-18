#!/usr/bin/env bash

env GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/checkDNSZone *.go
env GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o bin/checkDNSZone.mac *.go
upx --force bin/*
