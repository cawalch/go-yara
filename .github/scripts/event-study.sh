#!/usr/bin/env bash
set -euo pipefail

study_dir="$PWD"
mkdir -p results
{
  uname -a
  lscpu
  go version
  go env GOARCH GOOS GOAMD64
  sha256sum compiler/event_study_test.go compiler/event_guard_study_test.go
} > results/environment.txt

variants=(baseline approved anchor)
revisions=(98b7d5dc5d1641357ab87a0892230a957cb76620 fcd4e78 2d8d85e1b9f64d55c7c2c80f433415a020ce04b8)
for i in "${!variants[@]}"; do
  variant="${variants[$i]}"
  checkout="$RUNNER_TEMP/event-$variant"
  git worktree add --detach "$checkout" "${revisions[$i]}"
  cp compiler/event_study_test.go compiler/event_guard_study_test.go "$checkout/compiler/"
  printf '%s %s\n' "$variant" "$(git rev-parse "${revisions[$i]}")" >> results/revisions.txt
  (cd "$checkout" && go test -c -tags=perfstudy -o "$study_dir/results/$variant.test" ./compiler)
  "results/$variant.test" -test.run '^(TestEventStudyParity|TestHighEPSEventCorpusParity|TestACEventGuardParity)$' -test.v > "results/$variant-parity.txt"
done

bench='^(BenchmarkEventStudy|BenchmarkHighEPSSelectivity|BenchmarkHighEPSGateThenScan|BenchmarkHighEPSMatchingRulesSelectivity|BenchmarkACScanLargeInput|BenchmarkACEventGuard)$'
for round in 1 2 3 4 5 6; do
  order=(baseline approved anchor)
  if ((round % 2 == 0)); then order=(anchor approved baseline); fi
  for variant in "${order[@]}"; do
    printf 'round=%s variant=%s start=%s\n' "$round" "$variant" "$(date -u +%FT%TZ)" | tee -a results/order.txt
    "results/$variant.test" -test.run '^$' -test.bench "$bench" -test.benchtime=100ms -test.count=1 >> "results/$variant.txt"
  done
done
rm results/*.test
