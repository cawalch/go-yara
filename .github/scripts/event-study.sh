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

if [[ "$(lscpu | awk '/Vendor ID:/ {print $3}')" != AuthenticAMD ]]; then
  echo 'AMD regression validation: no timing on this non-AMD runner.' | tee results/runner-skipped.txt
  exit 0
fi

variants=(baseline approved fast anchor_fast)
revisions=(98b7d5dc5d1641357ab87a0892230a957cb76620 fcd4e78754aeba52bc90d0cb36a2bc3e28bb7bf2 78f9702eaa0548465a8d8c3ceec8a90ea3d4e7c3 8b6a6fbefe54a09858bb19d4ee7ffa6fe50e5a52)
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
  order=(baseline approved fast anchor_fast)
  if ((round % 2 == 0)); then order=(anchor_fast fast approved baseline); fi
  for variant in "${order[@]}"; do
    printf 'round=%s variant=%s start=%s\n' "$round" "$variant" "$(date -u +%FT%TZ)" | tee -a results/order.txt
    "results/$variant.test" -test.run '^$' -test.bench "$bench" -test.benchtime=100ms -test.count=1 >> "results/$variant.txt"
  done
done
rm results/*.test
