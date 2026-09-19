#!/usr/bin/env bash
set -euo pipefail

study_dir="$PWD"
mkdir -p results
{
  uname -a
  lscpu
  go version
  go env GOARCH GOOS GOAMD64
  sha256sum compiler/event_study_test.go
} > results/environment.txt

variants=(baseline routing required pairs combined)
revisions=(98b7d5dc5d1641357ab87a0892230a957cb76620 a1e44a3e9366eac4f840fb0302bb1e3543b90930 1f891d791c524e7f3d4e841ca3183aaf79f804b7 096e982a444bf844d6d5122f2b8217ceeff01f18 fd58dc622bba9467294ad00be33a3c116f7edb42)
for i in "${!variants[@]}"; do
  variant="${variants[$i]}"
  checkout="$RUNNER_TEMP/event-$variant"
  git worktree add --detach "$checkout" "${revisions[$i]}"
  cp compiler/event_study_test.go "$checkout/compiler/event_study_test.go"
  printf '%s %s\n' "$variant" "${revisions[$i]}" >> results/revisions.txt
  (cd "$checkout" && go test -c -tags=perfstudy -o "$study_dir/results/$variant.test" ./compiler)
  "results/$variant.test" -test.run '^(TestEventStudyParity|TestHighEPSEventCorpusParity)$' -test.v > "results/$variant-parity.txt"
done

bench='^(BenchmarkEventStudy|BenchmarkHighEPSSelectivity|BenchmarkHighEPSGateThenScan|BenchmarkHighEPSMatchingRulesSelectivity|BenchmarkACScanLargeInput)$'
for round in 1 2 3 4 5 6; do
  order=(baseline routing required pairs combined)
  if ((round % 2 == 0)); then order=(combined pairs required routing baseline); fi
  for variant in "${order[@]}"; do
    printf 'round=%s variant=%s start=%s\n' "$round" "$variant" "$(date -u +%FT%TZ)" | tee -a results/order.txt
    "results/$variant.test" -test.run '^$' -test.bench "$bench" -test.benchtime=100ms -test.count=1 >> "results/$variant.txt"
  done
done
rm results/*.test
