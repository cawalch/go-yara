#!/usr/bin/env bash
set -euo pipefail

: "${BASELINE_REF:?Set BASELINE_REF to the frozen baseline revision}"
: "${FINAL_REF:?Set FINAL_REF to the frozen final candidate revision}"
export GOMAXPROCS=2
study_dir="$PWD"
mkdir -p results
{
  uname -a
  lscpu
  go version
  go env GOARCH GOOS GOAMD64
  printf 'GOMAXPROCS=%s\nstudy=%s\n' "$GOMAXPROCS" "$(git rev-parse HEAD)"
  sha256sum compiler/{event_study,event_guard_study,two_stage_study,two_stage_small_study}_test.go .github/scripts/two-stage-study.sh
} > results/environment.txt
[[ "$(go env GOOS)/$(go env GOARCH)" == linux/amd64 ]] || { echo 'Linux amd64 required'; exit 1; }

variants=(baseline final)
revisions=("$BASELINE_REF" "$FINAL_REF")
work_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/two-stage-study.XXXXXX")"
trap 'rm -f "$study_dir"/results/*.test' EXIT
for i in "${!variants[@]}"; do
  variant="${variants[$i]}"
  checkout="$work_dir/$variant"
  revision="$(git rev-parse --verify "${revisions[$i]}^{commit}")"
  git worktree add --detach "$checkout" "$revision"
  cp compiler/{event_study,event_guard_study,two_stage_study,two_stage_small_study}_test.go "$checkout/compiler/"
  printf '%s %s\n' "$variant" "$revision" >> results/revisions.txt
  (cd "$checkout" && go test -c -tags=perfstudy -o "$study_dir/results/$variant.test" ./compiler) > "results/$variant-build.txt" 2>&1
  sha256sum "results/$variant.test" >> results/binaries.sha256
done

parity='^Test(TwoStageStudy(Parity|Reuse|LateParity)|EventStudyParity|ACEventGuardParity)$'
for variant in "${variants[@]}"; do
  "results/$variant.test" -test.run "$parity" -test.v > "results/$variant-parity.txt" 2>&1
done

bench='^Benchmark(TwoStageStudy|TwoStageLatePositive|TwoStageSmallStudy|EventStudy|ACEventGuard)$'
for round in 1 2 3 4 5 6; do
  order=(baseline final)
  if ((round % 2 == 0)); then order=(final baseline); fi
  for variant in "${order[@]}"; do
    printf 'round=%s variant=%s start=%s\n' "$round" "$variant" "$(date -u +%FT%TZ)" | tee -a results/order.txt
    "results/$variant.test" -test.run '^$' -test.bench "$bench" -test.benchtime=100ms -test.count=1 >> "results/$variant.txt" 2>&1
  done
done

for round in 1 2 3 4 5 6; do
  order=(baseline final)
  if ((round % 2 == 0)); then order=(final baseline); fi
  for variant in "${order[@]}"; do
    "results/$variant.test" -test.run '^$' -test.bench '^BenchmarkTwoStageCompile$' -test.benchtime=1x -test.count=1 >> "results/$variant-compile.txt" 2>&1
  done
done
for round in 1 2 3; do
  for variant in "${variants[@]}"; do
    "results/$variant.test" -test.run '^TestTwoStageStudyMemory$' -test.count=1 -test.v > "results/$variant-memory-$round.txt" 2>&1
  done
done
