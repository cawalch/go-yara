#include <cuda_runtime.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

constexpr size_t kEventBytes = 256;

void check(cudaError_t error, const char* operation) {
  if (error != cudaSuccess) {
    throw std::runtime_error(std::string(operation) + ": " +
                             cudaGetErrorString(error));
  }
}

__global__ void touchEvents(const uint8_t* input, uint8_t* output,
                            size_t bytes) {
  const size_t index = blockIdx.x * blockDim.x + threadIdx.x;
  if (index < bytes) {
    output[index] = static_cast<uint8_t>(input[index] ^ 0x5a);
  }
}

void runBatch(size_t events) {
  const size_t bytes = events * kEventBytes;
  uint8_t* host = nullptr;
  uint8_t* device_input = nullptr;
  uint8_t* device_output = nullptr;
  check(cudaMallocHost(&host, bytes), "cudaMallocHost");
  check(cudaMalloc(&device_input, bytes), "cudaMalloc input");
  check(cudaMalloc(&device_output, bytes), "cudaMalloc output");
  std::fill(host, host + bytes, static_cast<uint8_t>('x'));

  const int blocks = static_cast<int>((bytes + 255) / 256);
  for (int warmup = 0; warmup < 10; ++warmup) {
    check(cudaMemcpyAsync(device_input, host, bytes, cudaMemcpyHostToDevice),
          "warmup memcpy");
    touchEvents<<<blocks, 256>>>(device_input, device_output, bytes);
  }
  check(cudaDeviceSynchronize(), "warmup synchronize");

  const size_t iterations =
      std::clamp<size_t>((4ULL << 30) / bytes, 100, 100000);
  cudaEvent_t start;
  cudaEvent_t end;
  check(cudaEventCreate(&start), "create start event");
  check(cudaEventCreate(&end), "create end event");
  check(cudaEventRecord(start), "record start");
  for (size_t iteration = 0; iteration < iterations; ++iteration) {
    check(cudaMemcpyAsync(device_input, host, bytes, cudaMemcpyHostToDevice),
          "memcpy");
    touchEvents<<<blocks, 256>>>(device_input, device_output, bytes);
  }
  check(cudaEventRecord(end), "record end");
  check(cudaEventSynchronize(end), "synchronize end");
  float milliseconds = 0;
  check(cudaEventElapsedTime(&milliseconds, start, end), "elapsed time");

  const double seconds = milliseconds / 1000.0;
  const double batches = static_cast<double>(iterations);
  const double total_events = batches * events;
  std::cout << "engine=cuda-floor event_bytes=" << kEventBytes
            << " batch_events=" << events << " iterations=" << iterations
            << " us_per_batch=" << seconds * 1e6 / batches
            << " ns_per_event=" << seconds * 1e9 / total_events
            << " eps=" << total_events / seconds
            << " host_to_device_gbps="
            << total_events * kEventBytes / seconds / 1e9 << '\n';

  cudaEventDestroy(start);
  cudaEventDestroy(end);
  cudaFree(device_output);
  cudaFree(device_input);
  cudaFreeHost(host);
}

}  // namespace

int main() {
  try {
    for (size_t events : {1, 8, 64, 1024, 16384, 65536, 131072}) {
      runBatch(events);
    }
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
