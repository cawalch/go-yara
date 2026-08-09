#include <hs/hs.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

struct MatchContext {
  uint64_t matches = 0;
  bool stop_after_first = false;
};

int onMatch(unsigned int, unsigned long long, unsigned long long, unsigned int,
            void* raw_context) {
  auto* context = static_cast<MatchContext*>(raw_context);
  ++context->matches;
  return context->stop_after_first ? 1 : 0;
}

std::string formatIndex(const char* format, int index) {
  char buffer[128];
  const int length = std::snprintf(buffer, sizeof(buffer), format, index);
  if (length < 0 || static_cast<size_t>(length) >= sizeof(buffer)) {
    throw std::runtime_error("formatted pattern overflow");
  }
  return std::string(buffer, static_cast<size_t>(length));
}

std::vector<std::string> makeExpressions(int rule_count, bool literal,
                                         const std::string& shape) {
  std::vector<std::string> expressions;
  expressions.reserve(static_cast<size_t>(rule_count));
  for (int index = 0; index < rule_count; ++index) {
    if (literal) {
      expressions.push_back(formatIndex("sig_%05d=deny_", index) +
                            formatIndex("%05d", index));
    } else if (shape == "unique") {
      expressions.push_back(formatIndex("sig_%05d=[A-Z]{2}[0-9]{6}", index));
    } else if (shape == "suffix") {
      expressions.push_back(formatIndex("[A-Z]{2}[0-9]{6}sig_%05d", index));
    } else if (shape == "duplicate") {
      expressions.emplace_back("sig_[0-9]{5}=[A-Z]{2}[0-9]{6}");
    } else if (shape == "bounded") {
      expressions.push_back(formatIndex(
          "(?:foo|bar|baz){16}sig_%05d=[A-Z]{2}[0-9]{6}", index));
    } else {
      throw std::runtime_error("unknown pattern shape: " + shape);
    }
  }
  return expressions;
}

std::vector<std::string> makeEvents(size_t event_size, size_t count,
                                    int rule_count, bool literal,
                                    const std::string& shape,
                                    const std::string& traffic) {
  std::vector<std::string> events;
  events.reserve(count);
  for (size_t index = 0; index < count; ++index) {
    char prefix_buffer[256];
    const int prefix_length = std::snprintf(
        prefix_buffer, sizeof(prefix_buffer),
        "{\"timestamp\":%zu,\"tenant\":\"tenant-%02zu\",\"src_ip\":"
        "\"10.20.%zu.%zu\",\"path\":\"/api/v1/events\",\"message\":\"",
        static_cast<size_t>(1800000000ULL + index), index % 32, index % 256,
        (index * 17) % 256);
    if (prefix_length < 0 ||
        static_cast<size_t>(prefix_length) >= sizeof(prefix_buffer)) {
      throw std::runtime_error("formatted event prefix overflow");
    }
    std::string payload;
    const bool positive = traffic == "dense" ||
                          (traffic == "sparse" && index % 100 == 0);
    if (positive) {
      const int rule_index = traffic == "dense"
                                 ? static_cast<int>(index % rule_count)
                                 : 0;
      if (literal) {
        payload = " " + formatIndex("sig_%05d=deny_", rule_index) +
                  formatIndex("%05d", rule_index);
      } else if (shape == "suffix") {
        payload = " AB123456" + formatIndex("sig_%05d", rule_index);
      } else if (shape == "bounded") {
        payload = " ";
        for (int repeat = 0; repeat < 16; ++repeat) {
          payload.append("foo");
        }
        payload.append(formatIndex("sig_%05d=AB123456", rule_index));
      } else {
        payload = " " + formatIndex("sig_%05d=AB123456", rule_index);
      }
    } else if (traffic == "common_miss") {
      payload = " sig_99999=AB123456";
    } else if (traffic == "near_miss") {
      payload = " sig_00000=ab12345x sig_00001=A1234567";
    } else if (traffic != "clean" && traffic != "sparse" &&
               traffic != "dense") {
      throw std::runtime_error("unknown traffic shape: " + traffic);
    }
    constexpr const char* suffix = "\"}";
    const size_t used = static_cast<size_t>(prefix_length) + payload.size() +
                        std::strlen(suffix);
    if (used > event_size) {
      throw std::runtime_error("event size is too small");
    }
    std::string event(prefix_buffer, static_cast<size_t>(prefix_length));
    event.append(event_size - used, 'x');
    event.append(payload);
    event.append(suffix);
    events.push_back(std::move(event));
  }
  return events;
}

}  // namespace

int main(int argc, char** argv) {
  const int rule_count = argc > 1 ? std::atoi(argv[1]) : 10000;
  const uint64_t iterations =
      argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 5000000;
  const std::string mode = argc > 3 ? argv[3] : "first";
  const bool literal = argc > 4 && std::string(argv[4]) == "literal";
  const std::string shape = argc > 5 ? argv[5] : "unique";
  const std::string traffic = argc > 6 ? argv[6] : "sparse";
  const size_t event_size =
      argc > 7 ? std::strtoull(argv[7], nullptr, 10) : 256;
  const bool stop_after_first = mode == "first";
  const bool report_som = mode == "som";

  auto expression_storage = makeExpressions(rule_count, literal, shape);
  std::vector<const char*> expressions;
  std::vector<unsigned int> flags;
  std::vector<unsigned int> ids;
  expressions.reserve(expression_storage.size());
  flags.reserve(expression_storage.size());
  ids.reserve(expression_storage.size());
  for (size_t index = 0; index < expression_storage.size(); ++index) {
    expressions.push_back(expression_storage[index].c_str());
    unsigned int expression_flags = 0;
    if (stop_after_first) {
      expression_flags |= HS_FLAG_SINGLEMATCH;
    }
    if (report_som) {
      expression_flags |= HS_FLAG_SOM_LEFTMOST;
    }
    flags.push_back(expression_flags);
    ids.push_back(static_cast<unsigned int>(index));
  }

  hs_database_t* database = nullptr;
  hs_compile_error_t* compile_error = nullptr;
  const auto compile_start = std::chrono::steady_clock::now();
  const hs_error_t compile_result = hs_compile_multi(
      expressions.data(), flags.data(), ids.data(),
      static_cast<unsigned int>(expressions.size()), HS_MODE_BLOCK, nullptr,
      &database, &compile_error);
  const auto compile_end = std::chrono::steady_clock::now();
  if (compile_result != HS_SUCCESS) {
    std::cerr << "compile failed";
    if (compile_error != nullptr) {
      std::cerr << " at expression " << compile_error->expression << ": "
                << compile_error->message;
      hs_free_compile_error(compile_error);
    }
    std::cerr << '\n';
    return 1;
  }

  size_t database_bytes = 0;
  if (hs_database_size(database, &database_bytes) != HS_SUCCESS) {
    std::cerr << "database size query failed\n";
    hs_free_database(database);
    return 1;
  }
  hs_scratch_t* scratch = nullptr;
  if (hs_alloc_scratch(database, &scratch) != HS_SUCCESS) {
    std::cerr << "scratch allocation failed\n";
    hs_free_database(database);
    return 1;
  }

  const auto events =
      makeEvents(event_size, 1024, rule_count, literal, shape, traffic);
  MatchContext context{0, stop_after_first};
  for (size_t index = 0; index < events.size(); ++index) {
    const auto& event = events[index];
    const hs_error_t result = hs_scan(database, event.data(), event.size(), 0,
                                      scratch, onMatch, &context);
    if (result != HS_SUCCESS && result != HS_SCAN_TERMINATED) {
      std::cerr << "warmup scan failed: " << result << '\n';
      return 1;
    }
  }
  context.matches = 0;

  const auto scan_start = std::chrono::steady_clock::now();
  for (uint64_t index = 0; index < iterations; ++index) {
    const auto& event = events[index & 1023];
    const hs_error_t result = hs_scan(database, event.data(), event.size(), 0,
                                      scratch, onMatch, &context);
    if (result != HS_SUCCESS && result != HS_SCAN_TERMINATED) {
      std::cerr << "scan failed: " << result << '\n';
      return 1;
    }
  }
  const auto scan_end = std::chrono::steady_clock::now();

  const double compile_seconds =
      std::chrono::duration<double>(compile_end - compile_start).count();
  const double scan_seconds =
      std::chrono::duration<double>(scan_end - scan_start).count();
  std::cout << "engine=libhs"
            << " version=\"" << hs_version() << "\""
            << " portfolio=" << (literal ? "literal" : "regex")
            << " mode=" << mode << " shape=" << shape
            << " traffic=" << traffic << " rules=" << rule_count
            << " event_bytes=" << event_size << " iterations=" << iterations
            << " matches=" << context.matches
            << " compile_s=" << compile_seconds
            << " database_bytes=" << database_bytes
            << " scan_s=" << scan_seconds
            << " ns_per_event=" << scan_seconds * 1e9 / iterations
            << " eps=" << iterations / scan_seconds
            << " gbps=" << iterations * event_size / scan_seconds / 1e9
            << '\n';

  hs_free_scratch(scratch);
  hs_free_database(database);
  return 0;
}
