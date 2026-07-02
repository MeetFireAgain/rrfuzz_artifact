# RR-Fuzz Vulnerable Test Program v2.0

## Overview

This is a multi-vulnerability test program specifically designed for RR-Fuzz. It contains 5 common vulnerability types to validate RR-Fuzz's vulnerability discovery capability.

---

## Design Features

### 1. **Syscall-based Input** ✅
- Uses `read(STDIN_FILENO, ...)` to receive input
- RR-Fuzz can mutate the return data and return value of `read()`
- Compatible with AFL/LibFuzzer input methods

### 2. **Multiple Vulnerability Types** 🐛
- Covers 5 common vulnerability types
- Each vulnerability is easy to trigger
- Suitable for demonstrating and testing fuzzer capabilities

### 3. **Smart Path Selection** 🔀
- Selects the vulnerability type based on the first byte of input
- `input[0] % 5` determines which vulnerability function to execute
- Maximizes code coverage

---

## Included Vulnerability Types

### Vulnerability 1: Classic Buffer Overflow

**Trigger condition**: First input byte `% 5 == 0`

```c
void vuln_buffer_overflow(const char *input, size_t len) {
    char buffer[16];  // 16-byte buffer
    memcpy(buffer, input, len);  // Overflow when len > 16
}
```

**How to trigger**:
- Input: `\x00` + `AAAAAAAAAAAAAAAAAAA` (20 A's)
- Effect: Writing more than 16 bytes causes stack overflow

**Difficulty**: ⭐ (Easy)

---

### Vulnerability 2: Length-based Overflow

**Trigger condition**: First input byte `% 5 == 1`

```c
void vuln_length_based(const char *input, uint32_t len) {
    char buffer[32];
    if (len > 0 && len < 1000) {  // Weak check
        memcpy(buffer, input, len);  // Overflow when len > 32
    }
}
```

**Input format**:
```
[0] Type byte = 0x01
[1-4] Length parameter (uint32_t, little-endian)
[5+] Data content
```

**How to trigger**:
- Input: `\x01\x40\x00\x00\x00AAAAAA...` (length=64)
- Effect: Trusts user-supplied length, causing overflow

**Difficulty**: ⭐⭐ (Medium)

---

### Vulnerability 3: Off-by-One Error

**Trigger condition**: First input byte `% 5 == 2`

```c
void vuln_off_by_one(const char *input, size_t len) {
    char buffer[20];
    for (i = 0; i <= len && i < sizeof(buffer); i++) {  // <= is wrong
        buffer[i] = input[i];
    }
}
```

**How to trigger**:
- Input: `\x02` + 20 characters
- Effect: Loop executes one extra iteration, writing to `buffer[20]`

**Difficulty**: ⭐⭐⭐ (Hard, requires precise length)

---

### Vulnerability 4: Buffer Overflow via Integer Overflow

**Trigger condition**: First input byte `% 5 == 3`

```c
void vuln_integer_overflow(const char *input, uint32_t count, uint32_t size) {
    char buffer[64];
    uint32_t total = count * size;  // Integer overflow
    if (total < sizeof(buffer)) {   // Check is bypassed
        memcpy(buffer, input, total);
    }
}
```

**Input format**:
```
[0] Type byte = 0x03
[1-4] count (uint32_t)
[5-8] size (uint32_t)
[9+] Data content
```

**How to trigger**:
- Input: `\x03\x00\x00\x00\x80\x02\x00\x00\x00AAAA...`
- count = 0x80000000 (2^31)
- size = 2
- total = 0 (overflow), bypassing the check

**Difficulty**: ⭐⭐⭐⭐ (Very hard, requires specific integer combination)

---

### Vulnerability 5: Stack Overflow (Deep Recursion)

**Trigger condition**: First input byte `% 5 == 4`

```c
int vuln_stack_overflow(const char *input, int depth) {
    char local_buffer[256];  // 256 bytes per recursion level
    if (depth > 0 && depth < 10000) {
        memset(local_buffer, 'A', sizeof(local_buffer));
        return vuln_stack_overflow(input, depth - 1) + 1;
    }
    return 0;
}
```

**Input format**:
```
[0] Type byte = 0x04
[1-4] depth (int32_t)
[5+] Data content
```

**How to trigger**:
- Input: `\x04\x00\x10\x00\x00DATA` (depth = 4096)
- Effect: 4096 × 256 = 1MB stack consumption, stack overflow

**Difficulty**: ⭐⭐ (Medium, but requires a large recursion depth)

---

## Usage

### Quick Test

```bash
cd /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests

# Run the full test suite
./test_vuln_v2.sh
```

### Manually Test a Specific Vulnerability

```bash
# Compile
gcc -o vuln_v2 vuln_stdin.c -g -no-pie -O0 -fno-stack-protector

# Test vulnerability type 0 (buffer overflow)
printf '\x00AAAAAAAAAAAAAAAAAAA' | ./vuln_v2

# Test vulnerability type 1 (length overflow)
printf '\x01\x40\x00\x00\x00AAAAAAAAAAAAAAAA' | ./vuln_v2

# Test vulnerability type 4 (stack overflow)
printf '\x04\x00\x10\x00\x00DATA' | ./vuln_v2
```

### RR-Fuzz Testing

```bash
QEMU="/path/to/qemu-x86_64"
VULN="./vuln_v2"

# 1. Record trace
printf '\x00hello' | RR_FUZZING_ENABLED=1 RR_MODE=record \
    RR_TRACE_FILE=vuln.dat $QEMU $VULN

# 2. Single-process fuzzing
cd ../fuzzing
python3 fuzz_conductor.py \
    --qemu $QEMU \
    --target $VULN \
    --trace vuln.dat \
    --iterations 1000

# 3. Multi-process fuzzing
python3 multiprocess/fuzz_master.py \
    -n 4 \
    -p $VULN \
    -q $QEMU \
    -t ./traces/ \
    -s ./sync_dir/
```

---

## Expected Results

### Single-process Mode (100 iterations/type)

| Vulnerability Type | Expected Crash | Difficulty | Notes |
|---------|---------|------|------|
| Type 0 | ✅ High | Easy | Simple length mutation can trigger |
| Type 1 | ✅ Medium | Medium | Requires mutating the length parameter |
| Type 2 | ⚠️ Low | Hard | Requires very precise off-by-one |
| Type 3 | ⚠️ Low | Very hard | Requires specific integer combination |
| Type 4 | ✅ Medium | Medium | Requires large recursion depth value |

### Multi-process Mode (4 workers × 60 seconds)

- **Expected**: Higher crash discovery rate
- **Speedup**: 3-4x
- **Seeds growth**: +200-300%

---

## Compilation Options Explained

```bash
gcc -o vuln_v2 vuln_stdin.c \
    -g              # Debug info
    -no-pie         # Disable PIE (Position-Independent Executable)
    -O0             # Disable optimization
    -fno-stack-protector  # Disable stack protection (easier to trigger)
```

**Why disable protection mechanisms?**
- Stack protection detects buffer overflows and terminates the program before the crash
- Disabling it makes it easier to observe real memory corruption
- Simulates older programs without modern protection mechanisms

---

## RR-Fuzz Capability Demonstration

### ✅ Discoverable Vulnerabilities

1. **Simple Buffer Overflow** (Types 0, 1)
   - By mutating the return value of `read()` (`nread`)
   - By mutating the length field in the input data

2. **Input-based Vulnerabilities** (Types 1, 3)
   - By mutating input content via `aux_data`
   - Mutating structured input (length fields, counters)

3. **Deep State Vulnerabilities** (Type 4)
   - By mutating control flow parameters (recursion depth)

### ⚠️ Harder-to-Find Vulnerabilities

1. **Off-by-One** (Type 2)
   - Requires very precise length control
   - May require more iterations or recipe-based mutations

2. **Complex Integer Overflow** (Type 3)
   - Requires a specific integer combination
   - May require symbolic execution or constraint solving

---

## Learning Points

### 1. Importance of Syscall-based Input

**Wrong approach** ❌:
```c
int main(int argc, char *argv[]) {
    vulnerable_function(argv[1]);  // RR-Fuzz cannot mutate this
}
```

**Correct approach** ✅:
```c
int main() {
    char input[1024];
    read(STDIN_FILENO, input, 1024);  // RR-Fuzz can mutate this
    vulnerable_function(input);
}
```

### 2. Structured Input

The program selects code paths based on input structure:
- `input[0]` → Selects vulnerability type
- `input[1-4]` → Length/count parameter
- `input[5+]` → Actual data

This design:
- ✅ Maximizes code coverage
- ✅ Tests multiple vulnerability types
- ✅ Demonstrates fuzzer path exploration capability

### 3. Why Are Some Vulnerabilities Harder to Find?

- **Simple vulnerabilities**: Any "abnormal" input can trigger them
- **Complex vulnerabilities**: Require specific input patterns or value combinations
- **Solutions**:
  - Increase iteration count
  - Use PathFinder (CFG analysis)
  - Recipe-based mutations

---

## Related Documentation

- **Design Rationale**: `/linux-user/rr_fuzzing/why-vuln-program-doesnt-crash.md`
- **Multi-process Testing**: `/linux-user/rr_fuzzing/multiprocess-mode-test-report.md`
- **Fuzzing Architecture**: `/linux-user/rr_fuzzing/fuzzing/README.md`

---

## Next Steps

1. **Run tests**: `./test_vuln_v2.sh`
2. **View results**: Check generated logs and crashes
3. **Adjust parameters**: Increase iteration count, try multi-process mode
4. **Add new vulnerabilities**: Extend the program with more vulnerability types

---

*Document creation date: 2025-10-31*  
*Program version: v2.0*  
*Design goal: Demonstrate RR-Fuzz's multi-vulnerability discovery capability* 🎯
