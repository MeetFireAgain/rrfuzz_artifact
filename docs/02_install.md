# install

## 1. prepare a clean qemu checkout

```bash
git clone https://github.com/qemu/qemu.git qemu-rrfuzz
cd qemu-rrfuzz
git checkout 95b9e0d2ade5d633fd13ffba96a54e87c65baf39
```

## 2. apply the artifact patches

```bash
bash /path/to/rrfuzz_artifact/scripts/apply_patches.sh "$PWD"
```

The script expects a clean git worktree rooted at the base commit above.

## 3. build user-mode qemu with rr-fuzz enabled

```bash
mkdir -p build
cd build
../configure \
  --target-list=x86_64-linux-user,mips-linux-user \
  --disable-system \
  --enable-rr-fuzzing
ninja qemu-x86_64 qemu-mips
```

If your local environment prefers direct Meson configuration, the equivalent feature is:
`-Drr_fuzzing=enabled`.

## 4. required local tools

- `bash`
- `python3`
- `gcc`
- `make`

Additional requirement for `samples/lightftp/`:
- `libgnutls` development headers and libraries
  - Ubuntu/Debian: `sudo apt-get install libgnutls28-dev`
  - (Note: the package is `libgnutls28-dev`, not `libgnutls-dev`)
