#!/bin/bash
# Builds rrc_pa.skprx (kernel: thread/module lists and the CPU sampler behind Razor's
# CPU trace) and libRrcPa_stub_weak.a, which build_user.sh links the SceShell plugin to.
# Run from WSL with VitaSDK at $HOME/vitasdk:  bash build_pa.sh
set -euo pipefail
export VITASDK=$HOME/vitasdk
export PATH=$VITASDK/bin:$PATH
SRC=$(cd "$(dirname "$0")" && pwd)
W=$HOME/rrcpa
rm -rf "$W" && mkdir -p "$W"
cp "$SRC/rrc_pa.c" "$SRC/rrc_pa.h" "$SRC/rrc_pa.yml" "$SRC/pa_encode.c" "$SRC/pa_encode.h" \
   "$SRC/pa_trace.c" "$SRC/pa_trace.h" "$W/"
cd "$W"

echo "=== compile ==="
for f in rrc_pa pa_encode pa_trace; do
  arm-vita-eabi-gcc -Wl,-q -nostdlib -mcpu=cortex-a9 -mthumb-interwork \
    -Wall -Wextra -Wno-attribute-alias -O2 -ffreestanding -fno-builtin -c $f.c -o $f.o
done

echo "=== link ==="
arm-vita-eabi-gcc -Wl,-q -nostdlib -mcpu=cortex-a9 rrc_pa.o pa_encode.o pa_trace.o -o rrc_pa.elf \
  -lSceThreadmgrForDriver_stub -lSceModulemgrForKernel_363_stub \
  -lSceSysmemForDriver_stub -lSceSysclibForDriver_stub -lSceCpuForDriver_stub -lgcc

echo "=== velf / fself ==="
vita-elf-create -e rrc_pa.yml rrc_pa.elf rrc_pa.velf
vita-make-fself -c rrc_pa.velf rrc_pa.skprx

echo "=== user import stub ==="
vita-elf-export k rrc_pa.elf rrc_pa.yml rrc_pa_nids.yml
vita-libs-gen rrc_pa_nids.yml stubs
cd stubs
objs=()
for s in rrc_pa_RrcPa_*.S; do
  o="${s%.S}.wo"
  arm-vita-eabi-as --defsym GEN_WEAK_EXPORTS=1 "$s" -o "$o"
  objs+=("$o")
done
arm-vita-eabi-ar rcs libRrcPa_stub_weak.a "${objs[@]}"
cd ..

cp rrc_pa.skprx stubs/libRrcPa_stub_weak.a "$SRC/"
ls -la "$SRC/rrc_pa.skprx" "$SRC/libRrcPa_stub_weak.a"
