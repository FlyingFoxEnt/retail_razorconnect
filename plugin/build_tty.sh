#!/bin/bash
# Builds rrc_tty.skprx (kernel console capture) and libRrcTty_stub_weak.a, the
# import library build_user.sh links the SceShell plugin against.
# Run from WSL with VitaSDK at $HOME/vitasdk:  bash build_tty.sh
set -euo pipefail
export VITASDK=$HOME/vitasdk
export PATH=$VITASDK/bin:$PATH
SRC=$(cd "$(dirname "$0")" && pwd)
W=$HOME/rrct
rm -rf "$W" && mkdir -p "$W"
cp "$SRC/rrc_tty.c" "$SRC/rrc_tty.h" "$SRC/rrc_tty.yml" "$W/"
cd "$W"

echo "=== compile ==="
arm-vita-eabi-gcc -Wl,-q -nostdlib -mcpu=cortex-a9 -mthumb-interwork \
  -Wall -Wextra -Wno-attribute-alias -O2 -ffreestanding -fno-builtin -c rrc_tty.c -o rrc_tty.o

echo "=== link ==="
arm-vita-eabi-gcc -Wl,-q -nostdlib -mcpu=cortex-a9 rrc_tty.o -o rrc_tty.elf \
  -lSceDebugForKernel_363_stub -lSceDebugForDriver_stub \
  -lSceThreadmgrForDriver_stub -lSceSysmemForDriver_stub \
  -lSceSysclibForDriver_stub -lSceCpuForDriver_stub -lgcc

echo "=== velf / fself ==="
vita-elf-create -e rrc_tty.yml rrc_tty.elf rrc_tty.velf
vita-make-fself -c rrc_tty.velf rrc_tty.skprx

echo "=== user import stub ==="
vita-elf-export k rrc_tty.elf rrc_tty.yml rrc_tty_nids.yml
vita-libs-gen rrc_tty_nids.yml stubs
# No make on this machine: assemble the weak variant by hand.
cd stubs
objs=()
for s in rrc_tty_RrcTty_*.S; do
  o="${s%.S}.wo"
  arm-vita-eabi-as --defsym GEN_WEAK_EXPORTS=1 "$s" -o "$o"
  objs+=("$o")
done
arm-vita-eabi-ar rcs libRrcTty_stub_weak.a "${objs[@]}"
cd ..

cp rrc_tty.skprx stubs/libRrcTty_stub_weak.a "$SRC/"
ls -la "$SRC/rrc_tty.skprx" "$SRC/libRrcTty_stub_weak.a"
