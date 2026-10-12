#!/bin/bash
# Builds retail_razorconnect.suprx, the SceShell plugin.
# Run build_tty.sh and build_pa.sh first: they produce libRrcTty_stub_weak.a and
# libRrcPa_stub_weak.a, imported weakly so the plugin still loads when
# rrc_tty.skprx / rrc_pa.skprx are not installed.
# Run from WSL with VitaSDK at $HOME/vitasdk:  bash build_user.sh
set -euo pipefail
export VITASDK=$HOME/vitasdk
export PATH=$VITASDK/bin:$PATH
SRC=$(cd "$(dirname "$0")" && pwd)
W=$HOME/rrcu
rm -rf "$W" && mkdir -p "$W"
cp "$SRC/rrc_user.c" "$SRC/rrc_user.yml" "$SRC/rrc_tty.h" "$SRC/libRrcTty_stub_weak.a" \
   "$SRC/rrc_pa.h" "$SRC/libRrcPa_stub_weak.a" "$SRC/pmon_trace.c" "$SRC/pmon_trace.h" "$W/"
cd "$W"

echo "=== compile ==="
for f in rrc_user pmon_trace; do
  arm-vita-eabi-gcc -Wl,-q,-z,nocopyreloc -nostdlib -mcpu=cortex-a9 -mthumb-interwork \
    -Wall -Wno-attribute-alias -O2 -ffreestanding -fno-builtin -c $f.c -o $f.o
done

echo "=== link ==="
# libgcc: 64-bit division in pmon_trace.c
arm-vita-eabi-gcc -Wl,-q,-z,nocopyreloc -nostdlib -mcpu=cortex-a9 \
  rrc_user.o pmon_trace.o -o rrc_user.elf -L. \
  -lSceLibKernel_stub -lSceKernelThreadMgr_stub -lSceNet_stub_weak -lSceNetCtl_stub_weak \
  -lSceIofilemgr_stub \
  -lSceSysmodule_stub -lScePower_stub -lSceKernelModulemgr_stub -lSceProcessmgr_stub \
  -lSceAppMgr_stub -lSceVshBridge_stub_weak -lRrcTty_stub_weak -lRrcPa_stub_weak \
  -lSceSysmem_stub -lgcc

echo "=== velf / fself ==="
vita-elf-create -e rrc_user.yml rrc_user.elf rrc_user.velf
vita-make-fself -c rrc_user.velf retail_razorconnect.suprx

cp retail_razorconnect.suprx "$SRC/"
ls -la "$SRC/retail_razorconnect.suprx"
