set -e
export VITASDK=$HOME/vitasdk
export PATH=$VITASDK/bin:$PATH
SRC=$(cd "$(dirname "$0")" && pwd)
W=$HOME/rrc
rm -rf $W && mkdir -p $W
cp "$SRC/retail_razorconnect.c" "$SRC/retail_razorconnect.yml" $W/
cd $W
echo "=== compile ==="
arm-vita-eabi-gcc -Wl,-q,-z,nocopyreloc -D__VITA_KERNEL__ -nostdlib \
  -mcpu=cortex-a9 -mthumb-interwork -Wall -O2 \
  -c retail_razorconnect.c -o rrc.o 2>&1 | head -40
echo "=== link ==="
arm-vita-eabi-gcc -Wl,-q,-z,nocopyreloc -nostdlib -mcpu=cortex-a9 \
  rrc.o -o rrc.elf \
  -lSceNetPsForDriver_stub -lSceThreadmgrForDriver_stub -lSceSysmemForDriver_stub \
  -lSceDebugForDriver_stub -lSceModulemgrForDriver_stub 2>&1 | head -40
echo "=== velf ==="
vita-elf-create -e retail_razorconnect.yml rrc.elf rrc.velf 2>&1 | head -20
echo "=== fself ==="
vita-make-fself -c rrc.velf retail_razorconnect.skprx 2>&1 | head -10
ls -la retail_razorconnect.skprx
