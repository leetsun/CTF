cd core
if [ -f core.cpio ]; then
    rm -f core.cpio
    ./gen_cpio.sh core.cpio
else
    ./gen_cpio.sh core.cpio
fi
cd ..
rm -f core.cpio
cp ./core/core.cpio ./
qemu-system-x86_64 \
-m 256M \
-kernel ./bzImage \
-initrd  ./core.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr useradd" \
-gdb tcp::1234 \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic  \

