#!/bin/bash

# basic files
ROOTFS_IMG_NAME="rootfs.qcow2"
ROOTFS_IMG_PATH="./$ROOTFS_IMG_NAME"
BZIMAGE_PATH="./bzImage"
QEMU_BIN_PATH="qemu-system-x86_64"

# vm configurations
CPU_PARAM="kvm64,+smep,+smap"
MM_PARAM="128M"
SMP_PARAM="cores=2,threads=2"
APPEND_PARAM="console=ttyS0 root=/dev/sda rw rdinit=/sbin/init quiet nokaslr pti=on oops=panic panic=1 loglevel=3"
MONITOR_PARAM="/dev/null"
MACHINE_PARAM="q35"
EXTRA_PARAM="-no-reboot -nographic -s"

# chal env
TMP_DIR_PATH=""
QEMU_PID=""
FLAG_PATH="./flag"

function prepare_env()
{
    trap 'err_exit $LINENO;' ERR

    TMP_DIR_PATH=$(mktemp -d)
    cp $ROOTFS_IMG_PATH $TMP_DIR_PATH/
    cp $BZIMAGE_PATH $TMP_DIR_PATH/
    cp $FLAG_PATH $TMP_DIR_PATH/
}

function run_chal()
{
    trap 'err_exit $LINENO;' ERR

    $QEMU_BIN_PATH \
        -cpu $CPU_PARAM \
        -m $MM_PARAM \
        -smp $SMP_PARAM \
        -append "${APPEND_PARAM}" \
        -monitor $MONITOR_PARAM \
        -kernel $TMP_DIR_PATH/bzImage \
        -machine $MACHINE_PARAM \
        -hda $TMP_DIR_PATH/$ROOTFS_IMG_NAME \
        -hdb $TMP_DIR_PATH/flag \
        $EXTRA_PARAM

    QEMU_PID=$!
    wait $QEMU_PID
}

function clear_env()
{
    if [[ -n "$QEMU_PID" ]] && ps -p $QEMU_PID &> /dev/null; then
        echo "[*] Killing QEMU (pid=$QEMU_PID)..."
        kill -9 $QEMU_PID
    fi

    echo "[*] Cleaning up environment..."
    rm -rf $TMP_DIR_PATH
}

function err_exit()
{
    echo "[x] Failed to run the challenge, failed at script line $1"
    clear_env
    exit 1
}

function on_exit()
{
    echo "[*] Caught termination signal, exiting..."
    clear_env
    exit 0
}

function main() {
    trap on_exit SIGINT SIGTERM
    sudo qemu-nbd -c /dev/nbd0 rootfs.qcow2
    sudo mount /dev/nbd0 rootfs
    cd LKET/build
    make -j16
    cd ../..
    sudo cp LKET/build/exp rootfs
    sudo umount /dev/nbd0
    sudo qemu-nbd -d /dev/nbd0
    prepare_env
    run_chal
    clear_env
}

# running stage
main
