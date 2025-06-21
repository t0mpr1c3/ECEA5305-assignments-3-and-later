#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

CWD=$(pwd)
OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.15.163
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-
TOOLCHAIN=${FINDER_APP_DIR}/../arm-cross-compiler/arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-linux-gnu
SYSROOT=${TOOLCHAIN}/aarch64-none-linux-gnu/libc

#OLDPATH=${PATH}
#export PATH=${PATH}:${TOOLCHAIN}/bin


if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p ${OUTDIR}
if [ ! -d "${OUTDIR}" ]; then
	echo "Directory ${OUTDIR} could not be created";
	exit 1;
fi;

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
	#Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
	cd linux-stable
	echo "Checking out version ${KERNEL_VERSION}"
	git checkout ${KERNEL_VERSION}

	# TODO: Add your kernel build steps here
	make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- mrproper
	make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- defconfig
	make -j4 ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- all
	make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- modules
	make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- dtbs
fi

echo "Adding the Image in outdir"
cp ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}/Image

echo "Creating the staging directory for the root filesystem"
cd ${OUTDIR}
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
	sudo rm -rf ${OUTDIR}/rootfs
fi

# TODO: Create necessary base directories
mkdir -p ${OUTDIR}/rootfs
cd ${OUTDIR}/rootfs
mkdir -p bin dev etc home lib lib64 sbin proc sys tmp usr var 
mkdir -p usr/bin usr/sbin usr/lib var/log
 
cd ${OUTDIR}
if [ ! -d "${OUTDIR}/busybox" ]
then
	git clone git://busybox.net/busybox.git
	cd busybox
	git checkout ${BUSYBOX_VERSION}
	# TODO:  Configure busybox
else
	cd busybox
fi

# TODO: Make and install busybox
make distclean
make defconfig
make -j4 LDFLAGS="--static" ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}
make CONFIG_PREFIX=${OUTDIR}/rootfs ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} install
 
echo "Library dependencies"
cd ${OUTDIR}/rootfs
${CROSS_COMPILE}readelf -a bin/busybox | grep "program interpreter" # copy from sysroot to /lib
${CROSS_COMPILE}readelf -a bin/busybox | grep "Shared library"      # copy from sysroot to /lib64

# TODO: Add library dependencies to rootfs
cp ${SYSROOT}/lib/ld-linux-aarch64.so.1 lib/
cp ${SYSROOT}/lib64/libm.so.6 lib64/
cp ${SYSROOT}/lib64/libresolv.so.2 lib64/
cp ${SYSROOT}/lib64/libc.so.6 lib64/

# TODO: Make device nodes
# fails: put these commands in the init script
#cd ${OUTDIR}/rootfs
#mknod -m 666 dev/null c 1 3
#mknod -m 600 dev/console c 5 1

# Copy init script to /
cd ${CWD}
cp init ${OUTDIR}/rootfs/

# TODO: Copy the finder related scripts and executables to the /home directory
# on the target rootfs
HOME=${OUTDIR}/rootfs/home/
cd ${CWD}
cp autorun-qemu.sh ${HOME}
cp finder-test.sh ${HOME}
cp finder.sh ${HOME}
cp Makefile ${HOME}
cp writer.c ${HOME}
mkdir -p ${HOME}/conf
cp conf/* ${HOME}/conf
cp ${TOOLCHAIN}/bin/${CROSS_COMPILE}gcc ${HOME}

# TODO: Clean and build the writer utility
cd ${HOME}
make clean
make CROSS_COMPILE=${CROSS_COMPILE} writer

# TODO: Chown the root directory
chown root:root ${OUTDIR}/rootfs

# TODO: Create initramfs.cpio.gz
cd ${OUTDIR}/rootfs
find . | cpio -H newc -ov --owner root:root > ${OUTDIR}/initramfs.cpio # must be superuser to change owner
cd ${OUTDIR}
gzip -f initramfs.cpio

#export PATH=${OLDPATH}
