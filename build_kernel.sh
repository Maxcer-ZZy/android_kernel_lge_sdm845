#!/bin/bash
###############################################################################
# SDM845 Kernel Build Script
# 用法: bash build_kernel.sh [defconfig]
# 示例: bash build_kernel.sh lineageos_judypn_defconfig
###############################################################################

set -e

DEFCONFIG="${1:-lineageos_judypn_defconfig}"
ARCH=arm64
CROSS_COMPILE=aarch64-linux-gnu-
THREADS=$(nproc)
KERNEL_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${KERNEL_DIR}/out"
FINAL_DIR="${OUT_DIR}/sdm845"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }

# --- 安装依赖 ---
install_deps() {
    log "安装编译依赖..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        build-essential gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu \
        bison flex libssl-dev libelf-dev bc cpio zip unzip lz4 xz-utils \
        zlib1g-dev device-tree-compiler libncurses-dev python3 2>/dev/null
    log "依赖就绪"
}

# --- 检查工具链 ---
check_toolchain() {
    which ${CROSS_COMPILE}gcc >/dev/null 2>&1 || err "找不到 ${CROSS_COMPILE}gcc"
    log "工具链: $(${CROSS_COMPILE}gcc --version | head -1)"
}

# --- 清理 ---
do_clean() {
    log "清理编译产物..."
    cd "$KERNEL_DIR"
    make ARCH=$ARCH mrproper 2>/dev/null || true
}

# --- 编译 ---
do_build() {
    cd "$KERNEL_DIR"

    log "使用 defconfig: $DEFCONFIG"
    make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE $DEFCONFIG -j$THREADS

    log "开始编译 (${THREADS}线程)..."
    make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE -j$THREADS 2>&1 | tee "${OUT_DIR}/build.log"

    log "编译完成"
}

# --- 打包 ---
do_package() {
    mkdir -p "$FINAL_DIR"

    cd "$KERNEL_DIR"
    if [ -f arch/$ARCH/boot/Image.gz-dtb ]; then
        cp arch/$ARCH/boot/Image.gz-dtb "$FINAL_DIR/"
    elif [ -f arch/$ARCH/boot/Image.gz ]; then
        cp arch/$ARCH/boot/Image.gz "$FINAL_DIR/"
    elif [ -f arch/$ARCH/boot/Image ]; then
        gzip -9 -c arch/$ARCH/boot/Image > "$FINAL_DIR/Image.gz"
    else
        err "找不到内核镜像"
    fi

    # dtbo
    cp arch/$ARCH/boot/dtbo.img "$FINAL_DIR/" 2>/dev/null || true

    # 复制 defconfig 供参考
    cp arch/$ARCH/configs/$DEFCONFIG "$FINAL_DIR/" 2>/dev/null || true

    # 打 zip
    KVER=$(head -5 Makefile | grep VERSION | awk '{print $3}')
    KPATCH=$(head -5 Makefile | grep PATCHLEVEL | awk '{print $3}')
    KSUB=$(head -5 Makefile | grep SUBLEVEL | awk '{print $3}')
    ZIPNAME="MaxcerZzy-SDM845-${KVER}.${KPATCH}.${KSUB}.zip"

    cd "$FINAL_DIR"
    zip -r "${OUT_DIR}/${ZIPNAME}" .
    cd "$KERNEL_DIR"

    log "输出: ${OUT_DIR}/${ZIPNAME}"
    ls -lh "${OUT_DIR}/${ZIPNAME}"
}

# --- 主流程 ---
main() {
    echo "============================================"
    echo "  SDM845 Kernel Builder - maxcer_zzy"
    echo "  Features: BPF 5.10 + KSU + SusFS + BBG"
    echo "============================================"

    mkdir -p "$OUT_DIR"
    install_deps
    check_toolchain
    do_clean
    do_build
    do_package

    log "全部完成!"
    log "输出目录: $FINAL_DIR"
    log "ZIP文件: ${OUT_DIR}/${ZIPNAME}"
}

main "$@"
