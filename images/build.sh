#!/bin/bash
# Build a minimal sealed VM image for DD.
# Output: dd-agent-vm.raw — bootable disk with dm-verity rootfs.
# Contents: kernel + dd-agent (PID 1) + cloudflared + ca-certs.
# No systemd, no package manager, no shell.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="${SCRIPT_DIR}/build"
OUTPUT="${SCRIPT_DIR}/dd-agent-vm.raw"
DD_AGENT="${SCRIPT_DIR}/../target/x86_64-unknown-linux-musl/release/dd-agent"
CLOUDFLARED="${SCRIPT_DIR}/image-extra/usr/local/bin/cloudflared"

# Sizes
ROOT_SIZE_MB=256
EFI_SIZE_MB=64
DISK_SIZE_MB=$((ROOT_SIZE_MB + EFI_SIZE_MB + 64))  # +64 for verity data

echo "==> Building sealed DD agent VM image"

# Check prerequisites
for bin in mke2fs mkfs.vfat veritysetup losetup sfdisk; do
    command -v "$bin" >/dev/null || { echo "ERROR: $bin not found"; exit 1; }
done
[ -f "$DD_AGENT" ] || { echo "ERROR: dd-agent not found at $DD_AGENT (run cargo build --release first)"; exit 1; }
[ -f "$CLOUDFLARED" ] || { echo "ERROR: cloudflared not found at $CLOUDFLARED"; exit 1; }

rm -rf "$WORK"
mkdir -p "$WORK"/{rootfs,initrd,efi}

# ── 1. Build rootfs ─────────────────────────────────────────────────────

echo "==> Creating rootfs"
ROOTFS="$WORK/rootfs"

mkdir -p "$ROOTFS"/{proc,sys,dev,dev/pts,tmp,run,etc,var/lib/dd/shared,var/lib/dd/workloads}

# Binaries
mkdir -p "$ROOTFS/usr/local/bin"
cp "$DD_AGENT" "$ROOTFS/usr/local/bin/dd-agent"
cp "$CLOUDFLARED" "$ROOTFS/usr/local/bin/cloudflared"
chmod +x "$ROOTFS/usr/local/bin/dd-agent" "$ROOTFS/usr/local/bin/cloudflared"

# dd-agent is statically linked (musl) — no shared libs needed
# cloudflared is Go, also statically linked

# dd-agent is init (PID 1)
ln -sf /usr/local/bin/dd-agent "$ROOTFS/init"

# CA certificates for HTTPS
mkdir -p "$ROOTFS/etc/ssl/certs"
cp /etc/ssl/certs/ca-certificates.crt "$ROOTFS/etc/ssl/certs/"

# Minimal /etc
echo "dd-agent" > "$ROOTFS/etc/hostname"
echo "nameserver 8.8.8.8" > "$ROOTFS/etc/resolv.conf"
cat > "$ROOTFS/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/false
EOF
cat > "$ROOTFS/etc/group" <<'EOF'
root:x:0:
EOF

# Busybox for networking (ip, udhcpc) — statically linked, no shared libs
if command -v busybox >/dev/null; then
    cp "$(command -v busybox)" "$ROOTFS/usr/local/bin/busybox"
    # Symlink common tools dd-agent needs
    for cmd in mount umount ip udhcpc sh; do
        ln -sf /usr/local/bin/busybox "$ROOTFS/usr/local/bin/$cmd"
    done
    mkdir -p "$ROOTFS/sbin" "$ROOTFS/bin"
    ln -sf /usr/local/bin/busybox "$ROOTFS/sbin/ip"
    ln -sf /usr/local/bin/busybox "$ROOTFS/bin/mount"
    ln -sf /usr/local/bin/busybox "$ROOTFS/bin/umount"
    ln -sf /usr/local/bin/busybox "$ROOTFS/bin/sh"
    # udhcpc needs a script
    mkdir -p "$ROOTFS/usr/share/udhcpc"
    cat > "$ROOTFS/usr/share/udhcpc/default.script" <<'DHCP'
#!/bin/sh
export PATH="/usr/local/bin:/sbin:/bin:/usr/bin"
case "$1" in
    bound|renew)
        ip addr flush dev "$interface" 2>/dev/null
        ip addr add "$ip/$mask" dev "$interface" 2>/dev/null
        if [ -n "$router" ]; then
            ip route add default via "$router" dev "$interface" 2>/dev/null
        fi
        if [ -n "$dns" ]; then
            echo "nameserver $dns" > /etc/resolv.conf
        fi
        echo "udhcpc: got ip=$ip mask=$mask router=$router dns=$dns" >&2
        ;;
esac
DHCP
    chmod +x "$ROOTFS/usr/share/udhcpc/default.script"
fi

echo "    rootfs size: $(du -sh "$ROOTFS" | cut -f1)"

# ── 2. Create rootfs ext4 image ─────────────────────────────────────────

echo "==> Creating rootfs ext4 image"
ROOT_IMG="$WORK/rootfs.img"
dd if=/dev/zero of="$ROOT_IMG" bs=1M count="$ROOT_SIZE_MB" status=none
mke2fs -t ext4 -d "$ROOTFS" -L ddroot "$ROOT_IMG" "${ROOT_SIZE_MB}M"

# ── 3. dm-verity ────────────────────────────────────────────────────────

echo "==> Setting up dm-verity"
VERITY_IMG="$WORK/verity.img"
VERITY_OUTPUT=$(veritysetup format "$ROOT_IMG" "$VERITY_IMG" 2>&1)
ROOT_HASH=$(echo "$VERITY_OUTPUT" | grep "Root hash:" | awk '{print $3}')
HASH_OFFSET=$(stat -c%s "$VERITY_IMG")

echo "    root hash: $ROOT_HASH"
echo "    verity data: $(du -sh "$VERITY_IMG" | cut -f1)"

# ── 4. Extract kernel from host (or use pre-downloaded) ─────────────────

echo "==> Extracting kernel"
KERNEL_VERSION=$(ls /lib/modules/ | sort -V | tail -1)
KERNEL="/boot/vmlinuz-${KERNEL_VERSION}"
[ -f "$KERNEL" ] || { echo "ERROR: kernel not found at $KERNEL"; exit 1; }
echo "    kernel: $KERNEL_VERSION"

# ── 5. Build initramfs ──────────────────────────────────────────────────

echo "==> Building initramfs"
INITRD_DIR="$WORK/initrd"
mkdir -p "$INITRD_DIR"/{bin,lib,proc,sys,dev,sysroot}

# Busybox for init script
if command -v busybox >/dev/null; then
    cp "$(command -v busybox)" "$INITRD_DIR/bin/busybox"
    for cmd in sh mount switch_root insmod modprobe cat grep tr; do
        ln -sf busybox "$INITRD_DIR/bin/$cmd"
    done
fi

# dm-verity kernel modules — decompress .ko.zst to .ko so busybox insmod can load them
MODDIR="/lib/modules/$KERNEL_VERSION"
mkdir -p "$INITRD_DIR/lib/modules/$KERNEL_VERSION"
for mod in dm-mod dm-verity dm-bufio; do
    modpath=$(find "$MODDIR" -name "${mod}.ko*" 2>/dev/null | head -1)
    if [ -n "$modpath" ]; then
        destdir="$INITRD_DIR/lib/modules/$KERNEL_VERSION/$(dirname "${modpath#$MODDIR/}")"
        mkdir -p "$destdir"
        case "$modpath" in
            *.zst) zstd -d "$modpath" -o "$destdir/${mod}.ko" 2>/dev/null ;;
            *.gz)  gunzip -c "$modpath" > "$destdir/${mod}.ko" ;;
            *)     cp "$modpath" "$destdir/" ;;
        esac
    fi
done
depmod -b "$INITRD_DIR" "$KERNEL_VERSION" 2>/dev/null || true

# Init script — load dm-verity, mount rootfs, switch_root to dd-agent
cat > "$INITRD_DIR/init" <<INIT
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

# Load dm-verity modules (insmod directly — busybox modprobe may not find them)
for ko in /lib/modules/*/kernel/drivers/md/dm-mod.ko \
          /lib/modules/*/kernel/drivers/md/dm-bufio.ko \
          /lib/modules/*/kernel/drivers/md/dm-verity.ko; do
    [ -f "\$ko" ] && insmod "\$ko" 2>/dev/null
done

# Get root hash from kernel cmdline
ROOTHASH=\$(cat /proc/cmdline | tr ' ' '\n' | grep '^dd.roothash=' | cut -d= -f2)

if [ -n "\$ROOTHASH" ]; then
    # Set up dm-verity verified root
    veritysetup open /dev/vda2 ddroot /dev/vda3 "\$ROOTHASH" 2>/dev/null
    mount -o ro /dev/mapper/ddroot /sysroot
else
    # Fallback: mount without verification (development only)
    mount -o ro /dev/vda2 /sysroot
fi

# Switch to real rootfs, exec dd-agent as PID 1
exec switch_root /sysroot /init
INIT
chmod +x "$INITRD_DIR/init"

# Copy veritysetup into initrd
if command -v veritysetup >/dev/null; then
    cp "$(command -v veritysetup)" "$INITRD_DIR/bin/"
    for lib in $(ldd "$(command -v veritysetup)" 2>/dev/null | awk '/=>/{print $3}' | sort -u); do
        dir="$INITRD_DIR$(dirname "$lib")"
        mkdir -p "$dir"
        cp "$lib" "$dir/" 2>/dev/null || true
    done
    local_ld=$(ldd "$(command -v veritysetup)" 2>/dev/null | awk '/ld-linux/{print $1}')
    if [ -n "$local_ld" ]; then
        mkdir -p "$INITRD_DIR$(dirname "$local_ld")"
        cp "$local_ld" "$INITRD_DIR$local_ld" 2>/dev/null || true
    fi
fi

# Create cpio archive
INITRD="$WORK/initrd.cpio.gz"
(cd "$INITRD_DIR" && find . | cpio -o -H newc 2>/dev/null | gzip -9) > "$INITRD"
echo "    initrd size: $(du -sh "$INITRD" | cut -f1)"

# ── 6. Create disk image ────────────────────────────────────────────────

echo "==> Creating disk image"

# Partition layout:
# 1: EFI System Partition (FAT32, kernel + initrd)
# 2: Root filesystem (ext4, dm-verity protected)
# 3: Verity hash data

dd if=/dev/zero of="$OUTPUT" bs=1M count="$DISK_SIZE_MB" status=none

# Create partition table
sfdisk "$OUTPUT" <<PARTS
label: gpt
size=${EFI_SIZE_MB}M, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI"
size=${ROOT_SIZE_MB}M, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="root"
type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="verity"
PARTS

# Write partitions via loopback
LOOP=$(losetup --find --show --partscan "$OUTPUT")
trap "losetup -d $LOOP" EXIT

# EFI partition
mkfs.vfat -F 32 "${LOOP}p1"
EFI_MNT="$WORK/efi_mnt"
mkdir -p "$EFI_MNT"
mount "${LOOP}p1" "$EFI_MNT"
mkdir -p "$EFI_MNT/EFI/BOOT"

# Create unified kernel image (kernel + initrd + cmdline)
CMDLINE="console=ttyS0 intel_iommu=on dd.roothash=${ROOT_HASH} root=/dev/mapper/ddroot ro"
echo "$CMDLINE" > "$WORK/cmdline.txt"

# Use ukify if available, otherwise just copy kernel + initrd
if command -v ukify >/dev/null; then
    ukify build \
        --linux="$KERNEL" \
        --initrd="$INITRD" \
        --cmdline="@$WORK/cmdline.txt" \
        --output="$EFI_MNT/EFI/BOOT/BOOTX64.EFI" 2>/dev/null || {
        # Fallback: copy separately
        cp "$KERNEL" "$EFI_MNT/EFI/BOOT/vmlinuz"
        cp "$INITRD" "$EFI_MNT/EFI/BOOT/initrd.img"
    }
else
    cp "$KERNEL" "$EFI_MNT/EFI/BOOT/vmlinuz"
    cp "$INITRD" "$EFI_MNT/EFI/BOOT/initrd.img"
fi

umount "$EFI_MNT"

# Root partition
dd if="$ROOT_IMG" of="${LOOP}p2" bs=4M status=none

# Verity partition
dd if="$VERITY_IMG" of="${LOOP}p3" bs=4M status=none

# Cleanup
losetup -d "$LOOP"
trap - EXIT

# ── 7. Summary ──────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Sealed VM image built: $OUTPUT"
echo "  Size: $(du -sh "$OUTPUT" | cut -f1)"
echo "  Root hash: $ROOT_HASH"
echo "  Kernel: $KERNEL_VERSION"
echo "  Contents: dd-agent (PID 1) + cloudflared + ca-certs"
echo ""
echo "  Boot with:"
echo "    qemu-system-x86_64 \\"
echo "      -machine q35,confidential-guest-support=tdx \\"
echo "      -object tdx-guest,id=tdx \\"
echo "      -cpu host -m 4G -smp 4 \\"
echo "      -drive file=$OUTPUT,format=raw,if=virtio \\"
echo "      -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \\"
echo "      -nographic"
echo "═══════════════════════════════════════════════════════════"
