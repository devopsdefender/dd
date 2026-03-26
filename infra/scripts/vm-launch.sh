#!/usr/bin/env bash
# Launch a libvirt-managed VM from a baked qcow2 image.
set -euo pipefail

IMAGE=""
VM_NAME=""
CONFIG_FILE=""
MEMORY="4G"
CPUS="2"
PORT_FORWARDS=()
VFIO_DEVICE=""
TDX="false"
VM_DIR="/var/lib/devopsdefender/vms"
CONFIG_MODE="agent"
LIBVIRT_NETWORK="${LIBVIRT_NETWORK:-default}"

usage() {
  cat <<EOF
Usage: $0 [options]
  --image PATH          Base qcow2 image (required)
  --name NAME           VM name (required)
  --config PATH         JSON config file to inject via cloud-init (required)
  --config-mode MODE    Config target: agent (default) or control-plane
  --memory SIZE         VM memory (default: 4G)
  --cpus N              VM CPUs (default: 2)
  --port-forward H:G    Recorded for metadata only in libvirt mode
  --vfio-device ADDR    PCI device to pass through via VFIO (e.g. 0d:00.0)
  --tdx                 Request Intel TDX launch settings
EOF
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Error: required command not found: $1" >&2
    exit 1
  }
}

to_mib() {
  local value number unit
  value="${1^^}"
  if [[ "$value" =~ ^([0-9]+)([GM])I?B?$ ]]; then
    number="${BASH_REMATCH[1]}"
    unit="${BASH_REMATCH[2]}"
  elif [[ "$value" =~ ^([0-9]+)$ ]]; then
    echo "$value"
    return 0
  else
    echo "Error: unsupported memory value '$1' (use 4096, 4G, 8192M)" >&2
    exit 1
  fi

  if [ "$unit" = "G" ]; then
    echo $((number * 1024))
  else
    echo "$number"
  fi
}

escape_xml() {
  sed \
    -e 's/&/\&amp;/g' \
    -e 's/</\&lt;/g' \
    -e 's/>/\&gt;/g' \
    -e "s/'/\&apos;/g" \
    -e 's/"/\&quot;/g'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    --name) VM_NAME="$2"; shift 2 ;;
    --config) CONFIG_FILE="$2"; shift 2 ;;
    --config-mode) CONFIG_MODE="$2"; shift 2 ;;
    --memory) MEMORY="$2"; shift 2 ;;
    --cpus) CPUS="$2"; shift 2 ;;
    --port-forward) PORT_FORWARDS+=("$2"); shift 2 ;;
    --vfio-device) VFIO_DEVICE="$2"; shift 2 ;;
    --tdx) TDX="true"; shift ;;
    --help|-h) usage ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
done

if [ -z "$IMAGE" ] || [ -z "$VM_NAME" ] || [ -z "$CONFIG_FILE" ]; then
  echo "Error: --image, --name, and --config are required" >&2
  usage
fi

require_cmd virsh
require_cmd qemu-img

[ -f "$IMAGE" ] || { echo "Error: base image not found: $IMAGE" >&2; exit 1; }
[ -f "$CONFIG_FILE" ] || { echo "Error: config file not found: $CONFIG_FILE" >&2; exit 1; }

VM_WORK_DIR="${VM_DIR}/${VM_NAME}"
mkdir -p "$VM_WORK_DIR"

OVERLAY="${VM_WORK_DIR}/${VM_NAME}.qcow2"
if [ ! -f "$OVERLAY" ]; then
  echo "==> Creating overlay image from base"
  qemu-img create -b "$(realpath "$IMAGE")" -F qcow2 -f qcow2 "$OVERLAY"
fi

if [ "$CONFIG_MODE" = "control-plane" ]; then
  CONFIG_DEST="/etc/devopsdefender/control-plane.json"
  SYSTEMD_ENABLE="devopsdefender-control-plane.service"
  SYSTEMD_DISABLE="devopsdefender-agent.service"
else
  CONFIG_DEST="/etc/devopsdefender/agent.json"
  SYSTEMD_ENABLE="devopsdefender-agent.service"
  SYSTEMD_DISABLE="devopsdefender-control-plane.service"
fi

CIDATA_DIR="${VM_WORK_DIR}/cidata"
mkdir -p "$CIDATA_DIR"
CONFIG_CONTENT="$(cat "$CONFIG_FILE")"

cat > "${CIDATA_DIR}/user-data" <<USERDATA
#cloud-config
write_files:
  - path: ${CONFIG_DEST}
    permissions: '0600'
    content: |
$(echo "$CONFIG_CONTENT" | sed 's/^/      /')

runcmd:
  - systemctl daemon-reload
  - systemctl disable --now ${SYSTEMD_DISABLE} || true
  - systemctl enable --now ${SYSTEMD_ENABLE}
USERDATA

cat > "${CIDATA_DIR}/meta-data" <<METADATA
instance-id: ${VM_NAME}
local-hostname: ${VM_NAME}
METADATA

CIDATA_ISO="${VM_WORK_DIR}/cidata.iso"
if command -v cloud-localds >/dev/null 2>&1; then
  cloud-localds "$CIDATA_ISO" "${CIDATA_DIR}/user-data" "${CIDATA_DIR}/meta-data"
elif command -v genisoimage >/dev/null 2>&1; then
  genisoimage -output "$CIDATA_ISO" -volid cidata -joliet -rock \
    "${CIDATA_DIR}/user-data" "${CIDATA_DIR}/meta-data"
else
  echo "Error: need cloud-localds or genisoimage to create cloud-init ISO" >&2
  exit 1
fi

MEMORY_MIB="$(to_mib "$MEMORY")"
DOMAIN_XML="${VM_WORK_DIR}/${VM_NAME}.xml"
SERIAL_LOG="${VM_WORK_DIR}/${VM_NAME}.log"

QEMU_NS=""
LAUNCH_SECURITY=""
QEMU_COMMANDLINE=""
if [ "$TDX" = "true" ]; then
  QEMU_NS=" xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'"
  LAUNCH_SECURITY="  <launchSecurity type='tdx'/>\n"
  QEMU_COMMANDLINE+="  <qemu:commandline>\n"
  QEMU_COMMANDLINE+="    <qemu:arg value='-object'/>\n"
  QEMU_COMMANDLINE+="    <qemu:arg value='memory-backend-ram,id=mem0,size=${MEMORY}'/>\n"
  QEMU_COMMANDLINE+="    <qemu:arg value='-machine'/>\n"
  QEMU_COMMANDLINE+="    <qemu:arg value='q35,kernel_irqchip=split,confidential-guest-support=tdx,memory-backend=mem0,hpet=off'/>\n"
  QEMU_COMMANDLINE+="  </qemu:commandline>\n"
fi

HOSTDEV_XML=""
if [ -n "$VFIO_DEVICE" ]; then
  domain_hex="${VFIO_DEVICE%%:*}"
  remainder="${VFIO_DEVICE#*:}"
  bus_hex="${remainder%%.*}"
  function_hex="${remainder##*.}"
  HOSTDEV_XML+="    <hostdev mode='subsystem' type='pci' managed='yes'>\n"
  HOSTDEV_XML+="      <source>\n"
  HOSTDEV_XML+="        <address domain='0x0000' bus='0x${domain_hex}' slot='0x${bus_hex}' function='0x${function_hex}'/>\n"
  HOSTDEV_XML+="      </source>\n"
  HOSTDEV_XML+="    </hostdev>\n"
fi

cat > "$DOMAIN_XML" <<EOF
<domain type='kvm'${QEMU_NS}>
  <name>${VM_NAME}</name>
  <memory unit='MiB'>${MEMORY_MIB}</memory>
  <currentMemory unit='MiB'>${MEMORY_MIB}</currentMemory>
  <vcpu placement='static'>${CPUS}</vcpu>
  <os firmware='efi'>
    <type arch='x86_64' machine='q35'>hvm</type>
    <boot dev='hd'/>
  </os>
$(printf "%b" "$LAUNCH_SECURITY")  <features>
    <acpi/>
    <apic/>
  </features>
  <cpu mode='host-passthrough' check='none'/>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none'/>
      <source file='$(printf "%s" "$OVERLAY" | escape_xml)'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='$(printf "%s" "$CIDATA_ISO" | escape_xml)'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>
    <interface type='network'>
      <source network='${LIBVIRT_NETWORK}'/>
      <model type='virtio'/>
    </interface>
    <serial type='file'>
      <source path='$(printf "%s" "$SERIAL_LOG" | escape_xml)'/>
      <target type='isa-serial' port='0'/>
    </serial>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <graphics type='none'/>
    <video>
      <model type='none'/>
    </video>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>
$(printf "%b" "$HOSTDEV_XML")  </devices>
$(printf "%b" "$QEMU_COMMANDLINE")</domain>
EOF

if virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
  echo "Error: domain '$VM_NAME' already exists; stop it first" >&2
  exit 1
fi

echo "==> Defining libvirt domain: ${VM_NAME}"
echo "    Memory: ${MEMORY}, CPUs: ${CPUS}"
echo "    Overlay: ${OVERLAY}"
echo "    Config mode: ${CONFIG_MODE}"
echo "    Libvirt network: ${LIBVIRT_NETWORK}"
echo "    TDX: ${TDX}"
if [ -n "$VFIO_DEVICE" ]; then
  echo "    VFIO device: ${VFIO_DEVICE}"
fi
for pf in "${PORT_FORWARDS[@]+"${PORT_FORWARDS[@]}"}"; do
  echo "    Recorded port forward hint: ${pf}"
done

virsh define "$DOMAIN_XML" >/dev/null
virsh start "$VM_NAME" >/dev/null

STATE="$(virsh domstate "$VM_NAME" | tr -d '\r' | xargs)"
echo "==> VM started with libvirt state: ${STATE}"
echo "    Inspect with: virsh list --all"

cat > "${VM_WORK_DIR}/vm-info.json" <<INFO
{
  "name": "${VM_NAME}",
  "overlay": "${OVERLAY}",
  "config_mode": "${CONFIG_MODE}",
  "memory": "${MEMORY}",
  "cpus": "${CPUS}",
  "libvirt_network": "${LIBVIRT_NETWORK}",
  "port_forwards": "$(IFS=,; echo "${PORT_FORWARDS[*]+"${PORT_FORWARDS[*]}"}")",
  "vfio_device": "${VFIO_DEVICE}",
  "tdx": ${TDX},
  "xml_path": "${DOMAIN_XML}",
  "started_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
INFO
