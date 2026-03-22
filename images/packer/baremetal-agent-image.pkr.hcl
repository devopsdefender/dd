packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = ">= 1.1.3"
    }
  }
}

variable "base_image_url" {
  type    = string
  default = "https://cloud-images.ubuntu.com/minimal/releases/noble/release/ubuntu-24.04-minimal-cloudimg-amd64.img"
}

variable "base_image_checksum" {
  type    = string
  default = "none"
}

variable "output_directory" {
  type    = string
  default = "output-baremetal"
}

variable "vm_name" {
  type    = string
  default = "dd-baremetal-agent"
}

variable "accelerator" {
  type    = string
  default = "kvm"
}

variable "disk_size" {
  type    = string
  default = "8G"
}

variable "cpus" {
  type    = number
  default = 2
}

variable "memory_mb" {
  type    = number
  default = 2048
}

variable "ssh_username" {
  type    = string
  default = "packer"
}

variable "ssh_private_key_file" {
  type = string
}

variable "cloud_init_user_data_path" {
  type = string
}

variable "cloud_init_meta_data_path" {
  type = string
}

variable "agent_binary_path" {
  type        = string
  description = "Path to the compiled dd-agent binary"
}

variable "cp_binary_path" {
  type        = string
  default     = ""
  description = "Path to the compiled dd-cp binary (optional, for CP bootstrap mode)"
}

variable "ssh_timeout" {
  type    = string
  default = "20m"
}

source "qemu" "baremetal" {
  accelerator          = var.accelerator
  headless             = true
  output_directory     = var.output_directory
  vm_name              = var.vm_name
  format               = "qcow2"
  disk_size            = var.disk_size
  disk_image           = true
  iso_url              = var.base_image_url
  iso_checksum         = var.base_image_checksum
  disk_interface       = "virtio"
  net_device           = "virtio-net"
  cpus                 = var.cpus
  memory               = var.memory_mb
  boot_wait            = "5s"
  ssh_username         = var.ssh_username
  ssh_private_key_file = var.ssh_private_key_file
  ssh_timeout          = var.ssh_timeout
  shutdown_command     = "sudo shutdown -P now"
  cd_files             = [var.cloud_init_user_data_path, var.cloud_init_meta_data_path]
  cd_label             = "cidata"
}

build {
  name    = "dd-baremetal-agent"
  sources = ["source.qemu.baremetal"]

  provisioner "file" {
    source      = var.agent_binary_path
    destination = "/tmp/dd-agent"
  }

  provisioner "file" {
    source      = var.cp_binary_path
    destination = "/tmp/dd-cp"
    only        = [for s in ["source.qemu.baremetal"] : s if var.cp_binary_path != ""]
  }

  provisioner "shell" {
    script          = "${path.root}/provision-baremetal-image.sh"
    execute_command = "chmod +x {{ .Path }}; {{ .Vars }} sudo -E bash -euxo pipefail {{ .Path }}"
  }
}
