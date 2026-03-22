packer {
  required_plugins {
    googlecompute = {
      source  = "github.com/hashicorp/googlecompute"
      version = ">= 1.1.0"
    }
  }
}

variable "project_id" {
  type = string
}

variable "build_zone" {
  type = string
}

variable "build_machine_type" {
  type = string
}

variable "build_boot_disk_gb" {
  type = number
}

variable "target_image_name" {
  type = string
}

variable "target_image_family" {
  type    = string
  default = ""
}

variable "target_image_description" {
  type = string
}

variable "source_image_project" {
  type = string
}

variable "source_image_name" {
  type    = string
  default = ""
}

variable "source_image_family" {
  type    = string
  default = ""
}

variable "image_labels_json" {
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

locals {
  image_labels = jsondecode(var.image_labels_json)
}

source "googlecompute" "agent" {
  project_id              = var.project_id
  zone                    = var.build_zone
  machine_type            = var.build_machine_type
  disk_size               = var.build_boot_disk_gb
  source_image_project_id = [var.source_image_project]
  source_image            = var.source_image_name
  source_image_family     = var.source_image_family
  image_name              = var.target_image_name
  image_family            = var.target_image_family
  image_description       = var.target_image_description
  image_labels            = local.image_labels
  labels = {
    devopsdefender = "managed"
    dd_role        = "image-bake"
  }
  ssh_username = "ubuntu"
}

build {
  name    = "dd-gcp-agent"
  sources = ["source.googlecompute.agent"]

  provisioner "file" {
    source      = var.agent_binary_path
    destination = "/tmp/dd-agent"
  }

  provisioner "file" {
    source      = var.cp_binary_path != "" ? var.cp_binary_path : "/dev/null"
    destination = "/tmp/dd-cp"
  }

  provisioner "shell" {
    script          = "${path.root}/provision-agent-image.sh"
    execute_command = "chmod +x {{ .Path }}; {{ .Vars }} sudo -E bash -euxo pipefail {{ .Path }}"
  }
}
