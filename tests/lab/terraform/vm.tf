resource "proxmox_virtual_environment_vm" "lab" {
  for_each = local.nodes

  name        = each.value.name
  description = "Temporary versitygw lifecycle development lab; managed by Terraform."
  node_name   = var.proxmox_node
  vm_id       = each.value.vm_id
  on_boot     = false
  started     = true
  tags        = ["temporary-lab", "terraform", "versitygw"]

  agent {
    enabled = true
  }

  clone {
    datastore_id = var.datastore_id
    full         = true
    node_name    = var.proxmox_node
    vm_id        = var.template_vm_id
  }

  cpu {
    cores = each.value.cpu_cores
    type  = "x86-64-v3"
  }

  memory {
    dedicated = each.value.memory_mib
  }

  disk {
    datastore_id = var.datastore_id
    interface    = "scsi0"
    size         = 30
  }

  dynamic "disk" {
    for_each = each.value.extra_disks

    content {
      datastore_id = var.datastore_id
      interface    = disk.value.interface
      serial       = disk.value.serial
      size         = disk.value.size
    }
  }

  network_device {
    bridge  = var.network_bridge
    vlan_id = var.vlan_id
  }

  initialization {
    datastore_id = var.datastore_id

    ip_config {
      ipv4 {
        address = "${each.value.ip_address}/${var.network_prefix_length}"
        gateway = var.gateway
      }
    }

    user_account {
      keys     = [var.ssh_public_key]
      username = var.ssh_username
    }
  }
}
