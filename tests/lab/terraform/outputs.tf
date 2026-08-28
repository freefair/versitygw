output "hosts" {
  description = "Lab host connection data used to generate the local Ansible inventory."
  value = {
    for role, vm in proxmox_virtual_environment_vm.lab : role => {
      ip_address = local.nodes[role].ip_address
      name       = vm.name
      vm_id      = vm.vm_id
    }
  }
}
