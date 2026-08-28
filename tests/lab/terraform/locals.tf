locals {
  node_names = ["node-a", "node-b", "node-c"]

  nodes = merge(
    {
      storage = {
        name       = "versitygw-dev-storage"
        vm_id      = var.storage_vm_id
        ip_address = var.storage_ip
        cpu_cores  = 2
        memory_mib = 4096
        extra_disks = [
          { interface = "scsi1", size = 80, serial = "SCOUTFSMETA" },
          { interface = "scsi2", size = 100, serial = "SCOUTFSDATA" },
          { interface = "scsi3", size = 80, serial = "NFSDATA" },
        ]
      }
    },
    {
      for index, node_name in local.node_names : node_name => {
        name        = "versitygw-dev-${node_name}"
        vm_id       = var.node_vm_ids[index]
        ip_address  = var.node_ips[index]
        cpu_cores   = 4
        memory_mib  = 6144
        extra_disks = []
      }
    }
  )
}
