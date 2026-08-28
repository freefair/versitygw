variable "proxmox_endpoint" {
  description = "Proxmox VE API endpoint, including the /api2/json path if required by the provider."
  type        = string
}

variable "proxmox_insecure" {
  description = "Allow an untrusted Proxmox TLS certificate. Keep false outside isolated development labs."
  type        = bool
  default     = false
}

variable "proxmox_node" {
  description = "Proxmox node on which the temporary test VMs are created."
  type        = string
}

variable "template_vm_id" {
  description = "Rocky Linux 9 cloud-init template VM ID."
  type        = number
}

variable "datastore_id" {
  description = "Proxmox datastore for cloned and additional VM disks."
  type        = string
}

variable "network_bridge" {
  description = "Proxmox bridge used by the lab VMs."
  type        = string
}

variable "vlan_id" {
  description = "VLAN tag used by the lab VMs."
  type        = number

  validation {
    condition     = var.vlan_id >= 1 && var.vlan_id <= 4094
    error_message = "vlan_id must be between 1 and 4094."
  }
}

variable "network_prefix_length" {
  description = "IPv4 prefix length shared by all lab VMs."
  type        = number

  validation {
    condition     = var.network_prefix_length >= 1 && var.network_prefix_length <= 32
    error_message = "network_prefix_length must be between 1 and 32."
  }
}

variable "gateway" {
  description = "IPv4 default gateway for the lab VMs."
  type        = string
}

variable "storage_ip" {
  description = "IPv4 address of the NFS and iSCSI storage VM."
  type        = string
}

variable "node_ips" {
  description = "IPv4 addresses of the three ScoutFS and gateway nodes."
  type        = list(string)

  validation {
    condition     = length(var.node_ips) == 3 && length(distinct(var.node_ips)) == 3
    error_message = "node_ips must contain exactly three distinct addresses."
  }
}

variable "storage_vm_id" {
  description = "VM ID of the storage VM."
  type        = number
}

variable "node_vm_ids" {
  description = "VM IDs of the three ScoutFS and gateway nodes."
  type        = list(number)

  validation {
    condition     = length(var.node_vm_ids) == 3 && length(distinct(var.node_vm_ids)) == 3
    error_message = "node_vm_ids must contain exactly three distinct IDs."
  }
}

variable "ssh_username" {
  description = "Cloud-init and Ansible login account."
  type        = string
  default     = "rocky"
}

variable "ssh_public_key" {
  description = "OpenSSH public key installed by cloud-init."
  type        = string
}
