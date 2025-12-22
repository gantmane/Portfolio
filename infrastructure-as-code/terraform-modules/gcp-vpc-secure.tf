# GCP Secure VPC Module
# Compliance: PCI DSS 1.3, CIS GCP 3.1

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "vpc_name" {
  description = "VPC name"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "subnets" {
  description = "List of subnets"
  type = list(object({
    subnet_name   = string
    subnet_ip     = string
    subnet_region = string
  }))
}

variable "enable_flow_logs" {
  description = "Enable VPC flow logs"
  type        = bool
  default     = true
}

resource "google_compute_network" "main" {
  project                 = var.project_id
  name                    = var.vpc_name
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "main" {
  for_each = { for subnet in var.subnets : subnet.subnet_name => subnet }

  project                  = var.project_id
  name                     = each.value.subnet_name
  ip_cidr_range            = each.value.subnet_ip
  region                   = each.value.subnet_region
  network                  = google_compute_network.main.id
  private_ip_google_access = true

  log_config {
    aggregation_interval = var.enable_flow_logs ? "INTERVAL_5_SEC" : null
    flow_sampling        = var.enable_flow_logs ? 0.5 : null
    metadata             = var.enable_flow_logs ? "INCLUDE_ALL_METADATA" : null
  }
}

resource "google_compute_router" "main" {
  project = var.project_id
  name    = "${var.vpc_name}-router"
  region  = var.region
  network = google_compute_network.main.id

  bgp {
    asn = 64514
  }
}

resource "google_compute_router_nat" "main" {
  project                            = var.project_id
  name                               = "${var.vpc_name}-nat"
  router                             = google_compute_router.main.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

output "network_name" {
  description = "VPC network name"
  value       = google_compute_network.main.name
}

output "network_self_link" {
  description = "VPC network self link"
  value       = google_compute_network.main.self_link
}

output "subnet_names" {
  description = "List of subnet names"
  value       = [for subnet in google_compute_subnetwork.main : subnet.name]
}
