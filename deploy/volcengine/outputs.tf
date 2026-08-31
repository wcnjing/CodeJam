output "instance_id" {
  description = "ECS instance ID."
  value       = volcenginecc_ecs_instance.sentinel.id
}

output "public_ip" {
  description = "ECS public IP."
  value       = volcenginecc_ecs_instance.sentinel.eip_address.ip_address
}

output "app_url" {
  description = "Agent sentinel URL. Wait for cloud-init to finish before opening it."
  value       = "http://${volcenginecc_ecs_instance.sentinel.eip_address.ip_address}"
}
