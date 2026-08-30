variable "region" {
  description = "Volcengine region, for example cn-beijing."
  type        = string
}

variable "zone_id" {
  description = "Availability zone that has inventory for the chosen instance type."
  type        = string
}

variable "image_id" {
  description = "A public Ubuntu 22.04/24.04 image ID in the selected region."
  type        = string
}

variable "instance_type" {
  description = "ECS instance type. 2 vCPU / 4 GiB or larger is recommended."
  type        = string
  default     = "ecs.g4i.large"
}

variable "key_pair_name" {
  description = "Existing ECS SSH key-pair name."
  type        = string
}

variable "project_name" {
  description = "Volcengine project."
  type        = string
  default     = "default"
}

variable "allowed_web_cidr" {
  description = "CIDR allowed to access the web UI. This must be an explicit, restricted network."
  type        = string
  validation {
    condition     = var.allowed_web_cidr != "0.0.0.0/0"
    error_message = "allowed_web_cidr must not expose this code-execution POC to the entire Internet."
  }
}

variable "allowed_ssh_cidr" {
  description = "CIDR allowed to SSH to the ECS."
  type        = string
}

variable "repository_url" {
  description = "Public Git URL of this Starter Kit repository."
  type        = string
  validation {
    condition     = startswith(var.repository_url, "https://")
    error_message = "repository_url must be an HTTPS URL."
  }
}

variable "repository_ref" {
  description = "Git branch or tag deployed by cloud-init."
  type        = string
  default     = "main"
}

variable "ark_api_key" {
  description = "Volcengine Ark API key. Supplied through TF_VAR_ark_api_key."
  type        = string
  sensitive   = true
}

variable "app_principals" {
  description = "Comma-separated id:token approver credentials. Supplied through TF_VAR_app_principals."
  type        = string
  sensitive   = true
  # Deliberately weaker than the server: this checks shape and the 24-character
  # remote-production token floor only. Duplicate ids and a token reused across
  # ids pass here and are rejected by PrincipalRegistry at startup, so such a
  # tfvars applies cleanly and then fails at cloud-init. The server is the
  # authority on principal validity; keeping the regex readable is worth the gap.
  validation {
    condition     = can(regex("^[A-Za-z0-9._@-]{1,64}:[A-Za-z0-9._~-]{24,128}(,[A-Za-z0-9._@-]{1,64}:[A-Za-z0-9._~-]{24,128})*$", var.app_principals)) && !strcontains(var.app_principals, ":replace-")
    error_message = "app_principals must be one or more id:token pairs with 24-128 URL-safe, non-placeholder token characters."
  }
}

variable "ark_model" {
  description = "Ark endpoint/model ID supporting the Responses API."
  type        = string
}

variable "ark_base_url" {
  description = "Ark OpenAI-compatible API base URL."
  type        = string
  default     = "https://ark.cn-beijing.volces.com/api/v3"
}
