variable "signing_key" {
  description = "HMAC-SHA256 secret shared by the dev boxes and this broker. Treat as a secret; pass via TF_VAR_signing_key or a tfvars file, not in source."
  type        = string
  sensitive   = true
}

variable "function_name" {
  description = "Name of the Lambda function (and prefix for its IAM role)."
  type        = string
  default     = "oauth-redirect-relay-broker"
}

variable "allow_loopback" {
  description = "Allow http://localhost and http://127.0.0.1 targets on any port (mode A). Set false to lock down to allowed_origins only (mode B)."
  type        = bool
  default     = true
}

variable "allowed_origins" {
  description = "Extra exact origins permitted as redirect targets, e.g. [\"https://alice.dev.example.com\"]."
  type        = list(string)
  default     = []
}

variable "ttl_seconds" {
  description = "Signed lifetime of a state token, in seconds."
  type        = number
  default     = 600
}

variable "log_retention_days" {
  description = "CloudWatch log retention for the function."
  type        = number
  default     = 14
}

variable "tags" {
  description = "Tags applied to all created resources."
  type        = map(string)
  default     = {}
}
