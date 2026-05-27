terraform {
  required_version = ">= 1.6.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.33"
    }
  }
}

variable "environment" {
  type    = string
  default = "base-sepolia"
}

variable "namespace" {
  type    = string
  default = "tsl"
}

variable "image" {
  type        = string
  description = "Production runtime image without Hardhat/Circom setup tooling."
}

variable "database_url" {
  type      = string
  sensitive = true
}

variable "queue_url" {
  type      = string
  sensitive = true
}

variable "settlement_rpc_url" {
  type      = string
  sensitive = true
}

variable "checkpoint_registry_address" {
  type = string
}

locals {
  common_env = {
    TSL_NETWORK                     = var.environment
    TSL_EPOCH_MS                    = "300000"
    TSL_SHARD_PREFIX_BITS           = "16"
    TSL_SETTLEMENT_BACKEND          = "eip155:84532"
    TSL_RELAY_ID                    = "did:tsl:relay:base-sepolia"
    TSL_CHECKPOINT_REGISTRY_ADDRESS = var.checkpoint_registry_address
  }
}

resource "kubernetes_namespace" "tsl" {
  metadata { name = var.namespace }
}

resource "kubernetes_secret" "runtime" {
  metadata {
    name      = "tsl-runtime"
    namespace = kubernetes_namespace.tsl.metadata[0].name
  }
  data = {
    TSL_DATABASE_URL                 = var.database_url
    TSL_QUEUE_URL                    = var.queue_url
    TSL_SETTLEMENT_RPC_URL           = var.settlement_rpc_url
    TSL_RELAY_PRIVATE_KEY_URI        = "kms:aws-kms:REPLACE"
    TSL_AUDITOR_PRIVATE_KEY_URI      = "kms:aws-kms:REPLACE"
    TSL_PROVIDER_PRIVATE_KEY_URI     = "kms:aws-kms:REPLACE"
  }
}

output "tsl_environment" {
  value = var.environment
}

output "deployment_notes" {
  value = "Apply infra/k8s/tsl-production-reference.yaml after replacing image and secret values, or translate the same service set into Terraform modules."
}
