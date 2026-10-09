locals {
  name = "secure-docs-${var.environment}"
}

module "storage" {
  source        = "../../modules/storage"
  name          = local.name
  region        = var.region
  force_destroy = !var.protect_from_deletion
}

module "network" {
  source      = "../../modules/network"
  name        = local.name
  region      = var.region
  kms_key_arn = module.storage.kms_key_arn
}

module "database" {
  source                = "../../modules/database"
  name                  = local.name
  vpc_id                = module.network.vpc_id
  subnet_ids            = module.network.data_subnet_ids
  app_security_group_id = module.compute.app_security_group_id
  kms_key_arn           = module.storage.kms_key_arn
  multi_az              = var.multi_az_database
  deletion_protection   = var.protect_from_deletion
}

module "cache" {
  count                 = var.enable_elasticache ? 1 : 0
  source                = "../../modules/cache"
  name                  = local.name
  vpc_id                = module.network.vpc_id
  subnet_ids            = module.network.data_subnet_ids
  app_security_group_id = module.compute.app_security_group_id
  kms_key_arn           = module.storage.kms_key_arn
}

module "compute" {
  source                = "../../modules/compute"
  name                  = local.name
  region                = var.region
  vpc_id                = module.network.vpc_id
  vpc_cidr              = "10.20.0.0/16"
  public_subnet_ids     = module.network.public_subnet_ids
  app_subnet_ids        = module.network.app_subnet_ids
  kms_key_arn           = module.storage.kms_key_arn
  bucket_name           = module.storage.bucket_name
  bucket_arn            = module.storage.bucket_arn
  db_host               = module.database.address
  db_master_secret_arn  = module.database.master_secret_arn
  redis_endpoint        = var.enable_elasticache ? module.cache[0].endpoint : ""
  redis_auth_secret_arn = var.enable_elasticache ? module.cache[0].auth_secret_arn : ""
  certificate_arn       = var.certificate_arn
  image_tag             = var.image_tag
  allowed_ingress_cidr  = var.allowed_ingress_cidr
  allowed_hosts         = var.public_hostname
  cors_origins          = var.cors_origins
  deletion_protection   = var.protect_from_deletion
}

module "waf" {
  count   = var.enable_waf ? 1 : 0
  source  = "../../modules/waf"
  name    = local.name
  alb_arn = module.compute.alb_arn
}

module "observability" {
  source                  = "../../modules/observability"
  name                    = local.name
  kms_key_arn             = module.storage.kms_key_arn
  alb_arn_suffix          = module.compute.alb_arn_suffix
  target_group_arn_suffix = module.compute.target_group_arn_suffix
  instance_id             = module.compute.instance_id
  db_identifier           = "${local.name}-pg"
  alert_email             = var.alert_email
}
