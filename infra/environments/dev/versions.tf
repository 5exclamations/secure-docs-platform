terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Remote state with locking is required for anything shared. Create the bucket once, then
  # enable this block (see docs/deployment.md):
  #
  # backend "s3" {
  #   bucket       = "<your-tfstate-bucket>"
  #   key          = "secure-docs/dev.tfstate"
  #   region       = "us-east-1"
  #   encrypt      = true
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project     = "secure-docs"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
