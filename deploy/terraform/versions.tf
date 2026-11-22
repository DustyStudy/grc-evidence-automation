terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
  }
}

check "govcloud_region" {
  assert {
    condition     = data.aws_partition.current.partition != "aws-us-gov" || contains(["us-gov-west-1", "us-gov-east-1"], data.aws_region.current.region)
    error_message = "In the aws-us-gov partition this module may only be deployed to us-gov-west-1 or us-gov-east-1; the provider region is ${data.aws_region.current.region}."
  }
}
