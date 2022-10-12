terraform {
  required_version = "~> 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.4"
    }
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = "~> 1.14"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

locals {
  cluster_name = "karpenter-demo"

  # Used to determine correct partition (i.e. - `aws`, `aws-gov`, `aws-cn`, etc.)
  partition = data.aws_partition.current.partition
}

data "aws_partition" "current" {}


module "vpc" {
  # https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/latest
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.12.0"

  name = local.cluster_name
  cidr = "10.0.0.0/16"

  azs             = ["us-west-2a", "us-west-2b", "us-west-2c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway     = true
  single_nat_gateway     = true
  one_nat_gateway_per_az = false
#The key part of this is that we need to tag the VPC subnets 
#that we want to use for the worker nodes.
  private_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "owned"
    # Tags subnets for Karpenter auto-discovery
    "karpenter.sh/discovery" = local.cluster_name
  }
}

module "eks" {
  # https://registry.terraform.io/modules/terraform-aws-modules/eks/aws/latest
  source  = "terraform-aws-modules/eks/aws"
  version = "18.17.0"

  cluster_name    = local.cluster_name
  cluster_version = "1.21"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Required for Karpenter role below
  enable_irsa = true

  # We will rely only on the cluster security group created by the EKS service
  # See note below for `tags`
  create_cluster_security_group = false
  create_node_security_group    = false

  # Only need one node to get Karpenter up and running.
  # This ensures core services such as VPC CNI, CoreDNS, etc. are up and running
  # so that Karpenter can be deployed and start managing compute capacity as required
  eks_managed_node_groups = {
    initial = {
      instance_types = ["t3.medium"]
      # We don't need the node security group since we are using the
      # cluster-created security group, which Karpenter will also use
      create_security_group                 = false
      attach_cluster_primary_security_group = true

      min_size     = 1
      max_size     = 1
      desired_size = 1

      iam_role_additional_policies = [
        # Required by Karpenter
        "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
      ]
    }
  }

  tags = {
    # Tag node group resources for Karpenter auto-discovery
    # NOTE - if creating multiple security groups with this module, only tag the
    # security group that Karpenter should utilize with the following tag
    "karpenter.sh/discovery" = local.cluster_name
  }
}
resource "aws_iam_instance_profile" "karpenter" {
  name = "KarpenterNodeInstanceProfile-${local.cluster_name}"
  role = module.eks.eks_managed_node_groups["initial"].iam_role_name
}
module "karpenter_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "4.17.1"

  role_name                          = "karpenter-controller-${local.cluster_name}"
  attach_karpenter_controller_policy = true

  karpenter_controller_cluster_id = module.eks.cluster_id
  karpenter_controller_node_iam_role_arns = [
    module.eks.eks_managed_node_groups["initial"].iam_role_arn
  ]
#IAM OIDC identity providers are entities in IAM that 
#describe an external identity provider (IdP) service that supports t
#he OpenID Connect (OIDC) standard, such as Google or Salesforce. 
#You use an IAM OIDC identity provider when you want to establish trust 
#between an OIDC-compatible IdP and your AWS account.  
  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["karpenter:karpenter"]
    }
  }
}
provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", local.cluster_name]
    }
  }
}

resource "helm_release" "karpenter" {
  namespace        = "karpenter"
  create_namespace = true

  name       = "karpenter"
  repository = "https://charts.karpenter.sh"
  chart      = "karpenter"
  version    = "v0.10.0"

  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.karpenter_irsa.iam_role_arn
  }

  set {
    name  = "clusterName"
    value = module.eks.cluster_id
  }

  set {
    name  = "clusterEndpoint"
    value = module.eks.cluster_endpoint
  }

  set {
    name  = "aws.defaultInstanceProfile"
    value = aws_iam_instance_profile.karpenter.name
  }
}
provider "kubectl" {
  apply_retry_count      = 5
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1alpha1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_id]
  }
}

resource "kubectl_manifest" "karpenter_provisioner" {
  yaml_body = <<-YAML
  apiVersion: karpenter.sh/v1alpha5
  kind: Provisioner
  metadata:
    name: default
  spec:
    requirements:
      - key: karpenter.sh/capacity-type
        operator: In
        values: ["spot"]
    limits:
      resources:
        cpu: 1000
    provider:
      subnetSelector:
        karpenter.sh/discovery: ${local.cluster_name}
      securityGroupSelector:
        karpenter.sh/discovery: ${local.cluster_name}
      tags:
        karpenter.sh/discovery: ${local.cluster_name}
    ttlSecondsAfterEmpty: 30
  YAML

  depends_on = [
    helm_release.karpenter
  ]
}
s
