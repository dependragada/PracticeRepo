terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }
  required_version = ">= 1.2.0"
}

provider "aws" {
  region = var.aws_region
}

##################################  VPC-Resources  ##################################
# Fetch the default VPC
data "aws_vpc" "default_vpc" {
  default = true
}

# Create default subnet 1 (without cidr_block and vpc_id)
resource "aws_default_subnet" "default_subnet_1" {
  availability_zone = local.availability_zone_subnet_1

  tags = {
    Name = "${var.organization}-${var.region}-default-subnet-1"
  }
}

# Create default subnet 2 (without cidr_block and vpc_id)
resource "aws_default_subnet" "default_subnet_2" {
  availability_zone = local.availability_zone_subnet_2

  tags = {
    Name = "${var.organization}-${var.region}-default-subnet-2"
  }
}

# Create the first private subnet
resource "aws_subnet" "private_subnet_1" {
  vpc_id                  = data.aws_vpc.default_vpc.id
  cidr_block              = var.subnet_1
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = false
  tags = {
    Name = "${var.organization}-${var.environment}-private-subnet-1"
  }
}

# Create the second private subnet
resource "aws_subnet" "private_subnet_2" {
  vpc_id                  = data.aws_vpc.default_vpc.id
  cidr_block              = var.subnet_2 # Adjust CIDR to avoid overlap with the first subnet
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false
  tags = {
    Name = "${var.organization}-${var.environment}-private-subnet-2"
  }
}

# Create the route table for the private subnet
resource "aws_route_table" "private_route_table" {
  vpc_id = data.aws_vpc.default_vpc.id
  tags = {
    Name = "${var.organization}-${var.environment}-${var.region}-private-route-table"
    tag  = local.env_tag
  }
}

# Create an Elastic IP (EIP) for the NAT Gateway
resource "aws_eip" "eip_nat_gateway" {
  count = var.existing_nat_gateway ? 0 : 1
}

# Create a NAT Gateway
resource "aws_nat_gateway" "nat_gateway" {
  count         = var.existing_nat_gateway ? 0 : 1
  allocation_id = var.existing_nat_gateway_allocation_id ? var.nat_gateway_allocation_id : aws_eip.eip_nat_gateway[0].id
  subnet_id     = aws_default_subnet.default_subnet_1.id
  tags = {
    Name = "${var.organization}-${var.environment}-nat-gateway"
  }
}

resource "aws_route" "private_nat_gateway_route" {
  route_table_id         = aws_route_table.private_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = var.existing_nat_gateway ? var.nat_gateway_id : aws_nat_gateway.nat_gateway[0].id
}

resource "aws_route_table_association" "private_subnet_1_route_table_association" {
  subnet_id      = aws_subnet.private_subnet_1.id
  route_table_id = aws_route_table.private_route_table.id
}
resource "aws_route_table_association" "private_subnet_2_route_table_association" {
  subnet_id      = aws_subnet.private_subnet_2.id
  route_table_id = aws_route_table.private_route_table.id
}

###################################### S3-Resources ##################################################################
# Create IAM Role for s3
resource "aws_iam_role" "s3_access_role" {
  name               = "${var.organization}-${var.environment}-s3-access-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

# Create IAM Policy
resource "aws_iam_policy" "s3_access_policy" {
  name        = "${var.organization}-${var.environment}-s3-access-policy"
  description = "Allows access to S3 bucket with secure transport"
  policy      = <<EOT
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket",
        "s3:*"
      ],
      "Resource": [
        "${aws_s3_bucket.s3-bucket.arn}",
        "${aws_s3_bucket.s3-bucket.arn}/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "true"
        }
      }
    }
  ]
}
EOT
}
# Attach IAM Policy to the Role
resource "aws_iam_role_policy_attachment" "s3_access_policy_attachment" {
  policy_arn = aws_iam_policy.s3_access_policy.arn
  role       = aws_iam_role.s3_access_role.name
}

# created s3 bucket
resource "aws_s3_bucket" "s3-bucket" {
  bucket        = "${var.organization}-${var.environment}-${var.region}-s3-bucket"
  force_destroy = true
  tags = {
    name        = "${var.organization}-${var.environment}-${var.region}-s3-bucket"
    environment = "${var.environment}"
    component   = "s3"
    team        = "${var.organization}"
    state       = "active"
    tag         = local.env_tag
  }
}

# Upload combined_templates_minimal.json
resource "aws_s3_object" "combined_templates_minimal_json_file" {
  depends_on = [aws_s3_bucket.s3-bucket]
  bucket     = aws_s3_bucket.s3-bucket.id
  key        = "combined_templates_minimal.json"
  source     = "${path.module}/configuration/combined_templates_minimal.json"

  tags = {
    tag = local.env_tag
  }
}

# Upload form_indentifier_label_mapping.json
resource "aws_s3_object" "form_identifier_label_mapping_json_file" {
  depends_on = [aws_s3_bucket.s3-bucket]
  bucket     = aws_s3_bucket.s3-bucket.id
  key        = "form_identifier_label_mapping.json"
  source     = "${path.module}/configuration/form_identifier_label_mapping.json"

  tags = {
    tag = local.env_tag
  }
}

# Upload preprocessing.json
resource "aws_s3_object" "preprocessing_json_file" {
  depends_on = [aws_s3_bucket.s3-bucket]
  bucket     = aws_s3_bucket.s3-bucket.id
  key        = "preprocessing.json"
  source     = "${path.module}/configuration/preprocessing.json"

  tags = {
    tag = local.env_tag
  }
}


# Created S3 bucket for transfer stage
resource "aws_s3_bucket" "s3_transfer_stage_bucket" {
  bucket        = "${var.organization}-${var.environment}-${var.region}-s3-transfer-stage-bucket"
  force_destroy = true

  tags = {
    name        = "${var.organization}-${var.environment}-${var.region}-s3-transfer-stage-bucket"
    environment = "${var.environment}"
    component   = "s3"
    team        = "${var.organization}"
    state       = "active"
    tag         = local.env_tag
  }
}

# Created S3 bucket for tranfer api
resource "aws_s3_bucket" "s3_transfer_api_bucket" {
  bucket        = "${var.organization}-${var.environment}-${var.region}-s3-transfer-api-bucket"
  force_destroy = true

  tags = {
    name        = "${var.organization}-${var.environment}-${var.region}-s3-transfer-api-bucket"
    environment = "${var.environment}"
    component   = "s3"
    team        = "${var.organization}"
    state       = "active"
    tag         = local.env_tag
  }
}

# S3 bucket for General Purpose
resource "aws_s3_bucket" "s3_general_purpose_bucket" {
  bucket        = "${var.organization}-${var.environment}-${var.region}-s3-general-bucket"
  force_destroy = true

  tags = {
    name        = "${var.organization}-${var.environment}-${var.region}-s3-general-bucket"
    environment = "${var.environment}"
    component   = "s3"
    team        = "${var.organization}"
    state       = "active"
    tag         = local.env_tag
  }
}

# Created S3 bucket for the tege historial files
resource "aws_s3_bucket" "s3_tege_historical_files_bucket" {
  bucket        = "${var.organization}-${var.environment}-${var.region}-s3-tege-historical-files-bucket"
  force_destroy = true

  tags = {
    name        = "${var.organization}-${var.environment}-${var.region}-s3-tege-historical-files-bucket"
    environment = "${var.environment}"
    component   = "s3"
    team        = "${var.organization}"
    state       = "active"
    tag         = local.env_tag
  }
}

# Created S3 bucket for the tege files
resource "aws_s3_bucket" "s3_tege_files_bucket" {
  bucket        = "${var.organization}-${var.environment}-${var.region}-s3-tege-files-bucket"
  force_destroy = true
  tags = {
    name        = "${var.organization}-${var.environment}-${var.region}-s3-tege-files-bucket"
    environment = "${var.environment}"
    component   = "s3"
    team        = "${var.organization}"
    state       = "active"
    tag         = local.env_tag
  }
}

# Created S3 bucket for the redacted files files
resource "aws_s3_bucket" "s3_redacted_files_bucket" {
  bucket        = "${var.organization}-${var.environment}-${var.region}-s3-redacted-files-bucket"
  force_destroy = true

  tags = {
    name        = "${var.organization}-${var.environment}-${var.region}-s3-redacted-files-bucket"
    environment = "${var.environment}"
    component   = "s3"
    team        = "${var.organization}"
    state       = "active"
    tag         = local.env_tag
  }
}

###################################### Security-group ##################################################################

# create security group for bastion instance
resource "aws_security_group" "ec2-bastion-sg" {
  name_prefix = "${var.organization}-${var.environment}-ec2-bastion-sg"
  description = "default VPC security group for bastion"
  vpc_id      = data.aws_vpc.default_vpc.id

  tags = {
    Name = "SG-${var.organization}-${var.environment}-ec2-bastion-host"
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# create security group for redis cluster
resource "aws_security_group" "elastic-cache-redis" {
  name_prefix = "${var.organization}-${var.environment}-elastic-cache-redis-sg"
  description = "default VPC security group for elastic cache redis cluster"
  vpc_id      = data.aws_vpc.default_vpc.id

  tags = {
    Name = "SG-${var.organization}-${var.environment}-elastic-cache-redis-cluster"
  }

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "TCP"
    security_groups = [aws_security_group.ec2-bastion-sg.id]
  }

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "TCP"
    security_groups = [aws_security_group.ecs-sg.id]
  }

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "TCP"
    security_groups = [aws_security_group.os-opensearch-sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# create security group for opensearch
resource "aws_security_group" "os-opensearch-sg" {
  name_prefix = "${var.organization}-${var.environment}-os-opensearch-sg"
  description = "default VPC security group for opensearch"
  vpc_id      = data.aws_vpc.default_vpc.id

  tags = {
    Name = "SG-${var.organization}-${var.environment}-opensearch"
  }

  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.ec2-bastion-sg.id]
  }

  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.ecs-sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#create security group for the aws aurora database
resource "aws_security_group" "rds-db-sg" {
  name_prefix = "${var.organization}-${var.environment}-rds-db-sg"
  description = "default VPC security group for database cluster"
  vpc_id      = data.aws_vpc.default_vpc.id

  tags = {
    Name = "SG-${var.organization}-${var.environment}-rds-db-sg"
  }

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "TCP"
    security_groups = [aws_security_group.ec2-bastion-sg.id]
  }

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "TCP"
    security_groups = [aws_security_group.ecs-sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Create a security group for the load balancer:
resource "aws_security_group" "lb-sg" {
  name   = "${var.organization}-${var.environment}-lb-sg"
  vpc_id = data.aws_vpc.default_vpc.id

  tags = {
    Name = "SG-${var.organization}-${var.environment}-application-load-balancer"
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allow traffic in from all sources
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allow traffic in from all sources
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# creating security group for ecs
resource "aws_security_group" "ecs-sg" {
  name_prefix = "${var.organization}-${var.environment}-${var.region}-ecs-sg"
  description = "default VPC security group for ecs"
  vpc_id      = data.aws_vpc.default_vpc.id

  tags = {
    Name = "SG-${var.organization}-${var.environment}-ecs-service"
  }
  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = ["${aws_security_group.lb-sg.id}"]
  }

  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
  }

  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = ["${aws_security_group.ec2-bastion-sg.id}"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# create security group for jenkins instance
resource "aws_security_group" "private-jenkins-sg" {
  name_prefix = "${var.organization}-${var.region}-${var.environment}-jenkins-sg"
  description = "default VPC security group for jenkins"
  vpc_id      = data.aws_vpc.default_vpc.id
  tags = {
    Name = "SG-${var.organization}-${var.environment}-private-jenkins-host"
  }
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Security Group for Tesseract Lambda
resource "aws_security_group" "runocr-tesseract-lambda-sg" {
  name        = "${var.organization}-${var.environment}-${var.region}-runocr-tesseract-lambda-sg"
  description = "Security group for runocr-tesseract-lambda"
  vpc_id      = data.aws_vpc.default_vpc.id

  tags = {
    Name = "SG-${var.organization}-${var.environment}-${var.region}-runocr-tesseract-lambda"
    tag  = local.env_tag
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

################################  open-search-config   #######################################
resource "aws_opensearch_domain" "os-opensearch" {
  domain_name    = local.opensearch_domain_name
  engine_version = var.opensearch_engine

  node_to_node_encryption {
    enabled = false
  }

  auto_tune_options {
    desired_state       = "DISABLED"
    rollback_on_disable = "NO_ROLLBACK"
  }

  cluster_config {
    instance_type            = var.opensearch_instance_type
    instance_count           = 1
    dedicated_master_enabled = false
    zone_awareness_enabled   = false
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = 40
    iops        = 3000
    throughput  = 125
  }

  snapshot_options {
    automated_snapshot_start_hour = 0
  }

  vpc_options {
    security_group_ids = [aws_security_group.os-opensearch-sg.id]
    subnet_ids         = [aws_subnet.private_subnet_1.id]
  }

  encrypt_at_rest {
    enabled = true
  }
}

resource "aws_opensearch_domain_policy" "os-opensearch-policy" {
  domain_name = aws_opensearch_domain.os-opensearch.domain_name
  depends_on  = [time_sleep.wait_for_opensearch]

  access_policies = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          AWS = "*"
        },
        Action   = "es:*",
        Resource = "${aws_opensearch_domain.os-opensearch.arn}/*"
      }
    ]
  })
}

resource "time_sleep" "wait_for_opensearch" {
  depends_on      = [aws_opensearch_domain.os-opensearch]
  create_duration = "2m"
}

##############################  ECR-Repository  ##################################
# creating aws ecr repository for Front-End
resource "aws_ecr_repository" "ecr_fe" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-fe-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository for Buow-Api
resource "aws_ecr_repository" "ecr_buow_api_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-buow-api-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository for security api
resource "aws_ecr_repository" "ecr_irs_security_api_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-irs-security-api-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository for records management api
resource "aws_ecr_repository" "ecr_records_management_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-records-management-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository for document-metadata-repository
resource "aws_ecr_repository" "ecr_document_metadata_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-document-metadata-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository for external-service-repository
resource "aws_ecr_repository" "ecr_external_service_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-external-service-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository for document repository
resource "aws_ecr_repository" "ecr_document_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-document-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository for rule repository
resource "aws_ecr_repository" "ecr_rule_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-rule-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository for metadata-schema repository
resource "aws_ecr_repository" "ecr_metadata_schema_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-metadata-schema-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository for metadata-search repository
resource "aws_ecr_repository" "ecr_metadata_search_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-metadata-search-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository for s3-api repository
resource "aws_ecr_repository" "ecr_s3_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-s3-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository for scan-on-demand repository
resource "aws_ecr_repository" "ecr_scan_on_demand_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-scan-on-demand-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository for transform api repository
resource "aws_ecr_repository" "ecr_transform_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-transform-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository for records management transfer repository
resource "aws_ecr_repository" "ecr_records_management_transfer_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-records-management-transfer-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository for records management disposition repository
resource "aws_ecr_repository" "ecr_records_management_disposition_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-records-management-disposition-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////

# creating aws ecr repository for ailet gateway repository
resource "aws_ecr_repository" "ecr_ailet_gateway_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-ailet-gateway-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository for gri-extraction repository
resource "aws_ecr_repository" "ecr_gri_extraction_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-gri-extraction-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository upload daemon repository
resource "aws_ecr_repository" "ecr_upload_daemon_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-upload-daemon-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository submit daemon repository
resource "aws_ecr_repository" "ecr_submit_daemon_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-submit-daemon-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository routing daemon repository
resource "aws_ecr_repository" "ecr_routing_daemon_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-routing-daemon-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository inbasket daemon repository
resource "aws_ecr_repository" "ecr_inbasket_daemon_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-inbasket-daemon-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository sense daemon repository
resource "aws_ecr_repository" "ecr_sense_daemon_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-sense-daemon-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository tege packager repository
resource "aws_ecr_repository" "ecr_tege_packager_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-tege-packager-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository naix object classification repository
resource "aws_ecr_repository" "ecr_naix_object_classification_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-naix-object-classification-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository dashboard daemon repository
resource "aws_ecr_repository" "ecr_dashboard_daemon_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-dashboard-daemon-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository batch driver repository
resource "aws_ecr_repository" "ecr_batch_driver_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-batch-driver-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository object driver repository
resource "aws_ecr_repository" "ecr_object_driver_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-object-driver-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository output driver repository
resource "aws_ecr_repository" "ecr_output_driver_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-output-driver-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository runocr repository
resource "aws_ecr_repository" "ecr_runocr_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-runocr-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository xml service repository
resource "aws_ecr_repository" "ecr_xml_service_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-xml-service-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating aws ecr repository runocr tesseract lambda repository
resource "aws_ecr_repository" "ecr_runocr_tesseract_lambda_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-runocr-tesseract-lambda-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    tag = local.env_tag
  }
}

# creating the ecr repository for batch-inferred-mode-daemon
resource "aws_ecr_repository" "ecr_batch_inferred_mode_daemon_repository" {
  name                 = "${var.organization}-${var.environment}-${var.region}-ecr-batch-inferred-mode-daemon-repository"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
  tags = {
    tag = local.env_tag
  }
}

############################   CloudMap-Service   ################################

resource "aws_service_discovery_private_dns_namespace" "private_dns_namespace" {
  name        = var.private_dns_namespace
  description = "${var.organization}-${var.environment}-${var.private_dns_namespace}"
  vpc         = data.aws_vpc.default_vpc.id
}

########################## Service-Discovery  #####################################

# Creating service discovery instance for search 
resource "aws_service_discovery_instance" "opensearch_service_discovery_instance" {
  instance_id = "${var.environment}-${var.opensearch_service_discovery_instance_id}"
  service_id  = aws_service_discovery_service.sd_opensearch_api.id

  attributes = {
    AWS_INSTANCE_CNAME = aws_opensearch_domain.os-opensearch.endpoint
    custom_attribute   = "custom"
  }
}

# Creating service discovery for search api
resource "aws_service_discovery_service" "sd_opensearch_api" {
  name = "${var.organization}-${var.environment}-${var.region}-opensearch"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "CNAME"
    }

    routing_policy = "WEIGHTED"
  }
}

# Creating service discovery for front-end api
resource "aws_service_discovery_service" "sd_management_console" {
  name = "${var.environment}-management-console"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for buow api
resource "aws_service_discovery_service" "sd_buow_api" {
  name = "${var.environment}-buow-api"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"

    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for scan on demand api
resource "aws_service_discovery_service" "sd_scan_on_demand_api" {
  name = "${var.environment}-scan-on-demand-api"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for Metadata schema api
resource "aws_service_discovery_service" "sd_metadata_schema_api" {
  name = "${var.environment}-metadata-schema-api"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for Document Metadata Submission api
resource "aws_service_discovery_service" "sd_document_metadata_submission_api" {
  name = "${var.environment}-document-and-metadata-submission-api"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for IRS Security api
resource "aws_service_discovery_service" "sd_irs_security_api" {
  name = "${var.environment}-irs-security-api"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for S3 api
resource "aws_service_discovery_service" "sd_s3_api" {
  name = "${var.environment}-s3-api"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for Metadata Search api
resource "aws_service_discovery_service" "sd_metadata_search_api" {
  name = "${var.environment}-metadata-search-api"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for Record Management api
resource "aws_service_discovery_service" "sd_records_management_api" {
  name = "${var.environment}-records-management-api"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for Rule api
resource "aws_service_discovery_service" "sd_rule_api" {
  name = "${var.environment}-rule-api"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for External Service api
resource "aws_service_discovery_service" "sd_external_service_api" {
  name = "${var.environment}-external-service-api"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for Transform  api
resource "aws_service_discovery_service" "sd_transform_api" {
  name = "${var.environment}-transform-api"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }

}

# Creating service discovery for document
resource "aws_service_discovery_service" "sd_document_api" {
  name = "${var.environment}-document-api"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

# # Creating service discovery for upload daemon
resource "aws_service_discovery_service" "sd_upload_daemon" {
  name = "${var.environment}-upload-daemon"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for ailet gateway
resource "aws_service_discovery_service" "sd_ailet_gateway" {
  name = "${var.environment}-ailet-gateway"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for gri extraction
resource "aws_service_discovery_service" "sd_gri_extraction" {
  name = "${var.environment}-gri-extraction"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for routing daemon
resource "aws_service_discovery_service" "sd_routing_daemon" {
  name = "${var.environment}-routing-daemon"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for inbasket daemon
resource "aws_service_discovery_service" "sd_inbasket_daemon" {
  name = "${var.environment}-inbasket-daemon"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for submit daemon
resource "aws_service_discovery_service" "sd_submit_daemon" {
  name = "${var.environment}-submit-daemon"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for sense daemon
resource "aws_service_discovery_service" "sd_sense_daemon" {
  name = "${var.environment}-sense-daemon"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for dashboard-daemon
resource "aws_service_discovery_service" "sd_dashboard_daemon" {
  name = "${var.environment}-dashboard-daemon"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for tege-packager
resource "aws_service_discovery_service" "sd_tege_packager" {
  name = "${var.environment}-tege-packager"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for batch driver
resource "aws_service_discovery_service" "sd_batch_driver" {
  name = "${var.environment}-batch-driver"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

resource "aws_service_discovery_service" "sd_naix_object_classification" {
  name = "${var.environment}-naix-object-classification"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for object driver
resource "aws_service_discovery_service" "sd_object_driver" {
  name = "${var.environment}-object-driver"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for output driver
resource "aws_service_discovery_service" "sd_output_driver" {
  name = "${var.environment}-output-driver"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Creating service discovery for runocr 
resource "aws_service_discovery_service" "sd_run_ocr" {
  name = "${var.environment}-run-ocr"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

# Service discovery for XML service
resource "aws_service_discovery_service" "sd_xml_service" {
  name = "${var.environment}-xml-service"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

resource "aws_service_discovery_service" "sd_batch_inferred_mode_daemon" {
  name = "${var.environment}-batch-inferred-mode-daemon"
  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.private_dns_namespace.id

    dns_records {
      ttl  = 15
      type = "A"
    }
    routing_policy = "MULTIVALUE"
  }
  tags = {
    tag = local.env_tag
  }
}

############################## Load Balancer ##################################

# Create Load Balancer
resource "aws_alb" "load_balancer" {
  name               = "${var.organization}-${var.environment}-${var.region}-alb"
  internal           = var.is_load_balancer_internal
  load_balancer_type = var.load_balancer_type
  subnets            = ["${aws_default_subnet.default_subnet_1.id}", "${aws_default_subnet.default_subnet_2.id}"]
  security_groups    = ["${aws_security_group.lb-sg.id}"] #security group for load balancer
}

# creating load balancer listener
resource "aws_lb_listener" "lb_http_listener" {
  load_balancer_arn = aws_alb.load_balancer.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.front_end_tg.arn
  }
  tags = {
    tag = local.env_tag
  }
}

# creating Load listener to forward traffic From HTTP to HTTPS
# resource "aws_lb_listener" "lb_http_listener_redirect" {
#   load_balancer_arn = aws_alb.load_balancer.arn #  load balancer
#   port              = "80"
#   protocol          = "HTTP"
#   default_action {
#     type             = "redirect"
#     redirect {
#       port = "443"
#       protocol = "HTTPS"
#       status_code = "HTTP_301"
#     }
#   }
# }

# creating HTTPS Listener
# resource "aws_lb_listener" "lb_https_listener" {
#   load_balancer_arn = aws_alb.load_balancer.arn
#   port              = "443"
#   protocol          = "HTTPS"
#   ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
#   certificate_arn = "arn:aws:acm:us-east-2:570949364509:certificate/0cfc5971-84d0-49a6-8d79-ec8e91671cfb"
#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.fe-tg.arn # target group
#   }
# }

# Create target group for management console
resource "aws_lb_target_group" "front_end_tg" {
  name        = "${var.environment}-fe-tg"
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id
  tags = {
    tag = local.env_tag
  }
}

# Create target group for rule api
resource "aws_lb_target_group" "rule_api_tg" {
  name        = "${var.environment}-rule-api-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/rules_api/healthcheck" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

# Create target group for  document repo api
resource "aws_lb_target_group" "document_api_tg" {
  name        = "${var.environment}-document-api-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/document_repo_api/healthcheck" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

# Create target group for  scanondemandapi api
resource "aws_lb_target_group" "scan_on_demand_api_tg" {
  name        = "${var.environment}-sod-api-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/scan_on_demand_api/healthcheck" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

# Create target group for  metadata schema api
resource "aws_lb_target_group" "metadata_schema_api-tg" {
  name        = "${var.environment}-md-schema-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/metadata_schema_api/healthcheck" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

# Create target group for document and metadata submission api
resource "aws_lb_target_group" "document_metadata_submission_api_tg" {
  name        = "${var.environment}-doc-md-sb-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/doc_and_metadata_submission_api/healthcheck" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}
# Create target group for irs security api
resource "aws_lb_target_group" "irs_security_api_tg" {
  name        = "${var.environment}-irs-security-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/security_api/healthcheck" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

# Create target group for s3 api
resource "aws_lb_target_group" "s3_api_tg" {
  name        = "${var.environment}-s3-api-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/aws_s3_api/healthcheck" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}


# Create target group for elasticsearch api
resource "aws_lb_target_group" "metdata_search_api_tg" {
  name        = "${var.environment}-ms-api-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/elasticsearch_api/healthcheck" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

# Create target group for record management api
resource "aws_lb_target_group" "record_management_api_tg" {
  name        = "${var.environment}-rm-api-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/recordsmanagementapi/healthcheck" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

# Create target group for external service api
resource "aws_lb_target_group" "external_service_api_tg" {
  name        = "${var.environment}-es-api-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/external_service_api/healthcheck" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

# Create target group for transform api
resource "aws_lb_target_group" "transform_api_tg" {
  name        = "${var.environment}-xform-api-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/transform_api/healthcheck" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

# Create target group for  buow api
resource "aws_lb_target_group" "buow_api_tg" {
  name        = "${var.environment}-buow-api-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/buow_api/healthcheck" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

# Create target group for ailet gateway
resource "aws_lb_target_group" "ailet_gateway_tg" {
  name        = "${var.environment}-ailet-gw-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/gateway/status" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

# Create target group for gri extraction
resource "aws_lb_target_group" "gri_extraction_tg" {
  name        = "${var.environment}-gri-extr-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/gri_api/status" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

resource "aws_lb_target_group" "batch_driver_tg" {
  name        = "${var.environment}-batch-driver-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/batch-driver/status" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

resource "aws_lb_target_group" "tege_packager_tg" {
  name        = "${var.environment}-tege-packager-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/tege-packager/status" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

resource "aws_lb_target_group" "naix_object_classification_tg" {
  name        = "${var.environment}-obj-classix-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC


  health_check {
    path                = "/naix-object-classification/status" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

# created target group for the object driver
resource "aws_lb_target_group" "object_driver_tg" {
  name        = "${var.environment}-object-driver-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/driver/status" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

# created target group for the output driver
resource "aws_lb_target_group" "output_driver_tg" {
  name        = "${var.environment}-output-driver-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/outputdriver/status" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

# created the target group for the runocr tg
resource "aws_lb_target_group" "runocr_tg" {
  name        = "${var.environment}-runocr-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/run-ocr/status" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 300
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

# created the target group for xml service
resource "aws_lb_target_group" "xml_service_tg" {
  name        = "${var.environment}-xml-service-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default_vpc.id # default VPC

  health_check {
    path                = "/xmlsvc/status" # Replace with your health check path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    tag = local.env_tag
  }
}

///////////////////////////////////////////////////////////////////////////////////////

# creating Listener rule for document repo api
resource "aws_lb_listener_rule" "document_api_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.document_api_tg.arn # target group
  }

  priority = 111 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/document_repo_api/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# creating Listener rule for scanondemandapi
resource "aws_lb_listener_rule" "scan_on_demand_api_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.scan_on_demand_api_tg.arn # target group
  }

  priority = 112 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/scan_on_demand_api/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# creating Listener rule for  metadata schema api
resource "aws_lb_listener_rule" "metadata_schema_api_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.metadata_schema_api-tg.arn # target group
  }

  priority = 113 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/metadata_schema_api/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# creating Listener rule for  document and metadata submission api
resource "aws_lb_listener_rule" "document_metadata_submission_api_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.document_metadata_submission_api_tg.arn # target group
  }

  priority = 114 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/doc_and_metadata_submission_api/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# creating Listener rule for IRS security api
resource "aws_lb_listener_rule" "irs_security_api_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.irs_security_api_tg.arn # target group
  }

  priority = 115 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/security_api/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# creating Listener rule for  S3 api
resource "aws_lb_listener_rule" "s3_api_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.s3_api_tg.arn # target group
  }

  priority = 116 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/aws_s3_api/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# creating Listener rule for Metadata search api
resource "aws_lb_listener_rule" "metadata_search_api_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.metdata_search_api_tg.arn # target group
  }

  priority = 117 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/elasticsearch_api/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# creating Listener rule for Record Management api
resource "aws_lb_listener_rule" "records_management_api_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.record_management_api_tg.arn # target group
  }

  priority = 118 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/recordsmanagementapi/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# creating Listener rule for  External Service 
resource "aws_lb_listener_rule" "external_service_api_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.external_service_api_tg.arn # target group
  }

  priority = 119 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/external_service_api/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# creating Listener rule for Transform Api
resource "aws_lb_listener_rule" "transform_api_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.transform_api_tg.arn # target group
  }

  priority = 120 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/transform_api/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# creating Listener rule for buow Api
resource "aws_lb_listener_rule" "buow_api_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.buow_api_tg.arn # target group
  }

  priority = 121 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/buow_api/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# creating Listener rule for buow Api
resource "aws_lb_listener_rule" "rules_api_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.rule_api_tg.arn # target group
  }

  priority = 122 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/rules_api/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# creating Listener rule for ailet gateway
resource "aws_lb_listener_rule" "ailet_gateway_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ailet_gateway_tg.arn
  }

  priority = 123 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/gateway/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# creating Listener rule for gri extraction
resource "aws_lb_listener_rule" "gri_extraction_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gri_extraction_tg.arn # target group
  }

  priority = 124 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/gri_api/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# creating Listener rule for batch driver
resource "aws_lb_listener_rule" "batch_driver_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.batch_driver_tg.arn # target group
  }

  priority = 127 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/batch-driver/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# creating Listener rule for naix object classification
resource "aws_lb_listener_rule" "naix_object_classification_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.naix_object_classification_tg.arn # target group
  }

  priority = 128 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/naix-object-classification/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# created the listerner rule for object driver
resource "aws_lb_listener_rule" "object_driver_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.object_driver_tg.arn # target group
  }

  priority = 129 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/driver/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# created the listerner rule for outputdriver
resource "aws_lb_listener_rule" "output_driver_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.output_driver_tg.arn # target group
  }

  priority = 130 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/outputdriver/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

#created listerner rule for run-ocr
resource "aws_lb_listener_rule" "run_ocr_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.runocr_tg.arn # target group
  }

  priority = 131 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/run-ocr/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

# lb_listerner rule for XML service
resource "aws_lb_listener_rule" "xml_service_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.xml_service_tg.arn # target group
  }

  priority = 132 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/xmlsvc/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}
# lb_listerner rule for XML service
resource "aws_lb_listener_rule" "tege_packager_l" {
  listener_arn = aws_lb_listener.lb_http_listener.arn #  load balancer

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tege_packager_tg.arn # target group
  }

  priority = 133 # Set the desired priority for the rule

  condition {
    path_pattern {
      values = ["/tege-packager/*"] # Replace with your desired path pattern
    }
  }
  tags = {
    tag = local.env_tag
  }
}

##################################  Pre-Processor/Bastion Role  ####################################

# creating Iam Role for Bastion
resource "aws_iam_role" "bastion_host_role" {
  name = "${var.organization}-${var.environment}-${var.region}-bastion-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# attach role to instance profile for Bastion server
resource "aws_iam_instance_profile" "bastion-role-instance-profile" {
  name = "${var.environment}-bastion-role-instance-profile"
  role = aws_iam_role.bastion_host_role.name
}

# Creating policy for Bastion server
resource "aws_iam_policy" "bastion_access_policy" {
  name = "${var.environment}-bastion-access-policy"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Elastic Container Service (ECS)
      {
        Action = [
          "ecs:List*",
          "ecs:Describe*",
        ],
        Effect   = "Allow",
        Resource = "*",
      },
      # Amazon RDS
      {
        Action = [
          "rds:Describe*",
          "rds:List*",
          "rds:Create*",
        ],
        Effect   = "Allow",
        Resource = "*",
      },
      # Amazon EC2
      {
        Action = [
          "ec2:Describe*",
        ],
        Effect   = "Allow",
        Resource = "*",
      },
      # Amazon ECR
      {
        Action = [
          "ecr:Get*",
          "ecr:List*",
          "ecr:Describe*",
          "ecr:Put*",
        ],
        Effect   = "Allow",
        Resource = "*",
      },
      # Systems Manager (SSM)
      {
        Action = [
          "ssm:Get*",
          "ssm:List*",
          "ssm:Describe*",
          "ssm:Create*",
        ],
        Effect   = "Allow",
        Resource = "*",
      },

      # Amazon ElastiCache (Redis)
      {
        Action = [
          "elasticache:Describe*",
          "elasticache:List*",
          "elasticache:Create*",
        ],
        Effect   = "Allow",
        Resource = "*",
      },

      # Amazon S3
      {
        Action = [
          "s3:Get*",
          "s3:List*",
          "s3:Put*",
        ],
        Effect   = "Allow",
        Resource = "*",
      }
    ]
  })
}

# attach policy with Bastion server role
resource "aws_iam_role_policy_attachment" "bastion_role_policy_attachment" {
  role       = aws_iam_role.bastion_host_role.name
  policy_arn = aws_iam_policy.bastion_access_policy.arn
}
############################ ECS-Role-Policy-Permission ##################################  
# Create IAM Role for ECS Task Execution
resource "aws_iam_role" "ecs_task_execution_role" {
  name               = "${var.environment}-ECS-TaskExecution-Role"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role_policy.json
}

# IAM Assume Role Policy for ECS Tasks
data "aws_iam_policy_document" "ecs_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# List of policies to attach
locals {
  ecs_task_policies = [
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    "arn:aws:iam::aws:policy/AmazonElastiCacheFullAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/SecretsManagerReadWrite",
    "arn:aws:iam::aws:policy/AmazonECS_FullAccess",
    "arn:aws:iam::aws:policy/AWSBatchFullAccess",
    "arn:aws:iam::aws:policy/AmazonSESFullAccess",
    "arn:aws:iam::aws:policy/AWSCloudMapFullAccess",
    "arn:aws:iam::aws:policy/AmazonTextractFullAccess"
  ]
}

# Attach all IAM policies to ECS task role
resource "aws_iam_role_policy_attachment" "ecs_task_execution_policies" {
  for_each   = toset(local.ecs_task_policies)
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = each.value
}

################################ ECS-Service ########################################
# created ECS Cluster 
resource "aws_ecs_cluster" "ecs-cluster" {
  name = "${var.organization}-${var.environment}-${var.region}-ecs-cluster"
}

# created aws cloudwatch log for management console group
resource "aws_cloudwatch_log_group" "fe-logs" {
  name = "/ecs/fargate-task-${var.environment}-fe-logs"
  tags = {
    tag = local.env_tag
  }
}

#1 created ecs task defination for front end api
resource "aws_ecs_task_definition" "fargate-task-fe" {
  family                   = "fargate-task-${var.environment}-fe"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.react_app_cpu_unit
  memory                   = var.react_app_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-fe",
    "image": "${aws_ecr_repository.ecr_fe.repository_url}",
    "portMappings": [
      {
        "containerPort": 80,
        "hostPort": 80
      }
    ],
    "cpu": ${var.react_app_cpu_unit},
    "memory": ${var.react_app_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.fe-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "environment": [
        { "name": "REACT_APP_EAUTH_LOGOUT_URL",              "value": "${var.react_app_eauth_logout_url}" },
        { "name": "REACT_APP_TIME_OUT",                      "value": "${var.react_app_time_out}" },
        { "name": "REACT_APP_EAUTH_DISABLE",                 "value": "${var.react_app_eauth_disable}" },
        { "name": "REACT_APP_OKTA_BASE_URL",                 "value": "${var.react_app_okta_base_url}" },
        { "name": "REACT_APP_OKTA_CLIENT_ID",                "value": "${var.react_app_okta_client_id}" },
        { "name": "REACT_APP_BACKEND_URL",                   "value": "http://${aws_alb.load_balancer.dns_name}" },
        { "name": "REACT_APP_ENVIRONMENT",                   "value": "${var.environment}" },
        { "name": "REACT_APP_S3_USER_GUIDE_BUCKET_NAME",     "value": "${local.s3_general_bucket_name}" },
        { "name": "REACT_APP_S3_USER_GUIDE_FOLDER_NAME",     "value": "${var.react_app_s3_user_guide_folder_name}" },
        { "name": "REACT_APP_USER_GUIDE_OBJECT_NAME",        "value": "${var.react_app_user_guide_object_name}" },
        { "name": "REACT_APP_CLIENT_NAME",                   "value": "${var.react_app_client_name}" },
        { "name": "REACT_APP_CLIENT_CONTEXT_ID",             "value": "${var.app_context_id}" },
        { "name": "REACT_APP_GUIDE_VISIBLE",                 "value": "${var.react_app_guide_visible}" }
      ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#2 created frontend service
resource "aws_ecs_service" "ecs_app_service" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-app-service" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                         # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-fe.arn                            # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.front_end_tg, aws_lb_listener.lb_http_listener]

  desired_count = 1 # Set up the number of containers to 1
  # Optional: Allow external changes without Terraform plan difference
  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.front_end_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-fe.family
    container_port   = 80 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_management_console.arn
  }
  tags = {
    tag = local.env_tag
  }
}


# created aws cloudwatch log group for buow api
resource "aws_cloudwatch_log_group" "buow_api_logs" {
  name = "/ecs/fargate-task-${var.environment}-buow-api-logs"
  tags = {
    tag = local.env_tag
  }
}

#1 created ecs task defination for buow api
resource "aws_ecs_task_definition" "fargate-task-buow-api" {
  family                   = "fargate-task-${var.environment}-buow-api"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.buow_api_cpu_unit
  memory                   = var.buow_api_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-buow-api",
    "image": "${aws_ecr_repository.ecr_buow_api_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.buow_api_cpu_unit},
    "memory": ${var.buow_api_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.buow_api_logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
    "environment": [
      { "name": "SERVER_PORT",                               "value": "${var.ecs_service_port}" },
      { "name": "SERVER_SSL_ENABLED",                        "value": "${var.ecs_server_ssl_enabled}" },
      { "name": "SPRING_DATASOURCE_URL",                     "value": "jdbc-secretsmanager:postgresql://${aws_rds_cluster.aurora_rds_database_cluster.endpoint}:${var.aurora_db_port}/${var.aurora_db_name}" },
      { "name": "SPRING_DATASOURCE_DRIVER-CLASS-NAME",       "value": "${var.datasource_driver_class_name}" },
      { "name": "SPRING_DATASOURCE_USERNAME",                "value": "${local.secret_manager_database_source}" },
      { "name": "METADATAAPI_SERVICE_HOST",                  "value": "${local.metadata_search_api_call}" },
      { "name": "METADATAAPI_SERVICE_PORT",                  "value": "${var.ecs_service_port}" },
      { "name": "METADATAAPI_SERVICE_URI",                   "value": "${var.metadata_search_api_uri}" },
      { "name": "SECURITYAPI_SERVICE_HOST",                  "value": "${local.irs_security_api_call}" },
      { "name": "SECURITYAPI_SERVICE_PORT",                  "value": "${var.ecs_service_port}" },
      { "name": "SECURITYAPI_SERVICE_URI",                   "value": "${var.security_api_uri}" },
      { "name": "SUBMISSIONAPI_SERVICE_HOST",                "value": "${local.document_and_metadata_submission_api_call}" },
      { "name": "SUBMISSIONAPI_SERVICE_PORT",                "value": "${var.ecs_service_port}" },
      { "name": "SUBMISSIONAPI_SERVICE_URI",                 "value": "${var.document_metadata_submission_api_uri}" },
      { "name": "SCANONDEMANDAPI_SERVICE_HOST",              "value": "${local.scan_on_demand_api_call}" },
      { "name": "SCANONDEMANDAPI_SERVICE_PORT",              "value": "${var.ecs_service_port}" },
      { "name": "SCANONDEMANDAPI_SERVICE_URI",               "value": "${var.scan_on_demand_api_uri}" },
      { "name": "OUTPUTDRIVER_SERVICE_HOST",                 "value": "${local.batch_driver_api_call}" },
      { "name": "OUTPUTDRIVER_SERVICE_PORT",                 "value": "${var.ecs_service_port}" },
      { "name": "OUTPUTDRIVER_SERVICE_URI",                  "value": "${var.batch_driver_api_uri}output_driver" },
      { "name": "BATCHDRIVER_SERVICE_URI",                   "value": "${var.batch_driver_api_uri}process-batch" },
      { "name": "SPRING_REDIS_HOST",                         "value": "${aws_elasticache_replication_group.elastic_cache_redis_rg.primary_endpoint_address}" },
      { "name": "SPRING_REDIS_PORT",                         "value": "${var.elasticache_redis_port}" },
      { "name": "SPRING_REDIS_DATABASE",                     "value": "${var.elasticache_redis_database}" },
      { "name": "SPRING_REDIS_SSL",                          "value": "${var.elasticache_redis_ssl_enabled}" },
      { "name": "SPRING_CACHE_REDIS_USE-KEY-PREFIX",         "value": "${var.elasticache_redis_use_key_prefix}" },
      { "name": "SPRING_CACHE_REDIS_KEY-PREFIX",             "value": "${var.environment}-" },
      { "name": "RETRY_MAXATTEMPTS",                         "value": "${var.buow_api_retry_maxattempts}" },
      { "name": "RETRY_TIMEINTERVAL",                        "value": "${var.buow_api_retry_timeinterval}" },
      { "name": "SENTIMENT_API_SERVICE.URI",                 "value": "${var.buow_api_sentiment_api_service_uri}" },
      { "name": "READABILITY_API_SERVICE_URI",               "value": "${var.buow_api_readability_api_service_uri}" },
      { "name": "SUMMARY_API_SERVICE_URI",                   "value": "${var.buow_api_summary_api_service_uri}" },
      { "name": "LANGUAGE_API_SERVICE_URI",                  "value": "${var.buow_api_language_api_service_uri}" },
      { "name": "TRUTH_API_SERVICE_URI",                     "value": "${var.buow_api_truth_api_service_uri}" },
      { "name": "BUOW_API_HOST_URL",                         "value": "http://${local.buow_api_call}:${var.ecs_service_port}${var.buow_api_uri}sentiments"},
      { "name": "SPRING_FLYWAY_OUT-OF-ORDER",                "value": "${var.buow_api_spring_flyway_out_of_order}" },
      { "name": "SPRING_DATA_REDIS_REPOSITORIES_ENABLED",    "value": "${var.elasticache_redis_repositories_enabled}" },
      { "name": "BUOW_WORKFLOW_BASE_URL",                    "value": "http://${aws_alb.load_balancer.dns_name}/buow/" }
    ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#1 created buow api service
resource "aws_ecs_service" "ecs_buow_api" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-buow-api" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                      # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-buow-api.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.buow_api_tg, aws_lb_listener_rule.buow_api_l]

  lifecycle {
    ignore_changes = [desired_count]

  }

  load_balancer {
    target_group_arn = aws_lb_target_group.buow_api_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-buow-api.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_buow_api.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#2 create a cloudwatch for the recordsmanagement api service
resource "aws_cloudwatch_log_group" "records-management-api-logs" {
  name = "/ecs/fargate-task-${var.environment}-records-management-api-logs"
  tags = {
    tag = local.env_tag
  }
}

#2 create a task definition for the  recordsmanagement api
resource "aws_ecs_task_definition" "fargate-task-records-management-api" {
  family                   = "fargate-task-${var.environment}-records-management-api"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.rdms_cpu_unit
  memory                   = var.rdms_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-records-management-api",
    "image": "${aws_ecr_repository.ecr_records_management_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.rdms_cpu_unit},
    "memory": ${var.rdms_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.records-management-api-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "environment": [
        { "name": "SERVER_PORT",                                "value": "${var.ecs_service_port}" },
        { "name": "SERVER_SSL_ENABLED",                         "value": "${var.ecs_server_ssl_enabled}" },
        { "name": "SPRING_DATASOURCE_URL",                      "value": "jdbc-secretsmanager:postgresql://${aws_rds_cluster.aurora_rds_database_cluster.endpoint}:${var.aurora_db_port}/${var.aurora_db_name}" },
        { "name": "SPRING_DATASOURCE_DRIVER-CLASS-NAME",        "value": "${var.datasource_driver_class_name}" },
        { "name": "SPRING_DATASOURCE_USERNAME",                 "value": "${local.secret_manager_database_source}" },
        { "name": "AMAZONPROPERTIES_AWSREGION",                 "value": "${var.aws_region}" },
        { "name": "AMAZONPROPERTIES_AWSRBATCHJOB_DEFINITION",   "value": "${local.records_management_xfer_batch_jobdefinition}" },
        { "name": "AMAZONPROPERTIES_AWSRBATCHJOB_QUEUE",        "value": "${local.records_management_xfer_batch_jobqueue}" },
        { "name": "AMAZONPROPERTIES_AWSRBATCHJOB_EXECUTION_PARAM", "value": "${var.rdms_amazonproperties_awsrbatchjob_execution_param}" },
        { "name": "METADATAAPI_SERVICE_HOST",                   "value": "${local.metadata_search_api_call}" },
        { "name": "METADATAAPI_SERVICE_PORT",                   "value": "${var.ecs_service_port}" },
        { "name": "METADATAAPI_SERVICE_URI",                    "value": "${var.metadata_search_api_uri}" },
        { "name": "SECURITYAPI_SERVICE_HOST",                   "value": "${local.irs_security_api_call}" },
        { "name": "SECURITYAPI_SERVICE_PORT",                   "value": "${var.ecs_service_port}" },
        { "name": "SECURITYAPI_SERVICE_URI",                    "value": "${var.security_api_uri}" },
        { "name": "RETRY_MAXATTEMPTS",                          "value": "${var.rdms_retry_maxattempts}" },
        { "name": "RETRY_TIMEINTERVAL",                         "value": "${var.rdms_retry_timeinterval}" }
      ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#2 create a aws ecs service for the  records management api
resource "aws_ecs_service" "ecs_records_management_api" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-records-management-api" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                                    # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-records-management-api.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.record_management_api_tg, aws_lb_listener_rule.records_management_api_l]

  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.record_management_api_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-records-management-api.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_records_management_api.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#3 create a cloudwatch for the document metadata api service
resource "aws_cloudwatch_log_group" "document-metadata-api-logs" {
  name = "/ecs/fargate-task-${var.environment}-document-metadata-api-logs"
  tags = {
    tag = local.env_tag
  }
}

#3 create a task definition for the  document metadata api
resource "aws_ecs_task_definition" "fargate-task-document-metadata-api" {
  family                   = "fargate-task-${var.environment}-document-metadata-api"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.doc_metadata_sub_cpu_unit
  memory                   = var.doc_metadata_sub_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-document-metadata-api",
    "image": "${aws_ecr_repository.ecr_document_metadata_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.doc_metadata_sub_cpu_unit},
    "memory": ${var.doc_metadata_sub_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.document-metadata-api-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "environment": [
      { "name": "SERVER_PORT",                                "value": "${var.ecs_service_port}" },
      { "name": "SERVER_SSL_ENABLED",                         "value": "${var.ecs_server_ssl_enabled}" },
      { "name": "SPRING_DATASOURCE_URL",                      "value": "jdbc-secretsmanager:postgresql://${aws_rds_cluster.aurora_rds_database_cluster.endpoint}:${var.aurora_db_port}/${var.aurora_db_name}" },
      { "name": "SPRING_DATASOURCE_DRIVER-CLASS-NAME",        "value": "${var.datasource_driver_class_name}" },
      { "name": "SPRING_DATASOURCE_USERNAME",                 "value": "${local.secret_manager_database_source}" },
      { "name": "METADATAAPI_SERVICE_HOST",                   "value": "${local.metadata_search_api_call}" },
      { "name": "METADATAAPI_SERVICE_PORT",                   "value": "${var.ecs_service_port}" },
      { "name": "METADATAAPI_SERVICE_URI",                    "value": "${var.metadata_search_api_uri}" },
      { "name": "SECURITYAPI_SERVICE_HOST",                   "value": "${local.irs_security_api_call}" },
      { "name": "SECURITYAPI_SERVICE_PORT",                   "value": "${var.ecs_service_port}" },
      { "name": "SECURITYAPI_SERVICE_URI",                    "value": "${var.security_api_uri}" },
      { "name": "DOCUMENTREPOAPI_SERVICE_HOST",               "value": "${local.document_api_call}" },
      { "name": "DOCUMENTREPOAPI_SERVICE_PORT",               "value": "${var.ecs_service_port}" },
      { "name": "DOCUMENTREPOAPI_SERVICE_URI",                "value": "${var.document_repo_api_uri}" },
      { "name": "RECORDSMANAGEMENTAPI_SERVICE_HOST",          "value": "${local.records_management_api_call}" },
      { "name": "RECORDSMANAGEMENTAPI_SERVICE_PORT",          "value": "${var.ecs_service_port}" },
      { "name": "RECORDSMANAGEMENTAPI_SERVICE_URI",           "value": "${var.records_management_api_uri}" },
      { "name": "RULESAPI_SERVICE_HOST",                      "value": "${local.rule_api_call}" },
      { "name": "RULESAPI_SERVICE_PORT",                      "value": "${var.ecs_service_port}" },
      { "name": "RULESAPI_SERVICE_URI",                       "value": "${var.rules_api_uri}" },
      { "name": "SCANONDEMAND_SERVICE_HOST",                  "value": "${local.scan_on_demand_api_call}" },
      { "name": "SCANONDEMAND_SERVICE_PORT",                  "value": "${var.ecs_service_port}" },
      { "name": "SCANONDEMAND_SERVICE_URI",                   "value": "${var.scan_on_demand_api_uri}" },
      { "name": "SECRETS-MANAGER_JWT_ID",                     "value": "${local.secret_manager_jwt_id}" },
      { "name": "S3_BUCKET_AGENCY_IRS",                       "value": "${local.s3_bucket_name}" },
      { "name": "S3_BUCKET_AGENCY_FBC",                       "value": "${local.s3_bucket_name}" },
      { "name": "S3_BUCKET_AGENCY_FSA",                       "value": "${local.s3_bucket_name}" },
      { "name": "S3_BUCKET_AGENCY_NRCS",                      "value": "${local.s3_bucket_name}" },
      { "name": "S3_BUCKET_AGENCY_RMA",                       "value": "${local.s3_bucket_name}" },
      { "name": "SPRING_SERVLET_MULTIPART_MAX-FILE-SIZE",     "value": "${var.doc_metadata_sub_spring_servlet_multipart_max_file_size}" },
      { "name": "SPRING_SERVLET_MULTIPART_MAX-REQUEST-SIZE",  "value": "${var.doc_metadata_sub_spring_servlet_multipart_max_request_size}" },
      { "name": "RETRY_MAXATTEMPTS",                          "value": "${var.doc_metadata_sub_retry_maxattempts}" },
      { "name": "RETRY_TIMEINTERVAL",                         "value": "${var.doc_metadata_sub_retry_timeinterval}" }
    ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#3 create a aws ecs service for the  document metadata api 
resource "aws_ecs_service" "ecs_document_metadata_api" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-document-metadata-api" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                                   # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-document-metadata-api.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.document_metadata_submission_api_tg, aws_lb_listener_rule.document_metadata_submission_api_l]

  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.document_metadata_submission_api_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-document-metadata-api.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_document_metadata_submission_api.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#4 create a cloudwatch for the external sevice api service
resource "aws_cloudwatch_log_group" "external-service-api-logs" {
  name = "/ecs/fargate-task-${var.environment}-external-service-api-logs"
  tags = {
    tag = local.env_tag
  }
}

#4 create a task definition for the  external service api 
resource "aws_ecs_task_definition" "fargate-task-external-service-api" {
  family                   = "fargate-task-${var.environment}-external-service-api"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.external_service_cpu_unit
  memory                   = var.external_service_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-external-service-api",
    "image": "${aws_ecr_repository.ecr_external_service_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.external_service_cpu_unit},
    "memory": ${var.external_service_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.external-service-api-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "environment": [
        { "name": "SERVER_PORT",                                         "value": "${var.ecs_service_port}" },
        { "name": "SERVER_SSL_ENABLED",                                  "value": "${var.ecs_server_ssl_enabled}" },
        { "name": "EXTERNAL_SERVICE_DATASOURCE",                         "value": "${var.external_service_datasource}" },
        { "name": "EXTERNALSERVICE_SCIMS_URI",                           "value": "${var.external_service_scims_uri}" },
        { "name": "EXTERNALSERVICE_LSD_URI",                             "value": "${var.external_service_lsd_uri}" },
        { "name": "EXTERNALSERVICE_EAS_URI",                             "value": "${var.external_service_eas_uri}" },
        { "name": "EXTERNAL_DRMS_ZROLES_SERVICE_URI",                    "value": "${var.external_service_zroles_service_uri}" },
        { "name": "EXTERNAL_DRMS_ZROLES_SERVICE_GETUSERACCESSROLESANDSCOPES_SOAP_ACTION", "value": "${var.external_service_zroles_service_getuseraccessrolesandscopes_soap_action}" },
        { "name": "EXTERNAL_DRMS_ZROLES_SERVICE_NAMESPACE_URI",          "value": "${var.external_service_zroles_service_namespace_uri}" },
        { "name": "EXTERNAL_DRMS_ZROLES_SERVICE_WS_SECURED_TOKEN",       "value": "${var.external_service_zroles_service_ws_secured_token}" },
        { "name": "EXTERNAL_DRMS_EAS_TESTEAUTHID",                       "value": "${var.external_service_eas_testeauthid}" },
        { "name": "EXTERNAL_DRMS_EAS_TESTROLE",                          "value": "${var.external_service_eas_testrole}" },
        { "name": "SECURITYAPI_SERVICE_HOST",                            "value": "${local.irs_security_api_call}" },
        { "name": "SECURITYAPI_SERVICE_PORT",                            "value": "${var.ecs_service_port}" },
        { "name": "SECURITYAPI_SERVICE_URI",                             "value": "${var.security_api_uri}" }
      ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#4 create a ecs service for the external service api service
resource "aws_ecs_service" "ecs_external_service_api" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-external-service-api" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                                  # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-external-service-api.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.external_service_api_tg, aws_lb_listener_rule.external_service_api_l]

  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.external_service_api_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-external-service-api.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_external_service_api.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#5 create a aws cloudwatch log group for the document repository api service
resource "aws_cloudwatch_log_group" "document-api-logs" {
  name = "/ecs/fargate-task-${var.environment}-document-api-logs"
  tags = {
    tag = local.env_tag
  }
}

#5 create a  task definition for the document repository api service
resource "aws_ecs_task_definition" "fargate-task-document-api" {
  family                   = "fargate-task-${var.environment}-document-api"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.doc_repo_cpu_unit
  memory                   = var.doc_repo_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-document-api",
    "image": "${aws_ecr_repository.ecr_document_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.doc_repo_cpu_unit},
    "memory": ${var.doc_repo_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.document-api-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "environment": [
      { "name": "SERVER_PORT",                                "value": "${var.ecs_service_port}" },
      { "name": "SERVER_SSL_ENABLED",                         "value": "${var.ecs_server_ssl_enabled}" },
      { "name": "ALFRESCOAPI_SERVICE_HOST",                   "value": "${local.alfresco_api_call}" },
      { "name": "ALFRESCOAPI_SERVICE_PORT",                   "value": "${var.ecs_service_port}" },
      { "name": "ALFRESCOAPI_SERVICE_URI",                    "value": "${var.alfresco_api_uri}alfresco/" },
      { "name": "SECURITYAPI_SERVICE_HOST",                   "value": "${local.irs_security_api_call}" },
      { "name": "SECURITYAPI_SERVICE_PORT",                   "value": "${var.ecs_service_port}" },
      { "name": "SECURITYAPI_SERVICE_URI",                    "value": "${var.security_api_uri}" },
      { "name": "SECRETS-MANAGER_JWT_ID",                     "value": "${local.secret_manager_jwt_id}" },
      { "name": "SPRING_SERVLET_MULTIPART_MAX-FILE-SIZE",     "value": "${var.doc_repo_spring_servlet_multipart_max_file_size}" },
      { "name": "SPRING_SERVLET_MULTIPART_MAX-REQUEST-SIZE",  "value": "${var.doc_repo_spring_servlet_multipart_max_request_size}" },
      { "name": "RETRY_MAXATTEMPTS",                          "value": "${var.doc_repo_retry_maxattempts}" },
      { "name": "RETRY_TIMEINTERVAL",                         "value": "${var.doc_repo_retry_timeinterval}" },
      { "name": "S3API_SERVICE_HOST",                         "value": "${local.s3_api_call}" },
      { "name": "S3API_SERVICE_PORT",                         "value": "${var.ecs_service_port}" },
      { "name": "S3API_SERVICE_URI",                          "value": "${var.s3_api_uri}" }
    ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#5 Create a aws ecs service for the  document api
resource "aws_ecs_service" "ecs_document_api" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-document-api" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                          # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-document-api.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.document_api_tg, aws_lb_listener_rule.document_api_l]

  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.document_api_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-document-api.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_document_api.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#6 create a aws cloudwatch log group for the rule api service
resource "aws_cloudwatch_log_group" "rule-api-logs" {
  name = "/ecs/fargate-task-${var.environment}-rule-api-logs"
  tags = {
    tag = local.env_tag
  }
}

#6 create a task definition for the  rule api service
resource "aws_ecs_task_definition" "fargate-task-rule-api" {
  family                   = "fargate-task-${var.environment}-rule-api"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.rule_api_cpu_unit
  memory                   = var.rule_api_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-rule-api",
    "image": "${aws_ecr_repository.ecr_rule_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.rule_api_cpu_unit},
    "memory": ${var.rule_api_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.rule-api-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "environment": [
        { "name": "SERVER_PORT",                           "value": "${var.ecs_service_port}" },
        { "name": "SERVER_SSL_ENABLED",                    "value": "${var.ecs_server_ssl_enabled}" },
        { "name": "SPRING_DATASOURCE_URL",                 "value": "jdbc-secretsmanager:postgresql://${aws_rds_cluster.aurora_rds_database_cluster.endpoint}:${var.aurora_db_port}/${var.aurora_db_name}" },
        { "name": "SPRING_DATASOURCE_DRIVER-CLASS-NAME",   "value": "${var.datasource_driver_class_name}" },
        { "name": "SPRING_DATASOURCE_USERNAME",            "value": "${local.secret_manager_database_source}" },
        { "name": "SPRING_DATA_REDIS_REPOSITORIES_ENABLED","value": "${var.elasticache_redis_repositories_enabled}" },
        { "name": "SPRING_REDIS_HOST",                     "value": "${aws_elasticache_replication_group.elastic_cache_redis_rg.primary_endpoint_address}" },
        { "name": "SPRING_REDIS_PORT",                     "value": "${var.elasticache_redis_port}" },
        { "name": "SPRING_REDIS_DATABASE",                 "value": "${var.elasticache_redis_database}" },
        { "name": "SPRING_REDIS_SSL",                      "value": "${var.elasticache_redis_ssl_enabled}" },
        { "name": "SPRING_CACHE_REDIS_USE-KEY-PREFIX",     "value": "${var.elasticache_redis_use_key_prefix}" },
        { "name": "SPRING_CACHE_REDIS_KEY-PREFIX",         "value": "${var.environment}-" },
        { "name": "SECRETS-MANAGER_JWT_ID",                "value": "${local.secret_manager_jwt_id}" },
        { "name": "SECURITYAPI_SERVICE_HOST",              "value": "${local.irs_security_api_call}" },
        { "name": "SECURITYAPI_SERVICE_PORT",              "value": "${var.ecs_service_port}" },
        { "name": "SECURITYAPI_SERVICE_URI",               "value": "${var.security_api_uri}" }
      ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#6 create a aws ecs service for the rule api service
resource "aws_ecs_service" "ecs_rule_api" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-rule-api" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                      # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-rule-api.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.rule_api_tg, aws_lb_listener_rule.rules_api_l]

  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.rule_api_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-rule-api.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_rule_api.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#7 create a aws ecs service for the metadata schema api service 
resource "aws_cloudwatch_log_group" "metadata-schema-api-logs" {
  name = "/ecs/fargate-task-${var.environment}-metadata-schema-api-logs"
  tags = {
    tag = local.env_tag
  }
}

#7 create a task definition for the meatadata schema api service 
resource "aws_ecs_task_definition" "fargate-task-metadata-schema-api" {
  family                   = "fargate-task-${var.environment}-metadata-schema-api"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.metadata_schema_cpu_unit
  memory                   = var.metadata_schema_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-metadata-schema-api",
    "image": "${aws_ecr_repository.ecr_metadata_schema_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.metadata_schema_cpu_unit},
    "memory": ${var.metadata_schema_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.metadata-schema-api-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "environment": [
      { "name": "SERVER_PORT",                         "value": "${var.ecs_service_port}" },
      { "name": "SERVER_SSL_ENABLED",                  "value": "${var.ecs_server_ssl_enabled}" },
      { "name": "SPRING_DATASOURCE_URL",               "value": "jdbc-secretsmanager:postgresql://${aws_rds_cluster.aurora_rds_database_cluster.endpoint}:${var.aurora_db_port}/${var.aurora_db_name}" },
      { "name": "SPRING_DATASOURCE_DRIVER-CLASS-NAME", "value": "${var.datasource_driver_class_name}" },
      { "name": "SPRING_DATASOURCE_USERNAME",          "value": "${local.secret_manager_database_source}" },
      { "name": "SECURITYAPI_SERVICE_HOST",            "value": "${local.irs_security_api_call}" },
      { "name": "SECURITYAPI_SERVICE_PORT",            "value": "${var.ecs_service_port}" },
      { "name": "SECURITYAPI_SERVICE_URI",             "value": "${var.security_api_uri}" }
    ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#7 Create a ecs service for the  metadata schema api service
resource "aws_ecs_service" "ecs_metadata_schema_api" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-metadata-schema-api" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                                 # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-metadata-schema-api.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.metadata_schema_api-tg, aws_lb_listener_rule.metadata_schema_api_l]
  # Optional: Allow external changes without Terraform plan difference
  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.metadata_schema_api-tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-metadata-schema-api.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_metadata_schema_api.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#8 create a cloudwatch log group for the metadata search api service
resource "aws_cloudwatch_log_group" "metadata-search-api-logs" {
  name = "/ecs/fargate-task-${var.environment}-metadata-search-api-logs"
  tags = {
    tag = local.env_tag
  }
}

#8 create a task definition for the metadata search api service
resource "aws_ecs_task_definition" "fargate-task-metadata-search-api" {
  family                   = "fargate-task-${var.environment}-metadata-search-api"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.metadata_search_cpu_unit
  memory                   = var.metadata_search_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-metadata-search-api",
    "image": "${aws_ecr_repository.ecr_metadata_search_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.metadata_search_cpu_unit},
    "memory": ${var.metadata_search_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.metadata-search-api-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
     "environment": [
        { "name": "SERVER_SSL_ENABLED",                         "value": "${var.ecs_server_ssl_enabled}" },
        { "name": "SPRING_DATA_ELASTICSEARCH_PROPERTIES_HOST",  "value": "${local.opensearch_api_call}" },
        { "name": "SPRING_DATA_ELASTICSEARCH_PROPERTIES_PORT",  "value": "${var.metadata_search_elasticsearch_port}" },
        { "name": "ELASTICSEARCH_INDEX_NAME",                   "value": "${var.metadata_search_elasticsearch_index_name}" },
        { "name": "SCANONDEMAND_SERVICE_HOST",                  "value": "${local.scan_on_demand_api_call}" },
        { "name": "SCANONDEMAND_SERVICE_PORT",                  "value": "${var.ecs_service_port}" },
        { "name": "SCANONDEMAND_SERVICE_URI",                   "value": "${var.scan_on_demand_api_uri}" },
        { "name": "BUOW_SERVICE_HOST",                          "value": "${local.buow_api_call}" },
        { "name": "BUOW_SERVICE_PORT",                          "value": "${var.ecs_service_port}" },
        { "name": "BUOW_SERVICE_URI",                           "value": "${var.buow_api_uri}" },
        { "name": "SECURITYAPI_SERVICE_HOST",                   "value": "${local.irs_security_api_call}" },
        { "name": "SECURITYAPI_SERVICE_PORT",                   "value": "${var.ecs_service_port}" },
        { "name": "SECURITYAPI_SERVICE_URI",                    "value": "${var.security_api_uri}" }
      ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#8 create aws ecs service for the  metadata search service 
resource "aws_ecs_service" "ecs-metadata-search-api" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-metadata-search-api" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                                 # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-metadata-search-api.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.metdata_search_api_tg, aws_lb_listener_rule.metadata_search_api_l]

  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.metdata_search_api_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-metadata-search-api.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_metadata_search_api.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#9 create an AWS cloudwatch log group service for the s3 api service
resource "aws_cloudwatch_log_group" "s3-api-logs" {
  name = "/ecs/fargate-task-${var.environment}-s3-api-logs"
  tags = {
    tag = local.env_tag
  }
}

#9 create a task defination for the s3 api service
resource "aws_ecs_task_definition" "fargate-task-s3-api" {
  family                   = "fargate-task-${var.environment}-s3-api"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.s3_api_cpu_unit
  memory                   = var.s3_api_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-s3-api",
    "image": "${aws_ecr_repository.ecr_s3_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.s3_api_cpu_unit},
    "memory": ${var.s3_api_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.s3-api-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "environment": [
      { "name": "SERVER_PORT",                              "value": "${var.ecs_service_port}" },
      { "name": "SERVER_SSL_ENABLED",                       "value": "${var.ecs_server_ssl_enabled}" },
      { "name": "AMAZONPROPERTIES_AWSREGION",               "value": "${var.aws_region}" },
      { "name": "AMAZONPROPERTIES_AWSTESTBUCKET",           "value": "${local.s3_bucket_name}" },
      { "name": "AMAZONPROPERTIES_AWSBUCKET_TEST",          "value": "${local.s3_bucket_name}" },
      { "name": "AMAZONPROPERTIES_AWSBUCKET_TEST2",         "value": "${local.s3_bucket_name}" },
      { "name": "SPRING_SERVLET_MULTIPART_MAX_FILE_SIZE",   "value": "${var.s3_api_max_file_size}" },
      { "name": "SPRING_SERVLET_MULTIPART_MAX_REQUEST_SIZE","value": "${var.s3_api_max_request_size}" },
      { "name": "SPRING_AUTOCONFIGURE_EXCLUDE",             "value": "${var.spring_autoconfigure_exclude}" },
      { "name": "SPRING_DATASOURCE_URL",                    "value": "jdbc-secretsmanager:postgresql://${aws_rds_cluster.aurora_rds_database_cluster.endpoint}:${var.aurora_db_port}/${var.aurora_db_name}" },
      { "name": "SPRING_DATASOURCE_DRIVER_CLASS_NAME",      "value": "${var.datasource_driver_class_name}" },
      { "name": "SPRING_DATASOURCE_USERNAME",               "value": "${local.secret_manager_database_source}" },
      { "name": "SECURITYAPI_SERVICE_HOST",                 "value": "${local.irs_security_api_call}" },
      { "name": "SECURITYAPI_SERVICE_PORT",                 "value": "${var.ecs_service_port}" },
      { "name": "SECURITYAPI_SERVICE_URI",                  "value": "${var.security_api_uri}" }
    ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#9 create a aws ecs service for the app service s3 api
resource "aws_ecs_service" "ecs_s3_api" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-s3-api" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                    # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-s3-api.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.s3_api_tg, aws_lb_listener_rule.s3_api_l]

  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.s3_api_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-s3-api.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_s3_api.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#10 create a aws cloudwatch log group for irs security  service
resource "aws_cloudwatch_log_group" "irs-security-api-logs" {
  name = "/ecs/fargate-task-${var.environment}-irs-security-api-logs"
  tags = {
    tag = local.env_tag
  }
}

#10 create an task defination for the  irs security api service
resource "aws_ecs_task_definition" "fargate-task-irs-security-api" {
  family                   = "fargate-task-${var.environment}-irs-security-api"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.irs_security_cpu_unit
  memory                   = var.irs_security_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-irs-security-api",
    "image": "${aws_ecr_repository.ecr_irs_security_api_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.irs_security_cpu_unit},
    "memory": ${var.irs_security_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.irs-security-api-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
     "environment": [
      { "name": "SERVER_PORT",                        "value": "${var.ecs_service_port}" },
      { "name": "SERVER_SSL_ENABLED",                 "value": "${var.ecs_server_ssl_enabled}" },
      { "name": "SPRING_DATASOURCE_URL",              "value": "jdbc-secretsmanager:postgresql://${aws_rds_cluster.aurora_rds_database_cluster.endpoint}:${var.aurora_db_port}/${var.aurora_db_name}" },
      { "name": "SPRING_DATASOURCE_DRIVER_CLASS_NAME","value": "${var.datasource_driver_class_name}" },
      { "name": "SPRING_DATASOURCE_USERNAME",         "value": "${local.secret_manager_database_source}" },
      { "name": "EXTERNALSERVICEAPI_SERVICE_HOST",    "value": "${local.external_service_api_call}" },
      { "name": "EXTERNALSERVICEAPI_SERVICE_PORT",    "value": "${var.ecs_service_port}" },
      { "name": "EXTERNALSERVICEAPI_SERVICE_URI",     "value": "${var.external_service_api_uri}" },
      { "name": "BUOW_API_SERVICE_HOST",              "value": "${local.buow_api_call}" },
      { "name": "BUOW_API_SERVICE_PORT",              "value": "${var.ecs_service_port}" },
      { "name": "BUOW_API_SERVICE_URI",               "value": "${var.buow_api_uri}" },
      { "name": "SECRETS_MANAGER_JWT_ID",             "value": "${local.secret_manager_jwt_id}" },
      { "name": "RETRY_MAXATTEMPTS",                  "value": "${var.irs_security_retry_maxattempts}" },
      { "name": "RETRY_TIMEINTERVAL",                 "value": "${var.irs_security_retry_timeinterval}" },
      { "name": "OKTA_ISSUER",                        "value": "${var.irs_security_okta_issuer}" }
    ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#10 create a AWS_ecs service for the app service irs security api service
resource "aws_ecs_service" "ecs_irs_security_api" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-irs-security-api" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                              # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-irs-security-api.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.irs_security_api_tg, aws_lb_listener_rule.irs_security_api_l]

  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.irs_security_api_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-irs-security-api.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_irs_security_api.arn
  }
  tags = {
    tag = local.env_tag
  }
}


#11 create a aws cloudwatch log group for the transform api service
resource "aws_cloudwatch_log_group" "transform-api-logs" {
  name = "/ecs/fargate-task-${var.environment}-transform-api-logs"
  tags = {
    tag = local.env_tag
  }
}

#11 create an task defination for the  irs transform api service
resource "aws_ecs_task_definition" "fargate-task-transform-api" {
  family                   = "fargate-task-${var.environment}-transform-api"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.transform_api_cpu_unit
  memory                   = var.transform_api_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-transform-api",
    "image": "${aws_ecr_repository.ecr_transform_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.transform_api_cpu_unit},
    "memory": ${var.transform_api_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.transform-api-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
       "environment": [
      { "name": "SERVER_PORT",                          "value": "${var.ecs_service_port}" },
      { "name": "SERVER_SSL_ENABLED",                   "value": "${var.ecs_server_ssl_enabled}" },
      { "name": "SPRING_DATASOURCE_JDBCURL",            "value": "jdbc-secretsmanager:postgresql://${aws_rds_cluster.aurora_rds_database_cluster.endpoint}:${var.aurora_db_port}/${var.aurora_db_name}" },
      { "name": "SPRING_DATASOURCE_DRIVER_CLASS_NAME",  "value": "${var.datasource_driver_class_name}" },
      { "name": "SPRING_DATASOURCE_USERNAME",           "value": "${local.secret_manager_database_source}" },
      { "name": "ORACLE_DATASOURCE_JDBCURL",            "value": "jdbc-secretsmanager:postgresql://${aws_rds_cluster.aurora_rds_database_cluster.endpoint}:${var.aurora_db_port}/${var.aurora_db_name}" },
      { "name": "ORACLE_DATASOURCE_USERNAME",           "value": "${local.secret_manager_database_source}" },
      { "name": "ORACLE_DATASOURCE_DRIVER_CLASS_NAME",  "value": "${var.datasource_driver_class_name}" },
      { "name": "ORACLE_WALLET_DIRECTORY",              "value": "${var.transform_api_oracle_wallet_directory}" },
      { "name": "QAQCAPI_SERVICE_HOST",                 "value": "${var.transform_api_qaqcapi_service_host}" },
      { "name": "QAQCAPI_SERVICE_PORT",                 "value": "${var.ecs_service_port}" },
      { "name": "QAQCAPI_SERVICE_URI",                  "value": "${var.transform_api_qaqcapi_service_uri}" },
      { "name": "EXTERNALAPI_SERVICE_HOST",             "value": "${local.external_service_api_call}" },
      { "name": "EXTERNALAPI_SERVICE_PORT",             "value": "${var.ecs_service_port}" },
      { "name": "EXTERNALAPI_SERVICE_URI",              "value": "${var.external_service_api_uri}" },
      { "name": "SECRETS_MANAGER_JWT_ID",               "value": "${local.secret_manager_jwt_id}" },
      { "name": "EDW_ENABLED",                          "value": "${var.transform_api_edw_enabled}" },
      { "name": "SECURITYAPI_SERVICE_HOST",             "value": "${local.irs_security_api_call}" },
      { "name": "SECURITYAPI_SERVICE_PORT",             "value": "${var.ecs_service_port}" },
      { "name": "SECURITYAPI_SERVICE_URI",              "value": "${var.security_api_uri}" }
    ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#11 create a AWS_ecs service for the app service transform service
resource "aws_ecs_service" "ecs_transform_api" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-transform-api" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                           # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-transform-api.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.transform_api_tg, aws_lb_listener_rule.transform_api_l]

  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.transform_api_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-transform-api.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_transform_api.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#12 create a aws cloudwatch log group for the scanondemandapi api service
resource "aws_cloudwatch_log_group" "scanondemand-api-logs" {
  name = "/ecs/fargate-task-${var.environment}-scanondemand-api-logs"
  tags = {
    tag = local.env_tag
  }
}

#12 create an task defination for the  scanondemandapi api service
resource "aws_ecs_task_definition" "fargate-task-scanondemand-api" {
  family                   = "fargate-task-${var.environment}-scanondemand-api"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.sod_cpu_unit
  memory                   = var.sod_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-scanondemand-api",
    "image": "${aws_ecr_repository.ecr_scan_on_demand_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.sod_cpu_unit},
    "memory": ${var.sod_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.scanondemand-api-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "environment": [
      { "name": "SERVER_PORT",                                   "value": "${var.ecs_service_port}" },
      { "name": "SERVER_SSL_ENABLED",                            "value": "${var.ecs_server_ssl_enabled}" },
      { "name": "SPRING_DATASOURCE_URL",                         "value": "jdbc-secretsmanager:postgresql://${aws_rds_cluster.aurora_rds_database_cluster.endpoint}:${var.aurora_db_port}/${var.aurora_db_name}" },
      { "name": "SPRING_DATASOURCE_DRIVER-CLASS-NAME",           "value": "${var.datasource_driver_class_name}" },
      { "name": "SPRING_DATASOURCE_USERNAME",                    "value": "${local.secret_manager_database_source}" },
      { "name": "BUOWAPI_SERVICE_HOST",                          "value": "${local.buow_api_call}" },
      { "name": "BUOWAPI_SERVICE_PORT",                          "value": "${var.ecs_service_port}" },
      { "name": "BUOWAPI_SERVICE_URI",                           "value": "${var.buow_api_uri}" },
      { "name": "S3API_SERVICE_HOST",                            "value": "${local.s3_api_call}" },
      { "name": "S3API_SERVICE_PORT",                            "value": "${var.ecs_service_port}" },
      { "name": "S3API_SERVICE_URI",                             "value": "${var.s3_api_uri}" },
      { "name": "SUBMISSIONAPI_SERVICE_HOST",                    "value": "${local.document_and_metadata_submission_api_call}" },
      { "name": "SUBMISSIONAPI_SERVICE_PORT",                    "value": "${var.ecs_service_port}" },
      { "name": "SUBMISSIONAPI_SERVICE_URI",                     "value": "${var.document_metadata_submission_api_uri}" },
      { "name": "S3_BUCKET_NAME",                                "value": "${local.s3_bucket_name}" },
      { "name": "S3_FOLDER_NAME",                                "value": "${var.sod_s3_folder_name}" },
      { "name": "TEGE_PACKAGER_S3_BUCKET_NAME",                  "value": "${local.s3_tege_files_bucket_name}" },
      { "name": "LOCAL_UPLOAD_PATH",                             "value": "${var.sod_local_upload_path}" },
      { "name": "SECRETS-MANAGER_JWT_ID",                        "value": "${local.secret_manager_jwt_id}" },
      { "name": "SPRING_SERVLET_MULTIPART_MAX-FILE-SIZE",        "value": "${var.sod_spring_servlet_multipart_max_file_size}" },
      { "name": "SPRING_SERVLET_MULTIPART_MAX-REQUEST-SIZE",     "value": "${var.sod_spring_servlet_multipart_max_request_size}" },
      { "name": "SPRING_AUTOCONFIGURE_EXCLUDE",                  "value": "${var.spring_autoconfigure_exclude}" },
      { "name": "RETRY_MAXATTEMPTS",                             "value": "${var.sod_retry_maxattempts}" },
      { "name": "RETRY_TIMEINTERVAL",                            "value": "${var.sod_retry_timeinterval}" },
      { "name": "SECURITYAPI_SERVICE_HOST",                      "value": "${local.irs_security_api_call}" },
      { "name": "SECURITYAPI_SERVICE_PORT",                      "value": "${var.ecs_service_port}" },
      { "name": "SECURITYAPI_SERVICE_URI",                       "value": "${var.security_api_uri}" }
    ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#12 create a AWS_ecs service for the app service scanondemandapi api service
resource "aws_ecs_service" "ecs-scanondemand-api" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-scanondemand-api" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                              # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-scanondemand-api.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.scan_on_demand_api_tg, aws_lb_listener_rule.scan_on_demand_api_l]

  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.scan_on_demand_api_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-scanondemand-api.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_scan_on_demand_api.arn
  }
  tags = {
    tag = local.env_tag
  }
}

////////////////////////////////////////////////////////////////////////////////////////////////

#13 create a aws cloudwatch log group for the ailet gateway service
resource "aws_cloudwatch_log_group" "ailet-gateway-logs" {
  name = "/ecs/fargate-task-${var.environment}-ailet-gateway-logs"
  tags = {
    tag = local.env_tag
  }
}

#13 create an task defination for the   ailet gateway service
resource "aws_ecs_task_definition" "fargate-task-ailet-gateway" {
  family                   = "fargate-task-${var.environment}-ailet-gateway"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.ailet_gateway_cpu_unit
  memory                   = var.ailet_gateway_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-ailet-gateway",
    "image": "${aws_ecr_repository.ecr_ailet_gateway_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.ailet_gateway_cpu_unit},
    "memory": ${var.ailet_gateway_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.ailet-gateway-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      }
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#13 create a AWS_ecs service for the app service ailet gateway service
resource "aws_ecs_service" "ecs_ailet_gateway" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-ailet-gateway" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                           # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-ailet-gateway.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.ailet_gateway_tg, aws_lb_listener_rule.ailet_gateway_l]

  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.ailet_gateway_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-ailet-gateway.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_ailet_gateway.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#14 create a aws cloudwatch log group for the gri extraction service
resource "aws_cloudwatch_log_group" "gri-extraction-logs" {
  name = "/ecs/fargate-task-${var.environment}-gri-extraction-logs"
  tags = {
    tag = local.env_tag

  }
}

#14 create an task defination for the  gri extraction service
resource "aws_ecs_task_definition" "fargate-task-gri-extraction" {
  family                   = "fargate-task-${var.environment}-gri-extraction"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.gri_extraction_cpu_unit
  memory                   = var.gri_extraction_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-gri-extraction",
    "image": "${aws_ecr_repository.ecr_gri_extraction_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.gri_extraction_cpu_unit},
    "memory": ${var.gri_extraction_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.gri-extraction-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      }
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#14 create a AWS_ecs service for the app service gri extraction service
resource "aws_ecs_service" "ecs-gri-extraction" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-gri-extraction" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                            # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-gri-extraction.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.gri_extraction_tg, aws_lb_listener_rule.gri_extraction_l]

  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.gri_extraction_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-gri-extraction.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_gri_extraction.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#15 create a aws cloudwatch log group for the naix service
resource "aws_cloudwatch_log_group" "upload-daemon-logs" {
  name = "/ecs/fargate-task-${var.environment}-upload-daemon-logs"
  tags = {
    tag = local.env_tag
  }
}

#15 create an task defination for the naix service
resource "aws_ecs_task_definition" "fargate-task-upload-daemon" {
  family                   = "fargate-task-${var.environment}-upload-daemon"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.upload_daemon_cpu_unit
  memory                   = var.upload_daemon_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-upload-daemon",
    "image": "${aws_ecr_repository.ecr_upload_daemon_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.upload_daemon_cpu_unit},
    "memory": ${var.upload_daemon_memory_unit},
    "environment": [
    { "name": "DAEMON",                         "value": "${var.upload_daemon_daemon}" },
    { "name": "UPLOAD_TEMP_FOLDER",             "value": "${var.upload_temp_folder_path}" },
    { "name": "RUNOCR_URL",                     "value": "http://${local.run_ocr_api_call}:${var.ecs_service_port}${var.run_ocr_api_uri}process" },
    { "name": "TESSERACT",                      "value": "${var.naix_services_tesseract_path}" },
    { "name": "POPPLER",                        "value": "${var.naix_services_poppler_path}" },
    { "name": "PG_DATABASE",                    "value": "${var.aurora_db_name}" },
    { "name": "CONNECTION_TYPE",                "value": "${var.environment}" },
    { "name": "WORKERS",                        "value": "${var.upload_daemon_workers}" },
    { "name": "THREAD",                         "value": "${var.upload_daemon_thread}" },
    { "name": "REGION",                         "value": "${var.aws_region}" },
    { "name": "BUCKET_NAME",                    "value": "${local.s3_bucket_name}" },
    { "name": "LOG_GROUP_NAME",                 "value": "${local.upload_daemon_log_group_name}" },
    { "name": "LOG_STREAM_NAME",                "value": "${local.upload_daemon_log_stream_name}" },
    { "name": "CONTEXT_ID",                     "value": "${var.app_context_id}" },
    { "name": "SECRET_NAME",                    "value": "${local.secret_manager_database_source}" },
    { "name": "JOBNAME",                        "value": "${local.naix_daemon_batch_jobname}" },
    { "name": "JOBQUEUE",                       "value": "${local.naix_daemon_batch_jobqueue}" },
    { "name": "JOBDEFINITION",                  "value": "${local.naix_daemon_batch_jobdefinition}" },
    { "name": "TEXTRACT_REGION_NAME",           "value": "${var.textract_region_name}" },
    { "name": "TEXTRACT_AWS_ACCESS_KEY_ID",     "value": "${var.upload_daemon_textract_aws_access_key_id}" },
    { "name": "TEXTRACT_AWS_SECRET_ACCESS_KEY", "value": "${var.upload_daemon_textract_aws_secret_access_key}" },
    { "name" : "BACKEND_DOMAIN",                "value" : "http://${local.scan_on_demand_api_call}:${var.ecs_service_port}" },
    { "name" : "990_DRIVER",                    "value" : "http://${local.object_driver_api_call}:${var.ecs_service_port}/driver" },
    { "name" : "OUTPUT_LOG_FOLDER",             "value" : "${var.output_log_folder}" },
    { "name" : "SUBMIT_TEMP_FOLDER",            "value" : "${var.submit_temp_folder_path}" },
    { "name" : "SERVICE_NAME",                  "value" : "${var.environment}-ailet-gateway" },
    { "name" : "NAME_SPACE",                    "value" : "${var.private_dns_namespace}" }
  ],
    "essential": true,
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "${aws_cloudwatch_log_group.upload-daemon-logs.name}",
        "awslogs-region": "${var.aws_region}",
        "awslogs-stream-prefix": "ecs"
      }
    }
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#15 create a AWS_ecs service for the upload daemon
resource "aws_ecs_service" "ecs_upload_daemon" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-upload-daemon" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                           # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-upload-daemon.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1

  lifecycle {
    ignore_changes = [desired_count]
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_upload_daemon.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#20 create a aws cloudwatch log group for the routing service
resource "aws_cloudwatch_log_group" "routing-daemon-logs" {
  name = "/ecs/fargate-task-${var.environment}-routing-daemon-logs"
  tags = {
    tag = local.env_tag
  }
}

#20 create an task defination for the routing service
resource "aws_ecs_task_definition" "fargate-task-routing-daemon" {
  family                   = "fargate-task-${var.environment}-routing-daemon"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.routing_daemon_cpu_unit
  memory                   = var.routing_daemon_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-routing-daemon",
    "image": "${aws_ecr_repository.ecr_routing_daemon_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.routing_daemon_cpu_unit},
    "memory": ${var.routing_daemon_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.routing-daemon-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "environment": [
      { "name": "PG_DATABASE",       "value": "${var.aurora_db_name}" },
      { "name": "CONNECTION_TYPE",   "value": "${var.environment}" },
      { "name": "REGION",            "value": "${var.aws_region}" },
      { "name": "SECRET_NAME",       "value": "${local.secret_manager_database_source}" },
      { "name": "LOG_GROUP_NAME",    "value": "${local.routing_daemon_log_group_name}" },
      { "name": "LOG_STREAM_NAME",   "value": "${local.routing_daemon_log_stream_name}" }
    ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#16 create a AWS_ecs service for the app service routing service
resource "aws_ecs_service" "ecs_routing_daemon" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-routing-daemon" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                            # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-routing-daemon.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1

  lifecycle {
    ignore_changes = [desired_count]
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_routing_daemon.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#21 create a aws cloudwatch log group for the inbasket service
resource "aws_cloudwatch_log_group" "inbasket-daemon-logs" {
  name = "/ecs/fargate-task-${var.environment}-inbasket-daemon-logs"
  tags = {
    tag = local.env_tag
  }
}

#21 create an task defination for the inbasket service
resource "aws_ecs_task_definition" "fargate-task-inbasket-daemon" {
  family                   = "fargate-task-${var.environment}-inbasket-daemon"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.inbasket_daemon_cpu_unit
  memory                   = var.inbasket_daemon_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-inbasket-daemon",
    "image": "${aws_ecr_repository.ecr_inbasket_daemon_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.inbasket_daemon_cpu_unit},
    "memory": ${var.inbasket_daemon_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.inbasket-daemon-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "environment": [
      { "name": "PG_DATABASE",       "value": "${var.aurora_db_name}" },
      { "name": "CONNECTION_TYPE",   "value": "${var.environment}" },
      { "name": "REGION",            "value": "${var.aws_region}" },
      { "name": "SECRET_NAME",       "value": "${local.secret_manager_database_source}" },
      { "name": "LOG_GROUP_NAME",    "value": "${local.inbasket_daemon_log_group_name}" },
      { "name": "LOG_STREAM_NAME",   "value": "${local.inbasket_daemon_log_stream_name}" }
    ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#17 create a AWS_ecs service for the app service inbasket service
resource "aws_ecs_service" "ecs-inbasket-daemon" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-inbasket-daemon" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                             # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-inbasket-daemon.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1

  lifecycle {
    ignore_changes = [desired_count]
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_inbasket_daemon.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#18 create a aws cloudwatch log group for the submit daemon service
resource "aws_cloudwatch_log_group" "submit-daemon-logs" {
  name = "/ecs/fargate-task-${var.environment}-submit-daemon-logs"
  tags = {
    tag = local.env_tag
  }
}

resource "aws_ecs_task_definition" "fargate-task-submit-daemon" {
  family                   = "fargate-task-${var.environment}-submit-daemon"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.submit_daemon_cpu_unit
  memory                   = var.submit_daemon_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn

  container_definitions = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-submit-daemon",
    "image": "${aws_ecr_repository.ecr_submit_daemon_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.submit_daemon_cpu_unit},
    "memory": ${var.submit_daemon_memory_unit},
    "environment": [
      { "name": "DAEMON",              "value": "${var.submit_daemon_daemon}" },
      { "name": "SUBMIT_TEMP_FOLDER",  "value": "${var.submit_temp_folder_path}" },
      { "name": "TESSERACT",           "value": "${var.naix_services_tesseract_path}" },
      { "name": "PG_DATABASE",         "value": "${var.aurora_db_name}" },
      { "name": "CONNECTION_TYPE",     "value": "${var.environment}" },
      { "name": "REGION",              "value": "${var.aws_region}" },
      { "name": "BUCKET_NAME",         "value": "${local.s3_bucket_name}" },
      { "name": "LOG_GROUP_NAME",      "value": "${local.submit_daemon_log_group_name}" },
      { "name": "LOG_STREAM_NAME",     "value": "${local.submit_daemon_log_stream_name}" },
      { "name": "CONTEXT_ID",          "value": "${var.app_context_id}" },
      { "name": "SECRET_NAME",         "value": "${local.secret_manager_database_source}" },
      { "name": "BACKEND_DOMAIN",      "value": "http://${local.scan_on_demand_api_call}:${var.ecs_service_port}" },
      { "name": "990_DRIVER",          "value": "http://${local.object_driver_api_call}:${var.ecs_service_port}${var.object_driver_api_uri}processpayload" },
      { "name": "HOST",                "value": "http://${local.irs_security_api_call}:${var.ecs_service_port}${var.security_api_uri}security/login" },
      { "name": "LOGIN_CREDENTIALS",   "value": "${var.login_credentials}" },
      { "name": "XML_SVC_URL",         "value": "http://${local.xml_service_api_call}:${var.ecs_service_port}${var.xml_service_api_uri}processpayload" },
      { "name": "JOBNAME",             "value": "${local.submit_daemon_batch_jobname}" },
      { "name": "JOBQUEUE",            "value": "${local.submit_daemon_batch_jobqueue}" },
      { "name": "JOBDEFINITION",       "value": "${local.submit_daemon_batch_jobdefinition}" },
      { "name": "DRIVER_SERVICE_NAME", "value": "${var.environment}-object-driver" },
      { "name": "NAME_SPACE",          "value": "${var.private_dns_namespace}" },
      { "name": "OUTPUT_LOG_FOLDER",   "value": "${var.output_log_folder}" },
      { "name": "POPPLER",             "value": "${var.naix_services_poppler_path}" },
      { "name": "THREAD",              "value": "${var.submit_daemon_thread}" },
      { "name": "UPLOAD_TEMP_FOLDER",  "value": "${var.upload_temp_folder_path}" },
      { "name": "WORKERS",             "value": "${var.submit_daemon_workers}" }
    ],
    "essential": true,
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "${aws_cloudwatch_log_group.submit-daemon-logs.name}",
        "awslogs-region": "${var.aws_region}",
        "awslogs-stream-prefix": "ecs"
      }
    }
  }
]
TASK_DEFINITION

  tags = {
    tag = local.env_tag
  }
}


#18 create a AWS_ecs service for the app service submit service
resource "aws_ecs_service" "ecs_submit_daemon" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-submit-daemon" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                           # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-submit-daemon.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1

  lifecycle {
    ignore_changes = [desired_count]
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_submit_daemon.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#19 create the cloudwatch logs for the sense daemon
resource "aws_cloudwatch_log_group" "sense-daemon-logs" {
  name = "/ecs/fargate-task-${var.environment}-sense-daemon-logs"
  tags = {
    tag = local.env_tag
  }
}

#19 create the ECS faragte Task definition for the sense daemon
resource "aws_ecs_task_definition" "fargate-task-sense-daemon" {
  family                   = "fargate-task-${var.environment}-sense-daemon"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.sense_daemon_cpu_unit
  memory                   = var.sense_daemon_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-sense-daemon",
    "image": "${aws_ecr_repository.ecr_sense_daemon_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.sense_daemon_cpu_unit},
    "memory": ${var.sense_daemon_memory_unit},
    "environment": [
      { "name": "REGION_NAME",       "value": "${var.aws_region}" },
      { "name": "LOG_GROUP_NAME",    "value": "${local.sense_daemon_log_group_name}" },
      { "name": "LOG_STREAM_NAME",   "value": "${local.sense_daemon_log_stream_name}" },
      { "name": "SECRET_NAME",       "value": "${local.secret_manager_database_source}" },
      { "name": "PG_DATABASE",       "value": "${var.aurora_db_name}" },
      { "name": "CONNECTION_TYPE",   "value": "${var.environment}" }
    ],
    "essential": true,
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "${aws_cloudwatch_log_group.sense-daemon-logs.name}",
        "awslogs-region": "${var.aws_region}",
        "awslogs-stream-prefix": "ecs"
      }
    }
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#20 Created the ECS servicr for the sense dameon
resource "aws_ecs_service" "ecs_sense_daemon" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-sense-daemon" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                          # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-sense-daemon.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1

  lifecycle {
    ignore_changes = [desired_count]
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_sense_daemon.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#20 Created the Cloudwatch logs for the dashboard daemon
resource "aws_cloudwatch_log_group" "dashboard-daemon-logs" {
  name = "/ecs/fargate-task-${var.environment}-dashboard-daemon-logs"
  tags = {
    tag = local.env_tag
  }
}

#20 created ECS task definiton for the dashboard daemon 
resource "aws_ecs_task_definition" "fargate-task-dashboard-daemon" {
  family                   = "fargate-task-${var.environment}-dashboard-daemon"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.dashboard_daemon_cpu_unit
  memory                   = var.dashboard_daemon_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-dashboard-daemon",
    "image": "${aws_ecr_repository.ecr_dashboard_daemon_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.dashboard_daemon_cpu_unit},
    "memory": ${var.dashboard_daemon_memory_unit},
    "environment": [
      { "name": "PG_DATABASE",     "value": "${var.aurora_db_name}" },
      { "name": "CONNECTION_TYPE", "value": "${var.environment}" },
      { "name": "REGION",          "value": "${var.aws_region}" },
      { "name": "SECRET_NAME",     "value": "${local.secret_manager_database_source}" },
      { "name": "LOG_GROUP_NAME",  "value": "${local.dashboard_daemon_log_group_name}" },
      { "name": "LOG_STREAM_NAME", "value": "${local.dashboard_daemon_log_stream_name}" },
      { "name": "CONTEXTID",       "value": "${var.app_context_id}" }
    ],
    "essential": true,
    "logConfiguration": { 
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.dashboard-daemon-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      }
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#20 Created the ECS servoce fpr the dashboard daemon
resource "aws_ecs_service" "ecs_dashboard_daemon" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-dashboard-daemon" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                              # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-dashboard-daemon.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1

  lifecycle {
    ignore_changes = [desired_count]
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_dashboard_daemon.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#21 Created clouddwatch logs for the Batch-Driver
resource "aws_cloudwatch_log_group" "batch-driver-logs" {
  name = "/ecs/fargate-task-${var.environment}-batch-driver-logs"
  tags = {
    tag = local.env_tag
  }
}

#21 create an task defination for the Batch-Driver service
resource "aws_ecs_task_definition" "fargate-task-batch-driver" {
  family                   = "fargate-task-${var.environment}-batch-driver"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.batch_driver_cpu_unit
  memory                   = var.batch_driver_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
  "name": "fargate-task-${var.environment}-batch-driver",
  "image": "${aws_ecr_repository.ecr_batch_driver_repository.repository_url}",
  "portMappings": [
    {
      "containerPort": 8080,
      "hostPort": 8080
    }
  ],
  "cpu": ${var.batch_driver_cpu_unit},
  "memory": ${var.batch_driver_memory_unit},
  "essential": true,
  "logConfiguration": {
    "logDriver": "awslogs",
    "options": {
      "awslogs-group": "${aws_cloudwatch_log_group.batch-driver-logs.name}",
      "awslogs-region": "${var.aws_region}",
      "awslogs-stream-prefix": "ecs"
    }
  },
  "environment": [
      { "name": "PG_DATABASE",            "value": "${var.aurora_db_name}" },
      { "name": "SECRET_NAME",            "value": "${local.secret_manager_database_source}" },
      { "name": "OUTPUT_DRIVER",          "value": "http://${local.output_driver_api_call}:${var.ecs_service_port}${var.output_driver_api_uri}processpayload" },
      { "name": "ELASTIC_SEARCH_URL",     "value": "http://${local.document_and_metadata_submission_api_call}:${var.ecs_service_port}${var.document_metadata_submission_api_uri}submission/search?page=0&limit=25" },
      { "name": "ELASTIC_UPDATE_CALL",    "value": "http://${local.document_and_metadata_submission_api_call}:${var.ecs_service_port}${var.document_metadata_submission_api_uri}submission/v2?docId={}&isCustomerUpload=true" },
      { "name": "POST_ELASTIC_CALL",      "value": "http://${local.document_and_metadata_submission_api_call}:${var.ecs_service_port}${var.document_metadata_submission_api_uri}submission/v2?mimeType=binary/octet-stream&fileName={}&humanReadableFileName={}&isCustomerUpload=false" },
      { "name": "REGION",                 "value": "${var.aws_region}" },
      { "name": "BUCKET_NAME",            "value": "${local.s3_bucket_name}" },
      { "name": "LOG_GROUP_NAME",         "value": "${local.batch_driver_log_group_name}" },
      { "name": "LOG_STREAM_NAME",        "value": "${local.batch_driver_log_stream_name}" },
      { "name": "CONNECTION_TYPE",        "value": "${var.environment}" },
      { "name": "TOKEN_VALIDATE_API",     "value": "http://${local.irs_security_api_call}:${var.ecs_service_port}${var.security_api_uri}security/userinfo" },
      { "name": "REDACTED_BUCKET_NAME",   "value": "${local.s3_redacted_files_bucket_name}" },
      { "name" : "SUBMIT_TEMP_FOLDER",    "value": "${var.submit_temp_folder_path}" },
      { "name" : "XML_SVC_URL",           "value": "http://${local.xml_service_api_call}:${var.ecs_service_port}${var.xml_service_api_uri}processpayload" }
    ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#21 create a AWS_ecs service for the Batch-Driver
resource "aws_ecs_service" "ecs-batch-driver" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-batch-driver" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                          # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-batch-driver.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.batch_driver_tg, aws_lb_listener_rule.batch_driver_l]

  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.batch_driver_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-batch-driver.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_batch_driver.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#22 created the cloudwatcvh logs for tege packager logs
resource "aws_cloudwatch_log_group" "tege-packager-logs" {
  name = "/ecs/fargate-task-${var.environment}-tege-packager-logs"
  tags = {
    tag = local.env_tag
  }
}

resource "aws_ecs_task_definition" "fargate-task-tege-packager" {
  family                   = "fargate-task-${var.environment}-tege-packager"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.tege_packager_cpu_unit
  memory                   = var.tege_packager_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn

  container_definitions = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-tege-packager",
    "image": "${aws_ecr_repository.ecr_tege_packager_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.tege_packager_cpu_unit},
    "memory": ${var.tege_packager_memory_unit},
    "essential": true,
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "${aws_cloudwatch_log_group.tege-packager-logs.name}",
        "awslogs-region": "${var.aws_region}",
        "awslogs-stream-prefix": "ecs"
      }
    },
    "environment": [
      { "name": "TEMP_FOLDER",             "value": "${var.tege_packager_temp_folder}" },
      { "name": "LOGIN_USER",              "value": "${var.tege_packager_login_user}" },
      { "name": "RUN_FREQUENCY_CONSTANT",  "value": "${var.tege_packager_run_frequency_constant}" },
      { "name": "SEARCH_FOLDER",           "value": "s3://${local.s3_tege_files_bucket_name}" },
      { "name": "HISTORICAL_FOLDER",       "value": "s3://${local.s3_tege_historical_files_bucket_name}" },
      { "name": "API_ENDPOINT",            "value": "http://${local.scan_on_demand_api_call}:${var.ecs_service_port}${var.scan_on_demand_api_uri}file/upload" },
      { "name": "LOGIN_CREDENTIALS",       "value": "${var.login_credentials}" },
      { "name": "HOST",                    "value": "http://${local.irs_security_api_call}:${var.ecs_service_port}${var.security_api_uri}security/login" },
      { "name": "REGION",                  "value": "${var.aws_region}" },
      { "name": "BUCKET_NAME",             "value": "${local.s3_tege_files_bucket_name}" },
      { "name": "HISTORICAL_BUCKET_NAME",  "value": "${local.s3_tege_historical_files_bucket_name}" },
      { "name": "LOG_GROUP_NAME",          "value": "${local.tege_packager_log_group_name}" },
      { "name": "LOG_STREAM_NAME",         "value": "${local.tege_packager_log_stream_name}" },
      { "name": "SECRET_NAME",             "value": "${local.secret_manager_database_source}" },
      { "name": "PG_DATABASE",             "value": "${var.aurora_db_name}" },
      { "name": "CONNECTION_TYPE",         "value": "${var.environment}" }
    ]
  }
]
TASK_DEFINITION

  tags = {
    tag = local.env_tag
  }
}

#22 cretaed the ecs service for the Tege Packager
resource "aws_ecs_service" "ecs_tege_packager" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-tege-packager" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                           # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-tege-packager.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1

  lifecycle {
    ignore_changes = [desired_count]
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_tege_packager.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#23 creted the cloudwatch logs for the NAix-object classification logs
resource "aws_cloudwatch_log_group" "naix-object-classification-logs" {
  name = "/ecs/fargate-task-${var.environment}-naix-object-classification-logs"
  tags = {
    tag = local.env_tag
  }
}

#23 create the task definition fo the naix object classification
resource "aws_ecs_task_definition" "fargate-task-naix-object-classification" {
  family                   = "fargate-task-${var.environment}-naix-object-classification"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.obj_classification_cpu_unit
  memory                   = var.obj_classification_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-naix-object-classification",
    "image": "${aws_ecr_repository.ecr_naix_object_classification_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.obj_classification_cpu_unit},
    "memory": ${var.obj_classification_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.naix-object-classification-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
    },
    "environment": [
      { "name": "TEMP_FOLDER",         "value": "${var.obj_classification_temp_folder}" },
      { "name": "PG_DATABASE",         "value": "${var.aurora_db_name}" },
      { "name": "SECRET_NAME",         "value": "${local.secret_manager_database_source}" },
      { "name": "CONNECTION_TYPE",     "value": "${var.environment}" },
      { "name": "REGION",              "value": "${var.aws_region}" },
      { "name": "BUCKET_NAME",         "value": "${local.s3_bucket_name}" },
      { "name": "LOG_GROUP_NAME",      "value": "${local.obj_classification_log_group_name}" },
      { "name": "LOG_STREAM_NAME",     "value": "${local.obj_classification_log_stream_name}" },
      { "name": "TOKEN_VALIDATE_API",  "value": "http://${local.irs_security_api_call}:${var.ecs_service_port}${var.security_api_uri}security/userinfo" },
      { "name": "RUNOCR_URL",          "value": "http://${local.run_ocr_api_call}:${var.ecs_service_port}${var.run_ocr_api_uri}process" }
    ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#23 create the ecs service fo the naix object classification
resource "aws_ecs_service" "ecs_naix_object_classification" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-naix-object-classification" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                                        # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-naix-object-classification.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.naix_object_classification_tg, aws_lb_listener_rule.naix_object_classification_l]
  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.naix_object_classification_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-naix-object-classification.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_naix_object_classification.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#24 created the cloudwatch logs for the object-driver service
resource "aws_cloudwatch_log_group" "object-driver-logs" {
  name = "/ecs/fargate-task-${var.environment}-object-driver-logs"
  tags = {
    tag = local.env_tag
  }
}

#24 create the task definition for the object driver service
resource "aws_ecs_task_definition" "fargate-task-object-driver" {
  family                   = "fargate-task-${var.environment}-object-driver"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.object_driver_cpu_unit
  memory                   = var.object_driver_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-object-driver",
    "image": "${aws_ecr_repository.ecr_object_driver_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.object_driver_cpu_unit},
    "memory": ${var.object_driver_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.object-driver-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "environment": [
      { "name": "DRIVER_NAME",             "value": "${var.object_driver_driver_name}" },
      { "name": "TOKEN_VALIDATE_API",      "value": "http://${local.irs_security_api_call}:${var.ecs_service_port}${var.security_api_uri}security/userinfo" },
      { "name": "DRIVER_OBJECTS",          "value": "${var.object_driver_driver_objects}" },
      { "name": "DRIVER_HOST",             "value": "${var.object_driver_driver_host}" },
      { "name": "DRIVER_PORT",             "value": "${var.ecs_service_port}" },
      { "name": "DRIVER_FULL_FUZZY_OBJECTS", "value": "${var.object_driver_driver_full_fuzzy_objects}" },
      { "name": "CLASSIFY_ONLY",           "value": "${var.object_driver_classify_only}" },
      { "name": "DRIMS_RULE_TRIGGER_ROUTE","value": "${var.object_driver_drims_rule_trigger_route}" },
      { "name": "DRIMS_AILET_GATEWAY",     "value": "${var.object_driver_drims_ailet_gateway}" },
      { "name": "TESSERACT_CMD_WINDOWS",   "value": "${var.object_driver_tesseract_cmd_windows}" },
      { "name": "TESSERACT_CMD_MACOS",     "value": "${var.object_driver_tesseract_cmd_macos}" },
      { "name": "TESSERACT_CMD_LINUX",     "value": "${var.naix_services_tesseract_path}" },
      { "name": "SHAREPOINT_URL",          "value": "${var.object_driver_sharepoint_url}" },
      { "name": "KEYWORD_CONFIG_URL",      "value": "${var.object_driver_keyword_config_url}" },
      { "name": "SHAREPOINT_UN",           "value": "${var.object_driver_sharepoint_un}" },
      { "name": "SHAREPOINT_PW",           "value": "${var.object_driver_sharepoint_pw}" },
      { "name": "REGION",                  "value": "${var.aws_region}" },
      { "name": "BUCKET_NAME",             "value": "${local.s3_bucket_name}" },
      { "name": "LOG_GROUP_NAME",          "value": "${local.object_driver_log_group_name}" },
      { "name": "LOG_STREAM_NAME",         "value": "${local.object_driver_log_stream_name}" },
      { "name": "DRIMS_URL_BASE",          "value": "http://${local.buow_api_call}:${var.ecs_service_port}${var.buow_api_uri}" },
      { "name": "CONTEXT_ID",              "value": "${var.app_context_id}" },
      { "name": "CONNECTION_TYPE",         "value": "${var.environment}" },
      { "name": "DRIMS_URL",               "value": "${var.object_driver_drims_url}" }
    ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#24 create the ecs service for the object driver service
resource "aws_ecs_service" "ecs_object_driver" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-object-driver" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                           # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-object-driver.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.object_driver_tg, aws_lb_listener_rule.object_driver_l]

  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.object_driver_tg.arn
    container_name   = aws_ecs_task_definition.fargate-task-object-driver.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_object_driver.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#25 create the cloudwatch for the output driver service
resource "aws_cloudwatch_log_group" "output-driver-logs" {
  name = "/ecs/fargate-task-${var.environment}-output-driver-logs"
  tags = {
    tag = local.env_tag
  }
}

#25 create the task definition for the output driver service
resource "aws_ecs_task_definition" "fargate-task-output-driver" {
  family                   = "fargate-task-${var.environment}-output-driver"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.output_driver_cpu_unit
  memory                   = var.output_driver_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-output-driver",
    "image": "${aws_ecr_repository.ecr_output_driver_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.output_driver_cpu_unit},
    "memory": ${var.output_driver_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.output-driver-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "environment": [
        { "name": "DRIVER_NAME",         "value": "${var.output_driver_driver_name}" },
        { "name": "TOKEN_VALIDATE_API",  "value": "http://${local.irs_security_api_call}:${var.ecs_service_port}${var.security_api_uri}security/userinfo" },
        { "name": "DRIVER_OBJECTS",      "value": "${var.output_driver_driver_objects}" },
        { "name": "DRIVER_HOST",         "value": "${var.output_driver_driver_host}" },
        { "name": "REGION",              "value": "${var.aws_region}" },
        { "name": "LOG_GROUP_NAME",      "value": "${local.output_driver_log_group_name}" },
        { "name": "LOG_STREAM_NAME",     "value": "${local.output_driver_log_stream_name}" },
        { "name": "CONNECTION_TYPE",     "value": "${var.environment}" },
        { "name": "DRIVER_PORT",         "value": "${var.ecs_service_port}" },
        { "name": "XML_SVC_URL",         "value": "http://${local.xml_service_api_call}:${var.ecs_service_port}${var.xml_service_api_uri}processpayload" },
        { "name": "BUCKET_NAME",         "value": "${local.s3_bucket_name}" }
      ]
    }
  ]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#25 create the ecs service for the output driver service
resource "aws_ecs_service" "ecs_output_driver" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-output-driver" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                           # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-output-driver.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.output_driver_tg, aws_lb_listener_rule.output_driver_l]

  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.output_driver_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-output-driver.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_output_driver.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#26 create the cloudwatch logs for the runocr service
resource "aws_cloudwatch_log_group" "run-ocr-logs" {
  name = "/ecs/fargate-task-${var.environment}-run-ocr-logs"
  tags = {
    tag = local.env_tag
  }
}

#26 create the task definition for the runocr service
resource "aws_ecs_task_definition" "fargate-task-run-ocr" {
  family                   = "fargate-task-${var.environment}-run-ocr"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.runocr_cpu_unit
  memory                   = var.runocr_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-run-ocr",
    "image": "${aws_ecr_repository.ecr_runocr_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.runocr_cpu_unit},
    "memory": ${var.runocr_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.run-ocr-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "environment": [
      { "name": "TESSERACT_CMD_WINDOWS",         "value": "${var.runocr_tesseract_cmd_windows}" },
      { "name": "TESSERACT_CMD_MACOS",           "value": "${var.runocr_tesseract_cmd_macos}" },
      { "name": "TESSERACT_CMD_LINUX",           "value": "${var.naix_services_tesseract_path}" },
      { "name": "TEXTRACT_AWS_SECRET_ACCESS_KEY","value": "${var.runocr_textract_aws_secret_access_key}" },
      { "name": "TEXTRACT_REGION_NAME",          "value": "${var.textract_region_name}" },
      { "name": "TEXTRACT_AWS_ACCESS_KEY_ID",    "value": "${var.runocr_textract_aws_access_key_id}" },
      { "name": "DRIVER_NAME",                   "value": "${var.runocr_driver_name}" },
      { "name": "DRIVER_OBJECTS",                "value": "${var.runocr_driver_objects}" },
      { "name": "DRIVER_FULL_FUZZY_OBJECTS",     "value": "${var.runocr_driver_full_fuzzy_objects}" },
      { "name": "CLASSIFY_ONLY",                 "value": "${var.runocr_classify_only}" },
      { "name": "DRIMS_URL",                     "value": "${var.runocr_drims_url}" },
      { "name": "DRIMS_RULE_TRIGGER_ROUTE",      "value": "${var.runocr_drims_rule_trigger_route}" },
      { "name": "DRIVER_HOST",                   "value": "${var.runocr_driver_host}" },
      { "name": "DRIVER_PORT",                   "value": "${var.ecs_service_port}" },
      { "name": "DRIMS_AILET_GATEWAY",           "value": "${var.runocr_drims_aillet_gateway}" },
      { "name": "SHAREPOINT_URL",                "value": "${var.runocr_sharepoint_url}" },
      { "name": "KEYWORD_CONFIG_URL",            "value": "${var.runocr_keyword_config_url}" },
      { "name": "SHAREPOINT_UN",                 "value": "${var.runocr_sharepoint_un}" },
      { "name": "SHAREPOINT_PW",                 "value": "${var.runocr_sharepoint_pw}" },
      { "name": "BUCKET_NAME",                   "value": "${local.s3_bucket_name}" },
      { "name": "REGION",                        "value": "${var.aws_region}" },
      { "name": "LOG_GROUP_NAME",                "value": "${local.runocr_log_group_name}" },
      { "name": "LOG_STREAM_NAME",               "value": "${local.runocr_log_stream_name}" },
      { "name": "CONNECTION_TYPE",               "value": "${var.environment}" },
      { "name": "FUNCTION_NAME",                 "value": "${local.runocr_tesseract_lambda_function}" }
    ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

resource "aws_ecs_service" "ecs_runocr_service" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-run-ocr" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                     # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-run-ocr.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.runocr_tg, aws_lb_listener_rule.run_ocr_l]

  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.runocr_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-run-ocr.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_run_ocr.arn
  }
  tags = {
    tag = local.env_tag
  }
}

#28 created the cloudwatch logs for the xml service
resource "aws_cloudwatch_log_group" "xml-service-logs" {
  name = "/ecs/fargate-task-${var.environment}-xml-service-logs"
  tags = {
    tag = local.env_tag
  }
}

#28 created the task definiton for the xml service
resource "aws_ecs_task_definition" "fargate-task-xml-service" {
  family                   = "fargate-task-${var.environment}-xml-service"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.xml_cpu_unit
  memory                   = var.xml_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-xml-service",
    "image": "${aws_ecr_repository.ecr_xml_service_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.xml_cpu_unit},
    "memory": ${var.xml_memory_unit} ,
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.xml-service-logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
    "environment": [
      { "name": "REGION",                "value": "${var.aws_region}" },
      { "name": "LOG_GROUP_NAME",        "value": "${local.xml_log_group_name}" },
      { "name": "LOG_STREAM_NAME",       "value": "${local.xml_log_stream_name}" },
      { "name": "CONNECTION_TYPE",       "value": "${var.environment}" },
      { "name": "BUCKET_NAME",           "value": "${local.s3_bucket_name}" },
      { "name": "TOKEN_VALIDATE_API",    "value": "http://${local.irs_security_api_call}:${var.ecs_service_port}${var.security_api_uri}security/userinfo" },
      { "name": "XSL_FOLDER",            "value": "${var.xml_xsl_folder}" },
      { "name": "XSL_LIST",              "value": "${var.xml_xsl_list}" }
    ]
  }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

#28 created the ecs service for the xml service
resource "aws_ecs_service" "ecs_xml_service" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-xml-service" # Name the service
  cluster         = aws_ecs_cluster.ecs-cluster.id                                         # Reference the created Cluster
  task_definition = aws_ecs_task_definition.fargate-task-xml-service.arn                   # Reference the task that the service will spin up
  launch_type     = "FARGATE"
  desired_count   = 1 # Set up the number of containers to 1
  depends_on      = [aws_alb.load_balancer, aws_lb_target_group.xml_service_tg, aws_lb_listener_rule.xml_service_l]

  lifecycle {
    ignore_changes = [desired_count]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.xml_service_tg.arn # Reference the target group
    container_name   = aws_ecs_task_definition.fargate-task-xml-service.family
    container_port   = 8080 # Specify the container port
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false                               # Provide the containers with public IPs
    security_groups  = ["${aws_security_group.ecs-sg.id}"] # Set up the security group
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_xml_service.arn
  }
  tags = {
    tag = local.env_tag
  }
}


resource "aws_cloudwatch_log_group" "batch_inferred_mode_daemon_logs" {
  name = "/ecs/fargate-task-${var.environment}-batch-inferred-mode-daemon-logs"
  tags = {
    tag = local.env_tag
  }
}

resource "aws_ecs_task_definition" "fargate-task-batch-inferred-mode-daemon" {
  family                   = "fargate-task-${var.environment}-batch-inferred-mode-daemon"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.batch_inferred_daemon_cpu_unit
  memory                   = var.batch_inferred_daemon_memory_unit
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = <<TASK_DEFINITION
[
  {
    "name": "fargate-task-${var.environment}-batch-inferred-mode-daemon",
    "image": "${aws_ecr_repository.ecr_batch_inferred_mode_daemon_repository.repository_url}",
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ],
    "cpu": ${var.batch_inferred_daemon_cpu_unit},
    "memory": ${var.batch_inferred_daemon_memory_unit},
    "essential": true,
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.batch_inferred_mode_daemon_logs.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "environment": [
        { "name": "API_ENDPOINT",               "value": "http://${local.scan_on_demand_api_call}:${var.ecs_service_port}${var.scan_on_demand_api_uri}file/upload" },
        { "name": "LOGIN_CREDENTIALS",          "value": "${var.login_credentials}" },
        { "name": "HOST",                       "value": "http://${local.irs_security_api_call}:${var.ecs_service_port}${var.security_api_uri}security/login" },
        { "name": "REGION",                     "value": "${var.aws_region}" },
        { "name": "CONNECTION_TYPE",            "value": "${var.environment}" },
        { "name": "SECRET_NAME",                "value": "${local.secret_manager_database_source}" },
        { "name": "PG_DATABASE",                "value": "${var.aurora_db_name}" },
        { "name": "IP",                         "value": "${var.batch_inferred_daemon_ip}" },
        { "name": "SHARED_DIRECTORY_USERNAME",  "value": "${var.batch_inferred_daemon_shared_directory_username}" },
        { "name": "SHARED_DIRECTORY_PASSWORD",  "value": "${var.batch_inferred_daemon_shared_directory_password}" },
        { "name": "GROUP_API_ENDPOINT",         "value": "http://${local.scan_on_demand_api_call}:${var.ecs_service_port}${var.scan_on_demand_api_uri}file/group" }
      ]
    }
]
TASK_DEFINITION
  tags = {
    tag = local.env_tag
  }
}

resource "aws_ecs_service" "ecs_batch_inferred_mode_daemon" {
  name            = "${var.organization}-${var.environment}-${var.region}-ecs-batch-inferred-mode-daemon"
  cluster         = aws_ecs_cluster.ecs-cluster.id
  task_definition = aws_ecs_task_definition.fargate-task-batch-inferred-mode-daemon.arn
  launch_type     = "FARGATE"
  depends_on      = [aws_alb.load_balancer, aws_lb_listener.lb_http_listener]
  desired_count   = 1

  lifecycle {
    ignore_changes = [desired_count]
  }

  network_configuration {
    subnets          = ["${aws_subnet.private_subnet_1.id}"]
    assign_public_ip = false
    security_groups  = ["${aws_security_group.ecs-sg.id}"]
  }

  service_registries {
    registry_arn = aws_service_discovery_service.sd_batch_inferred_mode_daemon.arn
  }
  tags = {
    tag = local.env_tag
  }
}

############################################# EC2-Instances ##############################################
# Generate keys if not using existing ones
resource "tls_private_key" "linux_bastion_key" {
  count     = var.existing_linux_bastion_key ? 0 : 1
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_private_key" "windows_bastion_key" {
  count     = var.existing_windows_bastion_key ? 0 : 1
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_private_key" "linux_jenkins_deployment_key" {
  count     = var.existing_private_jenkins_key ? 0 : 1
  algorithm = "RSA"
  rsa_bits  = 4096
}

# AWS key pairs
resource "aws_key_pair" "linux_bastion" {
  count      = var.existing_linux_bastion_key ? 0 : 1
  key_name   = "${var.organization}-${var.region}-${var.environment}-linux-bastion-key"
  public_key = tls_private_key.linux_bastion_key[0].public_key_openssh
}

resource "aws_key_pair" "windows_bastion" {
  count      = var.existing_windows_bastion_key ? 0 : 1
  key_name   = "${var.organization}-${var.region}-${var.environment}-windows-bastion-key"
  public_key = tls_private_key.windows_bastion_key[0].public_key_openssh
}

resource "aws_key_pair" "linux_jenkins_deployment_key" {
  count      = var.existing_private_jenkins_key ? 0 : 1
  key_name   = "${var.organization}-${var.region}-${var.environment}-jenkins-deployment-key"
  public_key = tls_private_key.linux_jenkins_deployment_key[0].public_key_openssh
}

# Local PEM key files
resource "local_file" "linux_bastion_key_file" {
  count           = var.existing_linux_bastion_key ? 0 : 1
  content         = tls_private_key.linux_bastion_key[0].private_key_pem
  filename        = "${path.module}/key-pem/${var.organization}-${var.region}-${var.environment}-linux-bastion-key.pem"
  file_permission = "0600"
}

resource "local_file" "windows_bastion_key_file" {
  count           = var.existing_windows_bastion_key ? 0 : 1
  content         = tls_private_key.windows_bastion_key[0].private_key_pem
  filename        = "${path.module}/key-pem/${var.organization}-${var.region}-${var.environment}-windows-bastion-key.pem"
  file_permission = "0600"
}

resource "local_file" "jenkins_deployment_key_file" {
  count           = var.existing_private_jenkins_key ? 0 : 1
  content         = tls_private_key.linux_jenkins_deployment_key[0].private_key_pem
  filename        = "${path.module}/key-pem/${var.organization}-${var.region}-${var.environment}-jenkins-deployment-key.pem"
  file_permission = "0600"
}

# creating EC2 bastion-windows Instance
resource "aws_instance" "ec2_windows_bastion_host" {
  ami           = var.windows_bastion_ami_id
  instance_type = var.windows_bastion_instance_type
  key_name      = var.existing_windows_bastion_key ? var.windows_bastion_key : aws_key_pair.windows_bastion[0].key_name

  root_block_device {
    volume_size           = var.windows_bastion_volume_size
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
    tags = {
      tag = local.env_tag
    }
  }

  tags = {
    Name          = "${var.organization}-ec2-${var.region}-${var.environment}-bastion-windows"
    Terraform     = "true"
    Environment   = "${var.environment}"
    Component     = "bastion"
    Managing-Team = "devops"
    State         = "active"
  }

  instance_initiated_shutdown_behavior = "stop"
  disable_api_termination              = "false"
  disable_api_stop                     = "false"
  security_groups                      = [aws_security_group.ec2-bastion-sg.name]
  iam_instance_profile                 = aws_iam_instance_profile.bastion-role-instance-profile.name
}

# Created the an Elastic IP  for the windows bastion host
resource "aws_eip" "ec2_windows_bastion_host_eip" {
  tags = {
    Name          = "${var.organization}-eip-${var.region}-${var.environment}-bastion-windows"
    Environment   = "${var.environment}"
    Component     = "windowsbastion"
    Managing-Team = "devops"
    State         = "active"
  }
}

# Associate the Elastic IP with the EC2 windows instance
resource "aws_eip_association" "ec2_windows_bastion_eip_association" {
  instance_id   = aws_instance.ec2_windows_bastion_host.id
  allocation_id = aws_eip.ec2_windows_bastion_host_eip.id
}

# creating EC2 Linux bastion instance
resource "aws_instance" "ec2_linux_bastion_host" {
  ami           = var.linux_bastion_ami_id
  instance_type = var.linux_bastion_instance_type
  key_name      = var.existing_linux_bastion_key ? var.linux_bastion_key : aws_key_pair.linux_bastion[0].key_name

  #Adding a 100GB EBS volume
  root_block_device {
    volume_size = var.linux_bastion_volume_size
    tags = {
      Name = "${var.organization}-${var.region}-${var.environment}-Linux-bastion-volume"
    }
  }

  tags = {
    Name          = "${var.organization}-ec2-${var.region}-${var.environment}-bastion-Linux"
    Terraform     = "true"
    Environment   = "${var.environment}"
    Component     = "bastion"
    Managing-Team = "devops"
    State         = "active"
  }

  instance_initiated_shutdown_behavior = "stop"
  disable_api_termination              = "false"
  disable_api_stop                     = "false"
  security_groups                      = [aws_security_group.ec2-bastion-sg.name]
  iam_instance_profile                 = aws_iam_instance_profile.bastion-role-instance-profile.name
}

# Allocate an Elastic IP
resource "aws_eip" "ec2_linux_bastion_eip" {
  tags = {
    Name          = "${var.organization}-eip-${var.region}-${var.environment}-bastion-Linux"
    Environment   = "${var.environment}"
    Component     = "bastion"
    Managing-Team = "devops"
    State         = "active"
  }
}

# Associate the Elastic IP with the EC2 instance
resource "aws_eip_association" "ec2_linux_bastion_eip_association" {
  instance_id   = aws_instance.ec2_linux_bastion_host.id
  allocation_id = aws_eip.ec2_linux_bastion_eip.id
}

# creating IAM Role for Jenkins-deployment-server
resource "aws_iam_role" "jenkins-deployment-role" {
  name = "${var.organization}-${var.region}-${var.environment}-jenkins-deployment-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

#Inline policy for jenkins deployment role
resource "aws_iam_role_policy" "jenkins_deployment_inline_policy" {
  name = "${var.organization}-${var.region}-${var.environment}-jenkins-deployment-access-inline-policy"
  role = aws_iam_role.jenkins-deployment-role.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "ECSAccess",
        Effect = "Allow",
        Action = [
          "ecs:*",
          "ecs-tasks:*"
        ],
        Resource = "*"
      },
      {
        Sid    = "EC2Access",
        Effect = "Allow",
        Action = [
          "ec2:*",
        ],
        Resource = "*"
      },
      {
        Sid    = "CloudMapAccess",
        Effect = "Allow",
        Action = [
          "servicediscovery:*"
        ],
        Resource = "*"
      },
      {
        Sid    = "RDSAccess",
        Effect = "Allow",
        Action = [
          "rds:*"
        ],
        Resource = "*"
      },
      {
        Sid    = "CloudWatchAccess",
        Effect = "Allow",
        Action = [
          "cloudwatch:*",
          "logs:*",
          "monitoring:*"
        ],
        Resource = "*"
      },
      {
        Sid    = "SecretsManagerAccess",
        Effect = "Allow",
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:ListSecrets"
        ],
        Resource = "*"
      },
      {
        Sid    = "IAMAccess",
        Effect = "Allow",
        Action = [
          "iam:PassRole",
          "iam:GetRole",
          "iam:ListRoles"
        ],
        Resource = "*"
      },
      {
        Sid    = "OpenSearchAccess",
        Effect = "Allow",
        Action = [
          "es:*"
        ],
        Resource = "*"
      },
      {
        Sid    = "ECRAccess",
        Effect = "Allow",
        Action = [
          "ecr:*"
        ],
        Resource = "*"
      },
      {
        Sid    = "LambdaAccess",
        Effect = "Allow",
        Action = [
          "lambda:*"
        ],
        Resource = "*"
      },
      {
        Sid    = "EventBridgeAccess",
        Effect = "Allow",
        Action = [
          "events:*"
        ],
        Resource = "*"
      },
      {
        Sid    = "S3Access",
        Effect = "Allow",
        Action = [
          "s3:*"
        ],
        Resource = "*"
      }
    ]
  })
}

# attach role to instance profile for Jenkins-deployment-server
resource "aws_iam_instance_profile" "jenkins-deployment-role-instance-profile" {
  name = "${var.organization}-${var.region}-${var.environment}-jenkins-deployment-role-instance-profile"
  role = aws_iam_role.jenkins-deployment-role.name
}

# creating EC2 Jenkins Instance
resource "aws_network_interface" "ec2-jenkins-interface" {
  subnet_id       = aws_subnet.private_subnet_1.id
  security_groups = [aws_security_group.private-jenkins-sg.id]

  tags = {
    Name = "${var.organization}-${var.region}-${var.environment}-jenkins-interface"
  }
}

resource "aws_instance" "ec2_private_jenkins_instance" {
  ami           = var.private_jenkins_ec2_ami_id
  instance_type = var.private_jenkins_instance_type
  key_name      = var.existing_private_jenkins_key ? var.private_jenkins_key : aws_key_pair.linux_jenkins_deployment_key[0].key_name

  network_interface {
    network_interface_id = aws_network_interface.ec2-jenkins-interface.id
    device_index         = 0
  }

  tags = {
    Name          = "${var.organization}-ec2-${var.region}-${var.environment}-jenkins-deployment-server"
    Terraform     = "true"
    environment   = "${var.environment}"
    Component     = "jenkins-deployment"
    Managing-Team = "devops"
    State         = "active"
    tag           = local.env_tag
  }

  root_block_device {
    volume_size           = var.private_jenkins_ec2_volume_size
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
    tags = {
      Name = "${var.organization}-${var.region}-${var.environment}-jenkins-deployment-server-volume"
    }
  }

  instance_initiated_shutdown_behavior = "stop"
  disable_api_termination              = "false"
  disable_api_stop                     = "false"
  iam_instance_profile                 = aws_iam_instance_profile.jenkins-deployment-role-instance-profile.name
}

#################################S AWS-Batch  ####################################################

# CloudWatch Log Group for AWS Batch Jobs of Records Transfer Management Service
resource "aws_cloudwatch_log_group" "records_xfer_batch_log" {
  name = "/aws/batch/${var.organization}-${var.environment}-records-xfer-batch-logs"
  tags = {
    "Environment" = local.env_tag
  }
}

# AWS Batch Compute Environment for the Records Transfer Management Service
resource "aws_batch_compute_environment" "records_xfer_batch_ce" {
  compute_environment_name = "${var.organization}-${var.environment}-records-xfer-batch-ce"

  compute_resources {
    max_vcpus          = 64
    security_group_ids = [aws_security_group.ecs-sg.id]
    subnets            = [aws_subnet.private_subnet_1.id]
    type               = "FARGATE"
  }
  type = "MANAGED"
  tags = {
    "Environment" = local.env_tag
  }
}

# AWS Batch Job Queue for the Records Transfer Management Service
resource "aws_batch_job_queue" "records_xfer_batch" {
  name                 = "${var.organization}-${var.environment}-records-xfer-batch"
  state                = "ENABLED"
  priority             = 1
  compute_environments = [aws_batch_compute_environment.records_xfer_batch_ce.arn]
  depends_on           = [aws_batch_compute_environment.records_xfer_batch_ce]
  tags = {
    "Environment" = local.env_tag
  }
}

# AWS Batch Job Definition Records Transfer Management Service
resource "aws_batch_job_definition" "records_xfer_batch_defination" {
  name = "${var.organization}-${var.environment}-records-xfer-batch-job-definition"
  type = "container"

  platform_capabilities = ["FARGATE"]

  container_properties = jsonencode({
    command          = ["java", "-XshowSettings:vm", "-XX:MaxRAMPercentage=85", "-jar", "/app/app.jar"]
    image            = "${aws_ecr_repository.ecr_records_management_transfer_repository.repository_url}"
    executionRoleArn = "${aws_iam_role.ecs_task_execution_role.arn}"
    jobRoleArn       = "${aws_iam_role.ecs_task_execution_role.arn}"
    resourceRequirements = [
      { type = "VCPU", value = "1" },
      { type = "MEMORY", value = "2048" }
    ]
    fargatePlatformConfiguration = {
      platformVersion = "LATEST"
      assignPublicIp  = "ENABLED"
    }

    environment = [
      { name = "SPRING_PROFILES_ACTIVE", value = "new${var.environment}${var.organization}jaw" },
      { name = "SERVER_PORT", value = "${var.ecs_service_port}" },
      { name = "SERVER_SSL_ENABLED", value = "${var.ecs_server_ssl_enabled}" },
      { name = "SPRING_DATASOURCE_URL", value = "jdbc-secretsmanager:postgresql://${aws_rds_cluster.aurora_rds_database_cluster.endpoint}:${var.aurora_db_port}/${var.aurora_db_name}" },
      { name = "SPRING_DATASOURCE_DRIVER-CLASS-NAME", value = "${var.datasource_driver_class_name}" },
      { name = "SPRING_DATASOURCE_USERNAME", value = "${local.secret_manager_database_source}" },
      { name = "METADATAAPI_SERVICE_HOST", value = "${local.metadata_search_api_call}" },
      { name = "METADATAAPI_SERVICE_PORT", value = "${var.ecs_service_port}" },
      { name = "METADATAAPI_SERVICE_URI", value = "${var.metadata_search_api_uri}" },
      { name = "S3API_SERVICE_HOST", value = "${local.s3_api_call}" },
      { name = "S3API_SERVICE_PORT", value = "${var.ecs_service_port}" },
      { name = "S3API_SERVICE_URI", value = "${var.s3_api_uri}" },
      { name = "RECORDSMANAGEMENTAPI_SERVICE_HOST", value = "${local.records_management_api_call}" },
      { name = "RECORDSMANAGEMENTAPI_SERVICE_PORT", value = "${var.ecs_service_port}" },
      { name = "RECORDSMANAGEMENTAPI_SERVICE_URI", value = "${var.records_management_api_uri}" },
      { name = "SECURITYAPI_SERVICE_HOST", value = "${local.irs_security_api_call}" },
      { name = "SECURITYAPI_SERVICE_PORT", value = "${var.ecs_service_port}" },
      { name = "SECURITYAPI_SERVICE_URI", value = "${var.security_api_uri}" },
      { name = "AMAZONPROPERTIES_TRANSFER_STAGE_BUCKET", value = "${local.s3_transfer_stage_bucket_name}" },
      { name = "AMAZONPROPERTIES_TRANSFER_BUCKET", value = "${local.s3_transfer_api_bucket_name}" },
      { name = "RETRY_MAXATTEMPTS", value = "${var.records_transfer_retry_max_attempts}" },
      { name = "RETRY_TIMEINTERVAL", value = "${var.records_transfer_retry_time_interval}" }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/aws/batch/${var.organization}-${var.environment}-records-xfer-batch-logs"
        "awslogs-region"        = "${var.aws_region}"
        "awslogs-stream-prefix" = "${var.organization}-${var.environment}-records-xfer"
      }
    }
  })
  tags = {
    "Environment" = local.env_tag
  }
}

# Creating AWS CloudWatch logs for AWS Batch job  for records management disposition api 
resource "aws_cloudwatch_log_group" "disposition_xfer_batch_log" {
  name = "/aws/batch/${var.organization}-${var.environment}-records-disposition-xfer-batch-logs"
  tags = {
    "Environment" = local.env_tag
  }
}

# Creating AWS Batch job definition resource for irs record management disposition api 
resource "aws_batch_job_definition" "records_disposition_xfer_batch" {
  name                  = "${var.organization}-${var.environment}-records-disposition-xfer-batch-job-definition"
  type                  = "container"
  platform_capabilities = ["FARGATE"]
  container_properties = jsonencode({
    command          = ["java", "-XshowSettings:vm", "-XX:MaxRAMPercentage=85", "-jar", "/app/app.jar"]
    image            = "${aws_ecr_repository.ecr_records_management_disposition_repository.repository_url}"
    executionRoleArn = "${aws_iam_role.ecs_task_execution_role.arn}"
    jobRoleArn       = "${aws_iam_role.ecs_task_execution_role.arn}"
    fargatePlatformConfiguration = {
      platformVersion = "LATEST"
      assignPublicIp  = "ENABLED" # assign a public IP
    }
    resourceRequirements = [
      { type = "VCPU", value = "1" },
      { type = "MEMORY", value = "2048" }
    ]
    environment = [
      { name = "SPRING_PROFILES_ACTIVE", value = "new${var.environment}${var.organization}jaw" },
      { name = "SERVER_PORT", value = "${var.ecs_service_port}" },
      { name = "SERVER_SSL_ENABLED", value = "${var.ecs_server_ssl_enabled}" },
      { name = "SPRING_DATASOURCE_URL", value = "jdbc-secretsmanager:postgresql://${aws_rds_cluster.aurora_rds_database_cluster.endpoint}:${var.aurora_db_port}/${var.aurora_db_name}" },
      { name = "SPRING_DATASOURCE_DRIVER-CLASS-NAME", value = "${var.datasource_driver_class_name}" },
      { name = "SPRING_DATASOURCE_USERNAME", value = "${local.secret_manager_database_source}" },
      { name = "AMAZONPROPERTIES_AWSREGION", value = "${var.aws_region}" },
      { name = "AMAZONPROPERTIES_AWSRBATCHJOB_DEFINITION", value = "${local.records_management_xfer_batch_jobdefinition}" },
      { name = "AMAZONPROPERTIES_AWSRBATCHJOB_QUEUE", value = "${local.records_management_xfer_batch_jobqueue}" },
      { name = "AMAZONPROPERTIES_AWSRBATCHJOB_EXECUTION_PARAM", value = "${var.records_disposition_batch_job_execution_param}" },
      { name = "METADATAAPI_SERVICE_HOST", value = "${local.metadata_search_api_call}" },
      { name = "METADATAAPI_SERVICE_PORT", value = "${var.ecs_service_port}" },
      { name = "METADATAAPI_SERVICE_URI", value = "${var.metadata_search_api_uri}" },
      { name = "SECURITYAPI_SERVICE_HOST", value = "${local.irs_security_api_call}" },
      { name = "SECURITYAPI_SERVICE_PORT", value = "${var.ecs_service_port}" },
      { name = "SECURITYAPI_SERVICE_URI", value = "${var.security_api_uri}" },
      { name = "RETRY_MAXATTEMPTS", value = "${var.records_disposition_retry_max_attempts}" },
      { name = "RETRY_TIMEINTERVAL", value = "${var.records_disposition_retry_time_interval}" }
    ]
    # Log configuration block
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/aws/batch/${var.organization}-${var.environment}-records-disposition-xfer-batch-logs"
        "awslogs-region"        = "${var.aws_region}"
        "awslogs-stream-prefix" = "${var.organization}-${var.environment}-records-disposition-xfer"
      }
    }
  })
  tags = {
    "Environment" = local.env_tag
  }
}

# IAM Role for AWS Batch Service
resource "aws_iam_role" "batch_service_role" {
  name = "${var.organization}-${var.environment}-${var.region}-batch-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "batch.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    "Environment" = local.env_tag
  }
}

# Attach the AWS managed policy to the Batch service role
resource "aws_iam_role_policy_attachment" "batch_service_role_policy" {
  role       = aws_iam_role.batch_service_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
  depends_on = [aws_iam_role.batch_service_role]
}
resource "aws_iam_role_policy_attachment" "ecs_full_access_policy_attachment" {
  role       = aws_iam_role.batch_service_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonECS_FullAccess"
  depends_on = [aws_iam_role.batch_service_role]
}

# IAM Role for EC2 Instances in Batch Compute Environment
resource "aws_iam_role" "batch_instance_role" {
  name = "${var.organization}-${var.environment}-${var.region}-batch-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

# Attach required policies to EC2 instance role for batch
resource "aws_iam_role_policy_attachment" "batch_instance_role_policy_ec2" {
  role       = aws_iam_role.batch_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

# Instance Profile for EC2 Instances in Batch
resource "aws_iam_instance_profile" "batch_instance_profile" {
  name = "${var.organization}-${var.environment}-${var.region}-batch-instance-profile"
  role = aws_iam_role.batch_instance_role.name
}

# Creating the cloudwatch log group for the Naix-Daemon Batch logs
resource "aws_cloudwatch_log_group" "naix_daemon_batch_logs" {
  name = "/aws/batch/${var.organization}-${var.environment}-naix-daemon-batch-logs"
  tags = {
    tag = local.env_tag
  }
}

# Compute Environment for AWS Batch for the Naix Batch Job
resource "aws_batch_compute_environment" "naix_batch_compute_environment" {
  compute_environment_name = "${var.organization}-${var.environment}-naix-batch-compute-environment"
  type                     = "MANAGED"
  state                    = "ENABLED"
  service_role             = aws_iam_role.batch_service_role.arn
  depends_on               = [aws_iam_role_policy_attachment.ecs_full_access_policy_attachment]

  compute_resources {
    type                = "EC2"
    allocation_strategy = "BEST_FIT_PROGRESSIVE"
    min_vcpus           = 0
    max_vcpus           = 256
    desired_vcpus       = 0
    instance_type       = ["optimal"]
    subnets             = [aws_subnet.private_subnet_1.id]
    security_group_ids  = [aws_security_group.ecs-sg.id]
    ec2_key_pair        = var.existing_naix_batch_key_pair ? var.naix_batch_ec2_key_pair : ""
    instance_role       = aws_iam_instance_profile.batch_instance_profile.arn
    ec2_configuration {
      image_type = "ECS_AL2"
    }
  }

  tags = {
    "Environment" = local.env_tag
  }
}

# Job Queue
resource "aws_batch_job_queue" "naix_batch_job_queue_ec2" {
  name                 = "${var.organization}-${var.environment}-naix-batch-job-queue-ec2"
  state                = "ENABLED"
  priority             = 0
  compute_environments = [aws_batch_compute_environment.naix_batch_compute_environment.arn]
  depends_on           = [aws_batch_compute_environment.naix_batch_compute_environment]
  lifecycle {
    prevent_destroy = false
  }

  tags = {
    "Environment" = local.env_tag
  }
}

resource "aws_batch_job_definition" "naix_batch_job_definition_ec2" {
  name = "${var.organization}-${var.environment}-naix-batch-job-definition-ec2"
  type = "container"

  container_properties = jsonencode({
    image            = "${aws_ecr_repository.ecr_upload_daemon_repository.repository_url}"
    command          = []
    jobRoleArn       = "${aws_iam_role.ecs_task_execution_role.arn}"
    executionRoleArn = "${aws_iam_role.ecs_task_execution_role.arn}"
    volumes          = []
    environment = [
      { name = "daemon", value = var.naix_batch_daemon },
      { name = "UPLOAD_TEMP_FOLDER", value = var.upload_temp_folder_path },
      { name = "RUNOCR_URL", value = "http://${local.run_ocr_api_call}:${var.ecs_service_port}${var.run_ocr_api_uri}process" },
      { name = "TESSERACT", value = var.naix_services_tesseract_path },
      { name = "POPPLER", value = var.naix_services_poppler_path },
      { name = "PG_DATABASE", value = var.aurora_db_name },
      { name = "CONNECTION_TYPE", value = var.environment },
      { name = "WORKERS", value = var.naix_batch_workers },
      { name = "THREAD", value = var.naix_batch_threads },
      { name = "REGION", value = var.aws_region },
      { name = "BUCKET_NAME", value = local.s3_bucket_name },
      { name = "LOG_GROUP_NAME", value = local.naix_batch_log_group_name },
      { name = "LOG_STREAM_NAME", value = local.naix_batch_log_stream_name },
      { name = "CONTEXT_ID", value = var.app_context_id },
      { name = "SECRET_NAME", value = local.secret_manager_database_source },
      { name = "JOBNAME", value = local.naix_daemon_batch_jobname },
      { name = "JOBQUEUE", value = local.naix_daemon_batch_jobqueue },
      { name = "JOBDEFINITION", value = local.naix_daemon_batch_jobdefinition },
      { name = "TEXTRACT_REGION_NAME", value = var.textract_region_name },
      { name = "TEXTRACT_AWS_SECRET_ACCESS_KEY", value = var.naix_batch_textract_aws_secret_access_key },
      { name = "TEXTRACT_AWS_ACCESS_KEY_ID", value = var.naix_batch_textract_aws_access_key_id },
      { name = "SUBMIT_TEMP_FOLDER", value = var.submit_temp_folder_path },
      { name = "OUTPUT_LOG_FOLDER", value = var.output_log_folder },
      { name = "990_DRIVER", value = "http://${local.object_driver_api_call}:${var.ecs_service_port}${var.object_driver_api_uri}processpayload" },
      { name = "BACKEND_DOMAIN", value = "http://${local.scan_on_demand_api_call}:${var.ecs_service_port}" }
    ]
    mountPoints = []
    ulimits     = []
    resourceRequirements = [
      {
        value = "8"
        type  = "VCPU"
      },
      {
        value = "16384"
        type  = "MEMORY"
      }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "${aws_cloudwatch_log_group.naix_daemon_batch_logs.name}"
        "awslogs-region"        = "${var.aws_region}"
        "awslogs-stream-prefix" = "${var.environment}-naix-batch-logs"
      }
    }
    secrets = []
  })

  timeout {
    attempt_duration_seconds = 900 # Set the timeout duration in seconds (e.g., 1 hour=3600)
  }

  platform_capabilities = ["EC2"]
  tags = {
    "Environment" = local.env_tag
  }
}

# Creating the Cloudwatch batch logs for the Submit Daemon batch
resource "aws_cloudwatch_log_group" "submit_daemon_batch_logs" {
  name = "/aws/batch/${var.organization}-${var.environment}-submit-daemon-batch-logs"
  tags = {
    tag = local.env_tag
  }
}

# Compute Environment for AWS Batch
resource "aws_batch_compute_environment" "submit_daemon_batch_compute_environment" {
  compute_environment_name = "${var.organization}-${var.environment}-submit-daemon-batch-compute-environment"
  type                     = "MANAGED"
  state                    = "ENABLED"
  service_role             = aws_iam_role.batch_service_role.arn
  depends_on               = [aws_iam_role_policy_attachment.ecs_full_access_policy_attachment]
  compute_resources {
    type                = "EC2"
    allocation_strategy = "BEST_FIT_PROGRESSIVE"
    min_vcpus           = 0
    max_vcpus           = 256
    desired_vcpus       = 0
    instance_type       = ["optimal"]
    subnets             = [aws_subnet.private_subnet_1.id]
    security_group_ids  = [aws_security_group.ecs-sg.id]
    ec2_key_pair        = var.existing_submit_daemon_batch_key_pair ? var.submit_daemon_batch_ec2_key_pair : ""
    instance_role       = aws_iam_instance_profile.batch_instance_profile.arn
    ec2_configuration {
      image_type = "ECS_AL2"
    }
  }

  tags = {
    "Environment" = local.env_tag
  }
}

# Job Queue
resource "aws_batch_job_queue" "submit_daemon_batch_job_queue_ec2" {
  name     = "${var.organization}-${var.environment}-submit-daemon-batch-job-queue-ec2"
  state    = "ENABLED"
  priority = 0

  compute_environments = [aws_batch_compute_environment.submit_daemon_batch_compute_environment.arn]
  depends_on           = [aws_batch_compute_environment.submit_daemon_batch_compute_environment]

  tags = {
    "Environment" = local.env_tag
  }
}

resource "aws_batch_job_definition" "submit_daemon_batch_job_definition_ec2" {
  name = "${var.organization}-${var.environment}-submit-daemon-batch-job-definition-ec2"
  type = "container"

  container_properties = jsonencode({
    image            = "${aws_ecr_repository.ecr_submit_daemon_repository.repository_url}"
    command          = []
    jobRoleArn       = "${aws_iam_role.ecs_task_execution_role.arn}"
    executionRoleArn = "${aws_iam_role.ecs_task_execution_role.arn}"
    volumes          = []
    environment = [
      { name = "DAEMON", value = var.submit_batch_daemon },
      { name = "SUBMIT_TEMP_FOLDER", value = var.submit_temp_folder_path },
      { name = "TESSERACT", value = var.naix_services_tesseract_path },
      { name = "PG_DATABASE", value = var.aurora_db_name },
      { name = "CONNECTION_TYPE", value = var.environment },
      { name = "REGION", value = var.aws_region },
      { name = "BUCKET_NAME", value = local.s3_bucket_name },
      { name = "LOG_GROUP_NAME", value = local.submit_batch_log_group_name },
      { name = "LOG_STREAM_NAME", value = local.submit_batch_log_stream_name },
      { name = "CONTEXT_ID", value = var.app_context_id },
      { name = "SECRET_NAME", value = local.secret_manager_database_source },
      { name = "BACKEND_DOMAIN", value = "http://${local.scan_on_demand_api_call}:${var.ecs_service_port}" },
      { name = "990_DRIVER", value = "http://${local.object_driver_api_call}:${var.ecs_service_port}${var.object_driver_api_uri}processpayload" },
      { name = "HOST", value = "http://${local.irs_security_api_call}:${var.ecs_service_port}${var.security_api_uri}security/login" },
      { name = "LOGIN_CREDENTIALS", value = var.submit_batch_login_credentials },
      { name = "XML_SVC_URL", value = "http://${local.xml_service_api_call}:${var.ecs_service_port}${var.xml_service_api_uri}processpayload" },
      { name = "JOBNAME", value = local.submit_daemon_batch_jobname },
      { name = "JOBQUEUE", value = local.submit_daemon_batch_jobqueue },
      { name = "JOBDEFINITION", value = local.submit_daemon_batch_jobdefinition },
      { name = "UPLOAD_TEMP_FOLDER", value = var.upload_temp_folder_path },
      { name = "POPPLER", value = var.naix_services_poppler_path },
      { name = "WORKERS", value = var.submit_daemon_batch_workers }

    ]
    mountPoints = []
    ulimits     = []
    resourceRequirements = [
      {
        value = "8"
        type  = "VCPU"
      },
      {
        value = "16384"
        type  = "MEMORY"
      }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "${aws_cloudwatch_log_group.submit_daemon_batch_logs.name}"
        "awslogs-region"        = "${var.aws_region}"
        "awslogs-stream-prefix" = "${var.environment}-submit-batch-logs"
      }
    }
    secrets = []
  })

  timeout {
    attempt_duration_seconds = 900 # Set the timeout duration in seconds (e.g., 1 hour=3600)
  }

  platform_capabilities = ["EC2"]
  tags = {
    "Environment" = local.env_tag
  }
}

################################### Aurora Postgresql Database ########################################
resource "aws_db_subnet_group" "aurora_subnet_group" {
  name = lower("${var.organization}-${var.environment}-${var.region}-aurora-subnet-group")
  subnet_ids = [
    aws_subnet.private_subnet_1.id,
    aws_subnet.private_subnet_2.id
  ]
  tags = {
    Name = "${var.organization}-${var.environment}-${var.region}-DB-group"
    tag  = local.env_tag
  }
}

#Create the RDS database cluster
resource "aws_rds_cluster" "aurora_rds_database_cluster" {
  cluster_identifier     = lower("${var.organization}-${var.environment}-${var.region}-aurora-db-cluster")
  engine                 = var.aurora_engine
  master_username        = var.aurora_master_username
  master_password        = var.aurora_master_password
  database_name          = var.aurora_db_name
  skip_final_snapshot    = true
  db_subnet_group_name   = aws_db_subnet_group.aurora_subnet_group.name
  vpc_security_group_ids = [aws_security_group.rds-db-sg.id]
  tags = {
    Name                    = "${var.organization}-${var.environment}-${var.region}-db-cluster"
    backup_retention_period = 7             # Retain backups for 7 days
    preferred_backup_window = "02:00-03:00" # Set the preferred backup window (UTC)
    tag                     = local.env_tag
  }
}

# Create an RDS instance in the cluster with a custom name
resource "aws_rds_cluster_instance" "aurora_rds_database_instance" {
  count              = 1 # Change this if you need more instances
  cluster_identifier = aws_rds_cluster.aurora_rds_database_cluster.cluster_identifier
  instance_class     = var.aurora_db_instance_class
  engine             = var.aurora_engine

  # Custom instance identifier
  identifier = lower("${var.organization}-${var.region}-${var.environment}-rds-database-instance-${count.index + 1}")

  tags = {
    Name = "${var.organization}-${var.environment}-${var.region}-aurora-instance-${count.index + 1}"
    tag  = local.env_tag
  }
}

################################## AWS-Elastic-Cache ######################################
resource "aws_elasticache_subnet_group" "elastic_cache_subnet_group" {
  name       = "${var.organization}-${var.environment}-${var.region}-elasticache-subnet-group"
  subnet_ids = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id]
}

resource "aws_elasticache_replication_group" "elastic_cache_redis_rg" {
  replication_group_id       = "${var.organization}-${var.environment}-${var.region}-redis-cluster"
  description                = "${var.organization}-${var.environment}-${var.region}-Redis-Cluser-with-rg"
  engine                     = var.elasticache_redis_engine
  engine_version             = var.elasticache_redis_engine_version
  node_type                  = var.elasticache_redis_node_type
  num_cache_clusters         = 2
  parameter_group_name       = var.elasticache_redis_parameter_group_name
  port                       = var.elasticache_redis_port
  subnet_group_name          = aws_elasticache_subnet_group.elastic_cache_subnet_group.name
  security_group_ids         = [aws_security_group.elastic-cache-redis.id]
  automatic_failover_enabled = true
  multi_az_enabled           = true
  tags = {
    Name = "${var.organization}-${var.environment}-${var.region}-elasticache-redis-cluster"
  }
}

#######################################  AWS-Lambda-Resources ##############################################

data "aws_caller_identity" "current_user" {}

resource "null_resource" "push_image_for_runocr_tesseract_lambda" {
  depends_on = [aws_ecr_repository.ecr_runocr_tesseract_lambda_repository]
  provisioner "local-exec" {
    command = <<EOT
      aws ecr get-login-password --region ${var.aws_region} | sudo docker login --username AWS --password-stdin ${data.aws_caller_identity.current_user.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com
      sudo docker pull hello-world
      sudo docker tag hello-world ${aws_ecr_repository.ecr_runocr_tesseract_lambda_repository.repository_url}:latest
      sudo docker push ${aws_ecr_repository.ecr_runocr_tesseract_lambda_repository.repository_url}:latest
    EOT
  }
}

# 2. IAM Role for Tesseract Lambda
resource "aws_iam_role" "runocr-tesseract-lambda-role" {
  name               = "${var.organization}-${var.environment}-${var.region}-runocr-tesseract-lambda-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

# List of AWS-managed policy ARNs to attach for the runocr-tesseract Lambda role
locals {
  runocr_tesseract_lambda_policy_arns = [
    "arn:aws:iam::aws:policy/AWSLambda_FullAccess",
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
  ]
}

# Attach all specified policies to the runocr-tesseract Lambda IAM role
resource "aws_iam_role_policy_attachment" "runocr_tesseract_lambda_policies" {
  for_each   = toset(local.runocr_tesseract_lambda_policy_arns)
  role       = aws_iam_role.runocr-tesseract-lambda-role.name
  policy_arn = each.value
}

# 5. Tesseract Lambda Function
resource "aws_lambda_function" "runocr-tesseract-lambda-function" {
  function_name = "${var.organization}-${var.environment}-${var.region}-runocr-tesseract-lambda-function"
  role          = aws_iam_role.runocr-tesseract-lambda-role.arn
  image_uri     = "${aws_ecr_repository.ecr_runocr_tesseract_lambda_repository.repository_url}:latest"
  package_type  = "Image"
  timeout       = 300
  memory_size   = 1024
  architectures = ["x86_64"]

  depends_on = [
    aws_iam_role_policy_attachment.runocr_tesseract_lambda_policies,
    aws_security_group.runocr-tesseract-lambda-sg,
    null_resource.push_image_for_runocr_tesseract_lambda
  ]

  vpc_config {
    subnet_ids         = [aws_subnet.private_subnet_1.id]
    security_group_ids = [aws_security_group.runocr-tesseract-lambda-sg.id]
  }

  environment {
    variables = {
      REGION               = var.aws_region
      LOG_GROUP_NAME       = local.runocr_tesseract_lambda_log_group_name
      LOG_STREAM_NAME      = local.runocr_tesseract_lambda_log_stream_name
      CONNECTION_TYPE      = var.environment
      BUCKET_NAME          = local.s3_bucket_name
      TESSERACT_CMD_LAMBDA = var.runocr_tesseract_lambda_tesseract_cmd_path
    }
  }
}

resource "aws_iam_policy" "ecs_lambda_invoke_policy" {
  name        = "${var.organization}-${var.environment}-${var.region}-ecs-lambda-invoke-policy"
  description = "Allows ECS tasks to invoke the Lambda function"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "lambda:InvokeFunction",
          "lambda:InvokeAsync"
        ],
        Resource = aws_lambda_function.runocr-tesseract-lambda-function.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ECS-Lambda-InnovationAccess" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = aws_iam_policy.ecs_lambda_invoke_policy.arn
}

################################ secret-manager  ##########################################
resource "aws_secretsmanager_secret" "ssm_rds" {
  name = "${var.organization}-${var.environment}-${var.region}-ssm-key-rds"

  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_secretsmanager_secret_version" "ssm_version" {
  secret_id = aws_secretsmanager_secret.ssm_rds.id
  secret_string = jsonencode({
    username             = var.dbuser,
    password             = var.dbpassword,
    engine               = var.dbengine,
    host                 = aws_rds_cluster.aurora_rds_database_cluster.endpoint,
    port                 = var.dbport,
    dbInstanceIdentifier = aws_rds_cluster.aurora_rds_database_cluster.endpoint
  })
}

# JWT Secret
resource "aws_secretsmanager_secret" "ssm_jwt" {
  name = "${var.organization}-${var.environment}-${var.region}-ssm-jwt-secret"

  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_secretsmanager_secret_version" "ssm_jwt_version" {
  secret_id = aws_secretsmanager_secret.ssm_jwt.id
  secret_string = jsonencode({
    jwt-secret-eauth       = var.jwtsecreteauth,
    jwt-secret-internal    = var.jwtsecretinternal,
    jwt-secret-public      = var.jwtsecretpublic,
    jwt-secret-private     = var.jwtsecretprivate,
    jwt-secret-certificate = var.jwtsecretcertificate
  })
}
