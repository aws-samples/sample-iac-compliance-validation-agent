# Sample Terraform artifact with intentional compliance gaps for demoing CVA.
# Validate with:  cva validate samples/terraform/main.tf -f hipaa -f pci-dss

# VIOLATION: RDS instance without storage encryption (HIPAA/PCI encryption-at-rest).
resource "aws_db_instance" "patient_records" {
  identifier        = "patient-records"
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  allocated_storage = 100
  storage_encrypted = false
  publicly_accessible = true
}

# COMPLIANT: encrypted, private RDS instance.
resource "aws_db_instance" "billing" {
  identifier          = "billing"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  allocated_storage   = 100
  storage_encrypted   = true
  kms_key_id          = "arn:aws:kms:us-east-1:111122223333:key/abcd"
  deletion_protection = true
  publicly_accessible = false
  backup_retention_period = 30
}

# VIOLATION: S3 bucket with no encryption, versioning, or public-access block.
resource "aws_s3_bucket" "phi_exports" {
  bucket = "phi-exports"
}

# COMPLIANT: S3 bucket with encryption, versioning, and public-access block (modern split resources).
resource "aws_s3_bucket" "audit_logs" {
  bucket = "audit-logs"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs_enc" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:111122223333:key/abcd"
    }
  }
}

resource "aws_s3_bucket_versioning" "audit_logs_ver" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs_pab" {
  bucket                  = aws_s3_bucket.audit_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# VIOLATION: DynamoDB table without server-side encryption.
resource "aws_dynamodb_table" "sessions" {
  name         = "sessions"
  hash_key     = "id"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "id"
    type = "S"
  }
}
