# ------------------------------------------------------- Evidence integrity
# Each run manifest is signed with an asymmetric KMS key and hash-chained to the previous
# run's manifest, so a missing, reordered or altered run is detectable by `grc-evidence verify`.

data "aws_iam_policy_document" "signing_key" {
  #checkov:skip=CKV_AWS_109:Key policy root statement delegates key administration to IAM; resource "*" means this key in a key policy
  #checkov:skip=CKV_AWS_111:Key policy root statement delegates key administration to IAM; resource "*" means this key in a key policy
  #checkov:skip=CKV_AWS_356:In a KMS key policy, resource "*" refers only to the key the policy is attached to
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "signing" {
  #checkov:skip=CKV_AWS_7:KMS cannot rotate asymmetric keys automatically; rotate by creating a new key and updating signing.kms_key_id, keeping the old key to verify older runs
  count                    = var.enable_signing ? 1 : 0
  description              = "${var.name} run manifest signing"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  enable_key_rotation      = false
  deletion_window_in_days  = 30
  policy                   = data.aws_iam_policy_document.signing_key.json
  tags                     = var.tags
}

resource "aws_kms_alias" "signing" {
  count         = var.enable_signing ? 1 : 0
  name          = "alias/${var.name}-signing"
  target_key_id = aws_kms_key.signing[0].key_id
}

data "aws_iam_policy_document" "integrity" {
  dynamic "statement" {
    for_each = aws_kms_key.signing[*].arn

    content {
      sid       = "SignRunManifests"
      actions   = ["kms:Sign"]
      resources = [statement.value]

      condition {
        test     = "StringEquals"
        variable = "kms:SigningAlgorithm"
        values   = ["ECDSA_SHA_256"]
      }

      condition {
        test     = "StringEquals"
        variable = "kms:MessageType"
        values   = ["DIGEST"]
      }
    }
  }

  # The hash chain reads the previous run's manifest.json; works with signing off too.
  statement {
    sid       = "ReadPreviousRunForChain"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/evidence/dt=*/manifest.json"]
  }

  statement {
    sid       = "ListEvidencePrefix"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.evidence.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["evidence/", "evidence/*"]
    }
  }
}

resource "aws_iam_role_policy" "integrity" {
  name   = "evidence-integrity"
  role   = aws_iam_role.function.id
  policy = data.aws_iam_policy_document.integrity.json
}
