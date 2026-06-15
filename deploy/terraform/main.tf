# A stateless Lambda behind a public Function URL. The Function URL is the single
# stable HTTPS endpoint you register as your OAuth redirect URI; the function
# verifies the signed state and 302s the code back to the right dev box.

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "broker" {
  name               = "${var.function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.broker.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Log group declared explicitly so retention is managed (Lambda would otherwise
# create one with never-expire retention on first invocation).
resource "aws_cloudwatch_log_group" "broker" {
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

# Zips the prebuilt, dependency-free handler bundle (deploy/terraform/lambda/bundle/).
# It is committed to the repo, so consumers need no npm install — just terraform.
# Maintainers regenerate it with `npm install && npm run bundle` in lambda/.
data "archive_file" "broker" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/bundle"
  output_path = "${path.module}/.build/broker.zip"
}

resource "aws_lambda_function" "broker" {
  function_name    = var.function_name
  role             = aws_iam_role.broker.arn
  runtime          = "nodejs20.x"
  handler          = "index.handler"
  filename         = data.archive_file.broker.output_path
  source_code_hash = data.archive_file.broker.output_base64sha256
  timeout          = 5
  memory_size      = 128
  tags             = var.tags

  environment {
    variables = {
      RELAY_SIGNING_KEY = var.signing_key
      ALLOW_LOOPBACK    = tostring(var.allow_loopback)
      ALLOWED_ORIGINS   = join(",", var.allowed_origins)
      TTL_SECONDS       = tostring(var.ttl_seconds)
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.logs,
    aws_cloudwatch_log_group.broker,
  ]
}

# AuthType NONE: the OAuth provider must be able to reach this unauthenticated.
# Security comes from the signed state + allowlist inside the function, not the URL.
resource "aws_lambda_function_url" "broker" {
  function_name      = aws_lambda_function.broker.function_name
  authorization_type = "NONE"
}
