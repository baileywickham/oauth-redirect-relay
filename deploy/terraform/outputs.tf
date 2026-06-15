output "broker_url" {
  description = "Public HTTPS URL of the broker. Register this exact URL as the OAuth redirect URI with your provider, and point your dev boxes' redirect_uri at it."
  value       = aws_lambda_function_url.broker.function_url
}

output "function_name" {
  description = "Name of the deployed Lambda function."
  value       = aws_lambda_function.broker.function_name
}

output "log_group" {
  description = "CloudWatch log group for the broker."
  value       = aws_cloudwatch_log_group.broker.name
}
