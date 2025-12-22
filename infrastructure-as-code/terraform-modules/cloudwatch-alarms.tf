# CloudWatch Alarms Module
# Standard alarms for monitoring

variable "alarm_name_prefix" {
  description = "Prefix for alarm names"
  type        = string
}

variable "resource_id" {
  description = "Resource ID to monitor"
  type        = string
}

variable "resource_type" {
  description = "Resource type: ec2, rds, lambda"
  type        = string
}

variable "sns_topic_arn" {
  description = "SNS topic ARN for notifications"
  type        = string
}

resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "${var.alarm_name_prefix}-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = var.resource_type == "ec2" ? "AWS/EC2" : "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "CPU utilization is too high"
  alarm_actions       = [var.sns_topic_arn]

  dimensions = {
    InstanceId = var.resource_id
  }
}

output "alarm_arns" {
  description = "CloudWatch alarm ARNs"
  value       = [aws_cloudwatch_metric_alarm.cpu_high.arn]
}
