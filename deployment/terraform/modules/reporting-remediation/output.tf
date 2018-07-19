output "ReportRemediationEC2PublicIP" {
  value = "${lookup(aws_cloudformation_stack.reporting-remediation.outputs, "ReportingRemediationPublicIP", "unknown")}"
}

output "ReportRemediationEC2PrivateIP" {
    value = "${lookup(aws_cloudformation_stack.reporting-remediation.outputs, "ReportingRemediationPrivateIP", "unknown")}"
}