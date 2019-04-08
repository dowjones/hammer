output "ReportingRemediationPublicIP" {
  value = "${lookup(aws_cloudformation_stack.reporting-remediation.outputs, "ReportingRemediationPublicIP", "unknown")}"
}

output "ReportingRemediationPrivateIP" {
    value = "${lookup(aws_cloudformation_stack.reporting-remediation.outputs, "ReportingRemediationPrivateIP", "unknown")}"
}