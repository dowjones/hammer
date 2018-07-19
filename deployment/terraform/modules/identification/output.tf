output "lambdaLogsForwarderArn" {
    value = "${lookup(aws_cloudformation_stack.identification.outputs, "LambdaLogsForwarderArn", "not_present_yet")}"
}