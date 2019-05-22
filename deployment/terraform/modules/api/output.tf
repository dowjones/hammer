output "ApiUrl" {
    value = "${lookup(aws_cloudformation_stack.api.outputs, "ApiUrl", "not_present_yet")}"
}