output "APIUrl" {
    value = "${lookup(aws_cloudformation_stack.api.outputs, "APIUrl", "not_present_yet")}"
}