resource "aws_cloudformation_stack" "hammer_ddb" {
    name = "hammer-ddb-creation"

    tags = "${var.tags}"

    parameters {
        ResourcesPrefix = "${var.resources-prefix}"
    }

    template_url = "https://${var.s3bucket}.s3.amazonaws.com/${aws_s3_bucket_object.ddb-cfn.id}"
}