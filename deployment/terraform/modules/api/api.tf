resource "aws_cloudformation_stack" "api" {
    name = "hammer-api"
    depends_on = [
                  "aws_s3_bucket_object.api-cfn",
                  "aws_s3_bucket_object.api"
                 ]

    tags = "${var.tags}"
    capabilities = [ "CAPABILITY_NAMED_IAM" ]

    parameters {
        SourceS3Bucket  = "${var.s3bucket}"
        ResourcesPrefix = "${var.resources-prefix}"
        ApiIAMRole = "${var.apiIAMRole}"
        SourceApi = "${aws_s3_bucket_object.api.id}",
    }

    template_url = "https://${var.s3bucket}.s3.amazonaws.com/${aws_s3_bucket_object.api-cfn.id}"
}