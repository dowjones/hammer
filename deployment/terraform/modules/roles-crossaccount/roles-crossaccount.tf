data "template_file" "identification_crossaccount_role" {
    template = "${file("${path.module}/../../../cf-templates/identification-crossaccount-role.json")}"
}

data "template_file" "reporting-remediation-crossaccount-role" {
    template = "${file("${path.module}/../../../cf-templates/reporting-remediation-crossaccount-role.json")}"
}

resource "aws_cloudformation_stack" "identification_crossaccount_role" {
    name = "hammer-identification-crossaccount-role"

    capabilities = [ "CAPABILITY_NAMED_IAM" ]

    parameters {
        ResourcesPrefix = "${var.resources-prefix}"
        MasterAccountID = "${var.masterAccountId}"
        IdentificationCrossAccountIAMRole = "${var.identificationCrossAccountIAMRole}"
    }

    template_body = "${data.template_file.identification_crossaccount_role.rendered}"
}

resource "aws_cloudformation_stack" "reporting-remediation-crossaccount-role" {
    name = "hammer-reporting-remediation-crossaccount-role"

    capabilities = [ "CAPABILITY_NAMED_IAM" ]

    parameters {
        ResourcesPrefix = "${var.resources-prefix}"
        MasterAccountID = "${var.masterAccountId}"
        ReportingRemediationIAMCrossAccountRole = "${var.reportingRemediationIAMCrossAccountRole}"
    }

    template_body = "${data.template_file.reporting-remediation-crossaccount-role.rendered}"
}