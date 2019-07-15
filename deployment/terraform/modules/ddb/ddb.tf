module "hammer_ddb" {
    source    = "../../../../tf_templates/ddb"
    tags = "${var.tags}"
    parameters {
        ResourcesPrefix = "${var.resources-prefix}"

    }
}

