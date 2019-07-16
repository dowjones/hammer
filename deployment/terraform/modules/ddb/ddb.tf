resource "aws_dynamodb_table" "credentials" {

    name = "${var.resources-prefix}credentials"
    read_capacity  = 25
    write_capacity = 2
    hash_key       = "service"

    attribute {
        name = "service"
        type = "S"
    }

    server_side_encryption {
        enabled = true
    }
}

resource "aws_dynamodb_table" "cloudtrails" {
    depends_on = ["aws_dynamodb_table.credentials" ]

    name = "${var.resources-prefix}cloudtrails"
    read_capacity  = 20
    write_capacity = 4
    hash_key       = "account_id"
    range_key      = "issue_id"

    attribute {
        name = "account_id"
        type = "S"
    }

    attribute {
        name = "issue_id"
        type = "S"
    }
}

resource "aws_dynamodb_table" "insecure-sg-dynamodb-table" {

    depends_on = ["aws_dynamodb_table.credentials" ]

    name = "${var.resources-prefix}security-groups-unrestricted"
    read_capacity  = 20
    write_capacity = 4
    hash_key       = "account_id"
    range_key      = "issue_id"

    attribute {
        name = "account_id"
        type = "S"
    }

    attribute {
        name = "issue_id"
        type = "S"
    }
}

resource "aws_dynamodb_table" "s3-public-bucket-acl" {

    depends_on = ["aws_dynamodb_table.credentials" ]

    name = "${var.resources-prefix}s3-public-bucket-acl"
    read_capacity  = 20
    write_capacity = 4
    hash_key       = "account_id"
    range_key      = "issue_id"

    attribute {
        name = "account_id"
        type = "S"
    }

    attribute {
        name = "issue_id"
        type = "S"
    }
}

resource "aws_dynamodb_table" "s3-public-bucket-policy" {

    depends_on = ["aws_dynamodb_table.credentials" ]

    name = "${var.resources-prefix}s3-public-bucket-policy"
    read_capacity  = 20
    write_capacity = 4
    hash_key       = "account_id"
    range_key      = "issue_id"

    attribute {
        name = "account_id"
        type = "S"
    }

    attribute {
        name = "issue_id"
        type = "S"
    }
}

resource "aws_dynamodb_table" "iam-user-keys-rotation" {

    depends_on = ["aws_dynamodb_table.credentials" ]

    name = "${var.resources-prefix}iam-user-keys-rotation"
    read_capacity  = 20
    write_capacity = 4
    hash_key       = "account_id"
    range_key      = "issue_id"

    attribute {
        name = "account_id"
        type = "S"
    }

    attribute {
        name = "issue_id"
        type = "S"
    }
}

resource "aws_dynamodb_table" "iam-user-keys-inactive" {

    depends_on = ["aws_dynamodb_table.credentials" ]

    name = "${var.resources-prefix}iam-user-keys-inactive"
    read_capacity  = 20
    write_capacity = 4
    hash_key       = "account_id"
    range_key      = "issue_id"

    attribute {
        name = "account_id"
        type = "S"
    }

    attribute {
        name = "issue_id"
        type = "S"
    }
}

resource "aws_dynamodb_table" "ebs-volumes-unencrypted" {

    depends_on = ["aws_dynamodb_table.credentials" ]

    name = "${var.resources-prefix}ebs-volumes-unencrypted"
    read_capacity  = 20
    write_capacity = 4
    hash_key       = "account_id"
    range_key      = "issue_id"

    attribute {
        name = "account_id"
        type = "S"
    }

    attribute {
        name = "issue_id"
        type = "S"
    }
}

resource "aws_dynamodb_table" "rds-public-snapshots" {

    depends_on = ["aws_dynamodb_table.credentials" ]

    name = "${var.resources-prefix}rds-public-snapshots"
    read_capacity  = 20
    write_capacity = 4
    hash_key       = "account_id"
    range_key      = "issue_id"

    attribute {
        name = "account_id"
        type = "S"
    }

    attribute {
        name = "issue_id"
        type = "S"
    }
}

resource "aws_dynamodb_table" "sqs-public-access" {

    depends_on = ["aws_dynamodb_table.credentials" ]

    name = "${var.resources-prefix}sqs-public-access"
    read_capacity  = 20
    write_capacity = 4
    hash_key       = "account_id"
    range_key      = "issue_id"

    attribute {
        name = "account_id"
        type = "S"
    }

    attribute {
        name = "issue_id"
        type = "S"
    }
}

resource "aws_dynamodb_table" "s3-unencrypted" {

    depends_on = ["aws_dynamodb_table.credentials" ]

    name = "${var.resources-prefix}s3-unencrypted"
    read_capacity  = 20
    write_capacity = 4
    hash_key       = "account_id"
    range_key      = "issue_id"

    attribute {
        name = "account_id"
        type = "S"
    }

    attribute {
        name = "issue_id"
        type = "S"
    }
}

resource "aws_dynamodb_table" "rds-unencrypted" {

    depends_on = ["aws_dynamodb_table.credentials" ]

    name = "${var.resources-prefix}rds-unencrypted"
    read_capacity  = 20
    write_capacity = 4
    hash_key       = "account_id"
    range_key      = "issue_id"

    attribute {
        name = "account_id"
        type = "S"
    }

    attribute {
        name = "issue_id"
        type = "S"
    }
}

resource "aws_dynamodb_table" "ec2-public-ami" {

    depends_on = ["aws_dynamodb_table.credentials" ]

    name = "${var.resources-prefix}ec2-public-ami"
    read_capacity  = 20
    write_capacity = 4
    hash_key       = "account_id"
    range_key      = "issue_id"

    attribute {
        name = "account_id"
        type = "S"
    }

    attribute {
        name = "issue_id"
        type = "S"
    }
}


resource "aws_dynamodb_table" "api-requests" {

    depends_on = ["aws_dynamodb_table.credentials" ]

    name = "${var.resources-prefix}api-requests"
    read_capacity  = 20
    write_capacity = 4
    hash_key       = "request_id"

    attribute {
        name = "request_id"
        type = "S"
    }
}

