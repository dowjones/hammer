variable "s3bucket" {}
variable "identificationIAMRole" {}

variable "resources-prefix" {}

variable "tags" {
    type = "map"
    default = {}
}