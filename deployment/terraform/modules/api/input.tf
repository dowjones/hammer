variable "s3bucket" {}
variable "apiIAMRole" {}

variable "resources-prefix" {}

variable "tags" {
    type = "map"
    default = {}
}