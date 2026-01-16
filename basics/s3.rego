package basics

deny[msg] if {
    input.resource_type == "aws_s3_bucket"
    input.acl == "public-read"
    msg := sprintf("s3 bucket %s is public", [input.name])
}

deny[msg] if {
    input.resource_type == "aws_s3_bucket"
    not input.encrypted
    msg := sprintf("s3 bucket %s is not encrypted", [input.name])
}