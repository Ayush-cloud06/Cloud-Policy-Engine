package basics

deny[msg] if {
    r := input.resources[_]
    r.resource_type == "aws_s3_bucket"
    r.acl == "public-read"
    msg := sprintf("s3 bucket %s is public", [r.name])
}

deny[msg] if {
    r := input.resources[_]
    r.resource_type == "aws_s3_bucket"
    not r.encrypted
    msg := sprintf("s3 bucket %s is not encrypted", [r.name])
}


 # Test command : 
 # opa eval --input basics/bucket.json --data basics/s3.rego "data.basics.deny"

            # "s3 bucket my-bucket is not encrypted": true,
            # "s3 bucket my-bucket is public": true
         