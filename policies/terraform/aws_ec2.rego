package policies.terraform.aws_ec2

# Public port for instances 

deny[msg] if {
    sg := input.planned_values.root_module.resources[_]
    sg.type == "aws_security_group"

    rule := sg.values.ingress[_]
    rule.from_port == 22
    rule.to_port == 22
    rule.protocol == "tcp"
    rule.cidr_blocks[_] == "0.0.0.0/0"

    msg := sprintf(
        "security group %s allow SSH (22) from the internet",
        [sg.values.name]
    )
}


# HTTP open to world

deny[msg] if {
    sg := input.planned_values.root_module.resources[_]
    sg.type == "aws_security_group"

    rule := sg.values.ingress[_]
    rule.from_port == 80
    rule.to_port == 80
    rule.protocol == "tcp"
    rule.cidr_blocks[_] == "0.0.0.0/0"

    msg := sprintf(
        "Security group %s allows HTTP (80) from the internet",
        [sg.values.name]
    )
}

# Ec2 must enforce IMDSv2 (http_tokens = "required")

deny[msg] if {
    r := input.planned_values.root_module.resources[_]
    r.type == "aws_instance"

    #metadata_option missing or http_tokens not set to required
    not r.values.metadata_options.http_tokens == "required"

    msg := sprintf(
        "EC2 instance %s does not enforce IMDSv2 (http_token must be 'required)",
        [r.address]
    )
} 


# Instance root volume must be encrypted

deny[msg] if {
    r := input.planned_values.root_module.resources[_]
    r.type == "aws_instance"

    # Iterate over root block devices
    # (from resource_changes)
    disk := r.values.root_block_devices[_]
    not disk.encrypted

    msg := sprintf(
        "EC2 instance %s has an unecnrypted root volume",
        [r.address]
    )
}

# Instances must have  madatory tags of - Environment, Owner, CostCenter

deny[msg] if {
    r := input.planned_values.root_module.resources[_]
    r.type == "aws_instance"

    missing := missing_tags(r.values.tags)
    count(missing) > 0

    msg := sprintf(
        "Ec2 instance %s is missing mandatory tags: %v",
        [r.address, missing]
    )
}

   # Helper function to find missing tags

   missing_tags(tags) = missing if {
    required := {"Environment", "Owner", "CostCenter"}
    present := {k | tags[k]}
    missing := required - present
   }