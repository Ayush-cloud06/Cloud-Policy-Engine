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

