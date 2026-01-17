package policies.terraform.aws_iam

# No IAM policy should allow wildcard permissions

deny[msg] if {
    r := input.planned_values.root_module.resources[_]
    r.type in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"}

    policy := json.unmarshal(r.values.policy)
    stmt := policy.statement[_]

    stmt.Effect == "Allow"
    stmt.Action == "*"

    msg := sprintf(
        "IAM policy %s allows wildcard action '*'",
        [r.address]
    )
}