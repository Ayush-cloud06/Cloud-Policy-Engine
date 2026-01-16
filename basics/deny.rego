package basics

deny[msg] if {
    input.user != "ayush"
    msg := "Only ayush is authorized"
}

deny[msg] if {
    not input.is_admin
    msg := "Admin access required"
}