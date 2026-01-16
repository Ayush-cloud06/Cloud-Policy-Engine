package basics

default allow = false

allow if {
    input.user == "ayush"
}

deny[msg] if {
    input.user != "ayush"
    msg := "Only ayush is allowed"
}