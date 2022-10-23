    benchmark "isms" {
    title = "Organisational ISMS Dashboard"

    children = [
        benchmark.iam,
        benchmark.inf,
        benchmark.sec,
        benchmark.vul
    ]
    
}

benchmark "iam" { 
    title = "Identity and Access Management"

    children = [
        control.IAM_001,
        control.IAM_002
    ]
}

benchmark "inf" { 
    title = "Infrastructure"

    children = [
        control.INF_001,
        control.INF_002,
        control.INF_003
    ]
}

benchmark "sec" {
    title = "Security"

    children = [
        control.SEC_002
    ]
}

benchmark "vul" {
    title = "Vulnerability Management"

    children = [
        control.VUL_001,
        control.VUL_002
    ]
}