package kubernetes.admission

vfail[{"rule": "RunAsNonRoot", "severity": "High", "message": "Pod securityContext must enforce runAsNonRoot: true"}] {
    input.kind == "Deployment"
    not input.spec.template.spec.securityContext.runAsNonRoot
}

vfail[{"rule": "RunAsNonRoot", "severity": "High", "message": "Pod securityContext must enforce runAsNonRoot: true"}] {
    input.kind == "Pod"
    not input.spec.securityContext.runAsNonRoot
}

vfail[{"rule": "PrivilegedContainer", "severity": "Critical", "message": sprintf("Container '%v' must not run in privileged mode", [c.name])}] {
    c := all_containers[_]
    c.securityContext.privileged == true
}

vfail[{"rule": "MissingResourceLimits", "severity": "High", "message": sprintf("Container '%v' lacks CPU or Memory limits", [c.name])}] {
    c := all_containers[_]
    not c.resources.limits.cpu
}

vfail[{"rule": "MissingResourceLimits", "severity": "High", "message": sprintf("Container '%v' lacks CPU or Memory limits", [c.name])}] {
    c := all_containers[_]
    not c.resources.limits.memory
}

all_containers[c] {
    c := input.spec.template.spec.containers[_]
}
all_containers[c] {
    c := input.spec.containers[_]
}
