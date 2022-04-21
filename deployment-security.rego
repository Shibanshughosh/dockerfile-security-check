# File: mychart/deployment-security.rego

package main

deny[msg] {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg := "Containers must not run as root"
}

deny[msg] {
  input.kind == "Deployment"
  not input.spec.selector.matchLabels.app

  msg := "Containers must provide app label for pod selectors"
}

deny[msg] {
input.kind == "Deployment"
  image := input.spec.template.spec.containers[_].image
  not startswith(image, "verizon.com/")
  msg := sprintf("image '%v' doesn't come from verizon.com repository", [image])
}