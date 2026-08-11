terraform {
  required_version = ">= 1.0.0"
}

resource "aws_security_group" "synthetic" {
  name = "vcg-synthetic"
  ingress { cidr_blocks = ["0.0.0.0/0"] from_port = 8080 to_port = 8080 protocol = "tcp" }
}
