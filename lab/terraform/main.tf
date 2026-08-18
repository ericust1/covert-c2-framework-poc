provider "aws" {
  region = var.aws_region
}

resource "aws_vpc" "c2_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "c2-framework-vpc"
    Project     = "covert-c2-poc"
    Environment = "lab"
  }
}

resource "aws_internet_gateway" "c2_igw" {
  vpc_id = aws_vpc.c2_vpc.id

  tags = {
    Name = "c2-framework-igw"
  }
}

resource "aws_subnet" "c2_public" {
  vpc_id                  = aws_vpc.c2_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "c2-framework-subnet-public"
  }
}

resource "aws_route_table" "c2_public_rt" {
  vpc_id = aws_vpc.c2_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.c2_igw.id
  }
}

resource "aws_route_table_association" "c2_rta" {
  subnet_id      = aws_subnet.c2_public.id
  route_table_id = aws_route_table.c2_public_rt.id
}

resource "aws_security_group" "c2_sg" {
  name        = "c2-framework-sg"
  description = "Security group for C2 server allowing DNS, HTTPS, and management ports"
  vpc_id      = aws_vpc.c2_vpc.id

  ingress {
    description = "DNS (UDP)"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "DNS (TCP)"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "C2 Management"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.allowed_mgmt_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_route53_hosted_zone" "c2_zone" {
  name = var.dns_tunnel_domain

  tags = {
    Name = "c2-framework-dns-zone"
  }
}

data "aws_acm_certificate" "c2_cert" {
  domain      = var.c2_domain
  statuses    = ["ISSUED"]
  most_recent = true
}

resource "aws_instance" "c2_server" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.c2_public.id
  vpc_security_group_ids = [aws_security_group.c2_sg.id]

  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y python3 python3-pip gcc libcurl4-openssl-dev libssl-dev bind9
              pip3 install flask cryptography requests psutil
              EOF

  tags = {
    Name = "c2-framework-server"
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

resource "aws_route53_record" "c2_a_record" {
  zone_id = aws_route53_hosted_zone.c2_zone.zone_id
  name    = "server.${var.dns_tunnel_domain}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.c2_server.public_ip]
}

resource "aws_route53_record" "c2_ns_record" {
  zone_id = aws_route53_hosted_zone.c2_zone.zone_id
  name    = var.dns_tunnel_domain
  type    = "NS"
  ttl     = 172800
  records = aws_route53_hosted_zone.c2_zone.name_servers
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "dns_tunnel_domain" {
  type    = string
  default = "c2.example.com"
}

variable "c2_domain" {
  type    = string
  default = "c2.example.com"
}

variable "allowed_mgmt_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

output "c2_server_ip" {
  value = aws_instance.c2_server.public_ip
}

output "dns_zone_id" {
  value = aws_route53_hosted_zone.c2_zone.zone_id
}

output "ns_servers" {
  value = aws_route53_hosted_zone.c2_zone.name_servers
}
