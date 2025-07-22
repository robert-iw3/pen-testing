export const awsNetwork = ({ deploymentId }) => `
# Main VPC
resource "aws_vpc" "main" {
  cidr_block           = "192.168.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "Main VPC"
    forge_deployment = "${deploymentId}"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "internet_gateway" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "Internet Gateway"
    forge_deployment = "${deploymentId}"
  }
}

# Subnets
resource "aws_subnet" "public_subnet" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "192.168.1.0/24"

  tags = {
    Name = "Public Subnet"
    forge_deployment = "${deploymentId}"
  }
}

resource "aws_subnet" "private_subnet" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "192.168.2.0/24"

  tags = {
    Name = "Private Subnet"
    forge_deployment = "${deploymentId}"
  }
}

resource "aws_eip" "nat_gateway_eip" {
  domain = "vpc"

  tags = {
    Name = "NAT Gateway EIP"
    forge_deployment = "${deploymentId}"
  }
}

# NAT Gateway
resource "aws_nat_gateway" "nat_gateway" {
  allocation_id = aws_eip.nat_gateway_eip.id
  subnet_id     = aws_subnet.public_subnet.id
  depends_on    = [aws_internet_gateway.internet_gateway]

  tags = {
    Name = "NAT Gateway"
    forge_deployment = "${deploymentId}"
  }
}

# Routing
# Route to internet via internet gateway
resource "aws_route_table" "internet" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.internet_gateway.id
  }

  tags = {
    Name = "Route Table (To Internet)"
    forge_deployment = "${deploymentId}"
  }
}

# Route to internet via NAT gateway (egress)
resource "aws_route_table" "nat_gateway" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gateway.id
  }

  tags = {
    Name = "Route Table (Via NAT)"
    forge_deployment = "${deploymentId}"
  }
}

# Route public subnet to the internet
resource "aws_route_table_association" "public_subnet" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.internet.id
}

# Route private subnet through NAT gateway
resource "aws_route_table_association" "private_subnet" {
  subnet_id      = aws_subnet.private_subnet.id
  route_table_id = aws_route_table.nat_gateway.id
}
`;
