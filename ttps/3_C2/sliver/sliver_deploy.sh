#Create deploy.sh in '/root/red_team_infra/deploy.sh' | chmod +x deploy.sh | run ./deploy.sh
#Perform 'terraform destroy' when you want to teardown the infrastructure.
#Version 1.2

#!/bin/bash

set -e

# Function to install Terraform
install_terraform() {
    echo "Installing Terraform..."
    sudo apt-get update && sudo apt-get install -y gnupg software-properties-common curl
    curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
    sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
    sudo apt-get update && sudo apt-get install terraform
}

# Function to install AWS CLI
install_awscli() {
    echo "Installing AWS CLI..."
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    sudo ./aws/install
    rm -rf aws awscliv2.zip
}

# Check and install required tools
for cmd in terraform aws; do
    if ! command -v "$cmd" &> /dev/null; then
        read -p "$cmd is not installed. Do you want to install it? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if [ "$cmd" == "terraform" ]; then
                install_terraform
            elif [ "$cmd" == "aws" ]; then
                install_awscli
            fi
        else
            echo "Error: $cmd is required but not installed. Exiting."
            exit 1
        fi
    fi
done

# Prompt for AWS credentials if not set
if [ -z "$AWS_ACCESS_KEY_ID" ]; then
    read -p "Enter your AWS Access Key ID: " AWS_ACCESS_KEY_ID
    export AWS_ACCESS_KEY_ID
fi

if [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
    read -p "Enter your AWS Secret Access Key: " -s AWS_SECRET_ACCESS_KEY
    echo
    export AWS_SECRET_ACCESS_KEY
fi

# Prompt for AWS region
read -p "Enter your preferred AWS region (default: us-east-1): " AWS_REGION
AWS_REGION=${AWS_REGION:-us-east-1}

# Prompt for user's IP
read -p "Enter your IP address for SSH access (e.g., 123.456.789.0): " YOUR_IP

# Create necessary directories
mkdir -p terraform/scripts

# Create Sliver C2 setup script
cat << EOF > terraform/scripts/sliver_c2_setup.sh
#!/bin/bash
apt-get update
apt-get install -y curl jq

# Download and install Sliver server
sudo curl -s https://api.github.com/repos/BishopFox/sliver/releases/latest \
    | jq -r '.assets[] | select(.name == "sliver-server_linux") | .browser_download_url' \
    | sudo xargs -I {} wget -O /usr/local/bin/sliver-server {}
sudo chmod 755 /usr/local/bin/sliver-server

# Unpack Sliver assets
sudo sliver-server unpack --force

# Generate Sliver client config
PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
sudo sliver-server operator --name red_team_operator --lhost $PRIVATE_IP --save /home/ubuntu
sudo chown ubuntu:ubuntu /home/ubuntu/red_team_operator*.cfg

# Create systemd service for Sliver
cat <<EOT | sudo tee /etc/systemd/system/sliver-server.service
[Unit]
Description=Sliver C2 Server
After=network.target

[Service]
ExecStart=/usr/local/bin/sliver-server daemon
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOT

# Start and enable Sliver service
sudo systemctl daemon-reload
sudo systemctl start sliver-server
sudo systemctl enable sliver-server
EOF

# Create redirector setup script (if needed)
cat << EOF > terraform/scripts/redirector_setup.sh
#!/bin/bash
apt-get update 
apt-get install -y nginx 
systemctl start nginx 
systemctl enable nginx 

cat <<EOT > /etc/nginx/nginx.conf 
events { 
    worker_connections 1024; 
} 
http { 
    server { 
        listen 80; 
        server_name _; 
        location / { 
            proxy_pass http://\${sliver_c2_ip}; 
            proxy_set_header Host \$host; 
            proxy_set_header X-Real-IP \$remote_addr; 
        } 
    } 
} 
EOT 

systemctl restart nginx 
EOF

# Create attacker workstation setup script 
cat << EOF > terraform/scripts/attacker_setup.sh 
#!/bin/bash 
apt-get update 
apt-get install -y nmap curl jq 

# Install Sliver client 
sudo curl -s https://api.github.com/repos/BishopFox/sliver/releases/latest \
    | jq -r '.assets[] | select(.name == "sliver-client_linux") | .browser_download_url' \
    | sudo xargs -I {} wget -O /usr/local/bin/sliver-client {} 
sudo chmod 755 /usr/local/bin/sliver-client 

# Create Sliver client config directory 
mkdir -p /home/ubuntu/.sliver-client/configs 
mkdir -p /home/ubuntu/.ssh 

# Copy the Sliver server certificate 
scp -i /home/ubuntu/.ssh/id_rsa -o StrictHostKeyChecking=no ubuntu@\${sliver_c2_ip}:/home/ubuntu/red_team_operator*.cfg /home/ubuntu/.sliver-client/configs/

# Import the config file 
sudo sliver-client import /home/ubuntu/.sliver-client/configs/red_team_operator*.cfg 

chown -R ubuntu:ubuntu /home/ubuntu/.sliver-client 
EOF

# Create Terraform main configuration file 
cat << EOF > terraform/main.tf 
provider "aws" { 
  region = var.aws_region 
} 

resource "aws_vpc" "red_team_vpc" { 
  cidr_block           = "10.0.0.0/16" 
  enable_dns_hostnames = true 
  tags = { 
    Name = "Red Team VPC" 
  } 
} 

resource "aws_internet_gateway" "red_team_igw" { 
  vpc_id = aws_vpc.red_team_vpc.id 
  tags = { 
    Name = "Red Team IGW" 
  } 
} 

resource "aws_subnet" "red_team_subnet" { 
  vpc_id                  = aws_vpc.red_team_vpc.id 
  cidr_block              = "10.0.1.0/24" 
  map_public_ip_on_launch = true 
  availability_zone       = "\${var.aws_region}a" 
  tags = { 
    Name = "Red Team Subnet" 
  } 
} 

resource "aws_route_table" "red_team_rt" { 
  vpc_id = aws_vpc.red_team_vpc.id 
  route { 
    cidr_block = "0.0.0.0/0" 
    gateway_id = aws_internet_gateway.red_team_igw.id 
  } 
  tags = { 
    Name = "Red Team Route Table" 
  } 
} 

resource "aws_route_table_association" "red_team_rta" { 
  subnet_id      = aws_subnet.red_team_subnet.id 
  route_table_id = aws_route_table.red_team_rt.id 
} 

resource "aws_security_group" "red_team_sg" { 
  name        = "red-team-sg" 
  description = "Security group for Red Team infrastructure" 
  vpc_id      = aws_vpc.red_team_vpc.id 

  ingress { 
    from_port   = 22 
    to_port     = 22 
    protocol    = "tcp" 
    cidr_blocks = ["\${var.your_ip}/32", "10.0.0.0/16"] 
  } 

  ingress { 
    from_port   = 80  
    to_port     = 80  
    protocol    = "tcp"  
    cidr_blocks = ["0.0.0.0/0"]  
  } 

  ingress {  
    from_port   = 443  
    to_port     = 443  
    protocol    = "tcp"  
    cidr_blocks = ["0.0.0.0/0"]  
  } 

  ingress {  
    from_port   = 31337  
    to_port     = 31337  
    protocol    = "tcp"  
    cidr_blocks = ["10.0.0.0/16"]  
  } 

  egress {  
    from_port   = 0  
    to_port     = 0  
    protocol    = "-1"  
    cidr_blocks = ["0.0.0.0/0"]  
  } 

tags = {   
Name = "Red Team Security Group"
}
}

resource "aws_key_pair" "red_team_key" {
key_name   = "red-team-key"
public_key = file("\${path.module}/id_rsa.pub")
}

resource "aws_instance" "sliver_c2" {
ami                         = var.ami_id    
instance_type               = "t2.micro"
key_name                    = aws_key_pair.red_team_key.key_name    
vpc_security_group_ids      = [aws_security_group.red_team_sg.id]    
subnet_id                   = aws_subnet.red_team_subnet.id    
associate_public_ip_address = true    

user_data                   = file("\${path.module}/scripts/sliver_c2_setup.sh")    

tags                        ={    
Name ="Sliver C2 Server"
}
}

resource "aws_instance" "redirector" {
ami                         = var.ami_id    
instance_type               ="t2.micro"
key_name                    = aws_key_pair.red_team_key.key_name    
vpc_security_group_ids      =[aws_security_group.red_team_sg.id]    
subnet_id                   =aws_subnet.red_team_subnet.id    
associate_public_ip_address=true    

user_data                   =templatefile("\${path.module}/scripts/redirector_setup.sh", {
sliver_c2_ip= aws_instance.sliver_c2.private_ip    
})

tags                        ={    
Name ="Redirector"
}
}

resource "aws_instance" "attacker_workstation" {
ami                         = var.ami_id    
instance_type               ="t2.micro"
key_name                   = aws_key_pair.red_team_key.key_name    
vpc_security_group_ids      =[aws_security_group.red_team_sg.id]    
subnet_id                   =aws_subnet.red_team_subnet.id    
associate_public_ip_address=true    

user_data                   =templatefile("\${path.module}/scripts/attacker_setup.sh", {
sliver_c2_ip= aws_instance.sliver_c2.private_ip    
})

tags                        ={    
Name ="Attacker Workstation"
}
}

output "vpc_id"{   
value= aws_vpc.red_team_vpc.id   
}

output "subnet_id"{   
value= aws_subnet.red_team_subnet.id   
}

output "sliver_c2_public_ip"{   
value= aws_instance.sliver_c2.public_ip   
}

output "sliver_c2_private_ip"{   
value= aws_instance.sliver_c2.private_ip   
}

output "redirector_public_ip"{   
value= aws_instance.redirector.public_ip   
}

output "redirector_private_ip"{   
value= aws_instance.redirector.private_ip   
}

output "attacker_workstation_public_ip"{   
value= aws_instance.attacker_workstation.public_ip   
}

output "attacker_workstation_private_ip"{   
value= aws_instance.attacker_workstation.private_ip   
}
EOF

# Create Terraform variables file.
cat << EOF > terraform/variables.tf
variable "aws_region" {
  default = "us-east-1"
}

variable "ami_id" {
  default = "ami-0c7217cdde317cfec"  # Ubuntu 22.04 LTS AMI ID for us-east-1
}

variable "your_ip" {
  description = "Your IP address for SSH access"
}
EOF


# Create Terraform tfvars file
cat << EOF > terraform/terraform.tfvars
aws_region = "${AWS_REGION}"
your_ip    = "${YOUR_IP}"
EOF

# Generate SSH key pair
ssh-keygen -t rsa -b 4096 -f terraform/id_rsa -N ""

# Initialize Terraform
cd terraform
terraform init

# Apply Terraform configuration
terraform apply -auto-approve

# Output important information
echo "Infrastructure deployment complete. Here are your resources:"
terraform output

echo "Deployment complete!"

# Distribute SSH key to instances
terraform output -json > output.json
SLIVER_C2_IP=$(jq -r '.sliver_c2_public_ip.value' output.json)
REDIRECTOR_IP=$(jq -r '.redirector_public_ip.value' output.json)
ATTACKER_IP=$(jq -r '.attacker_workstation_public_ip.value' output.json)

for IP in $SLIVER_C2_IP $REDIRECTOR_IP $ATTACKER_IP; do
  scp -i id_rsa -o StrictHostKeyChecking=no id_rsa ubuntu@$IP:/home/ubuntu/.ssh/id_rsa
  ssh -i id_rsa ubuntu@$IP "chmod 600 /home/ubuntu/.ssh/id_rsa"
done

echo "SSH keys distributed to all instances."