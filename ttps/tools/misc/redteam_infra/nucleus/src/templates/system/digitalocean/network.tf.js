export const doNetwork = ({ deploymentId, region }) => `
# Main VPC
resource "digitalocean_vpc" "main" {
  region             = "${region}"
  name = "main-vpc-${deploymentId}"
}
`;
