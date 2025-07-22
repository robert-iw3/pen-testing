export const awsKey = ({ deploymentId, publicKey, keyName }) => `
resource "aws_key_pair" "key_pair" {
  public_key = "${publicKey}"

  tags = {
    Name = "Key Pair (${keyName})"
    forge_deployment = "${deploymentId}"
  }
}
`;
