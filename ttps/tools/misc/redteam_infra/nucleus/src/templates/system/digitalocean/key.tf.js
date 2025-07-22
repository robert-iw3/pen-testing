export const doKey = ({ deploymentId, publicKey, keyName }) => `
resource "digitalocean_ssh_key" "key_pair" {
  name       = "${keyName.toLowerCase().replaceAll(" ", "-")}-${deploymentId}"
  public_key = "${publicKey}"
}
`;
