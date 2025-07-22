export const tailscaleUserData = ({
    authKey,
    resourceId,
    resourceName,
    custom = "",
}) => `
#!/bin/bash

export DEBIAN_FRONTEND=noninteractive

# Install tailscale
curl -fsSL https://tailscale.com/install.sh | sh

tailscale up --auth-key=${authKey} --hostname=${
    String(resourceName + "-" + resourceId.split("-")[0])
        .toLowerCase() // Lowercase everything
        .replace(/[^a-z0-9-]+/g, "-") // Replace invalid characters with hyphen
        .replace(/^-+|-+$/g, "") // Trim leading/trailing hyphens
        .replace(/-+/g, "-") // Collapse multiple hyphens
        .slice(0, 63) // Trim to 63 characters max
}

${custom}
`;
