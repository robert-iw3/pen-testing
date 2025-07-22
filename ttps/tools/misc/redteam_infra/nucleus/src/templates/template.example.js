// Forge - Example template
// Created by The Lodestar Forge Team

export const template = {
    name: "example file",

    // Type must be infrastructure, configuration, or file
    type: "file",

    // Platform only required when type is infrastructure. Must be aws or digitalocean
    platform: "aws",

    // only required for type "file"
    extension: "txt",

    // Variables array, type can depend on template type:
    // Default - infrastructure-id text, number, domain, private-ip, tailscale-ip
    // Infrastructure - Default + subnet, vpc (Both of these values are terraform IDs)
    // Configuration - Default + file
    // File - Default
    variables: [
        {
            name: "name",
            type: "text",
        },
    ],

    // Template content
    value: ```
Hello $$name$$, nice to meet you!
```,
};
