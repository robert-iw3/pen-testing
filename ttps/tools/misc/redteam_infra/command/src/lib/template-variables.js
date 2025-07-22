const commonVariableTypes = [
    { value: "infrastructure-id", label: "Infrastructure ID" },
    {
        value: "domain",
        label: "Domain",
    },
    {
        value: "private-ip",
        label: "Host (Private IP)",
    },
    {
        value: "public-ip",
        label: "Host (Public IP)",
    },
    {
        value: "tailscale-ip",
        label: "Host (Tailscale IP)",
    },
    {
        value: "number",
        label: "Number",
    },
    {
        value: "text",
        label: "Text",
    },
];

export const infrastructureVariableTypes = [
    ...commonVariableTypes,
    {
        value: "subnet",
        label: "Subnet ID",
    },
    {
        value: "vpc",
        label: "VPC ID",
    },
];

export const configurationVariableTypes = [
    ...commonVariableTypes,
    {
        value: "file",
        label: "File",
    },
];

export const fileVariableTypes = [...commonVariableTypes];
