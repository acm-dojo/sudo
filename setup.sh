#!/bin/bash

# Setup the sudo bash environment
chown root:root /mnt/sudo/bash
chmod 4755 /mnt/sudo/bash

# Setup the signature file if not exists
if [ ! -f /challenge/.signature ]; then
    touch /challenge/.signature
    chown root:root /challenge/.signature
    chmod 644 /challenge/.signature # Readable by all users
fi