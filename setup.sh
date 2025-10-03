#!/bin/bash

# Setup the sudo bash environment
chown root:root /mnt/sudo/bash
chmod 6755 /mnt/sudo/bash

# Setup the sudo python environment
chown root:root /mnt/sudo/python
chmod 6755 /mnt/sudo/python

# Setup the signature file if not exists
if [ ! -f /challenge/.signature ]; then
    touch /challenge/.signature
    chown root:root /challenge/.signature
    chmod 644 /challenge/.signature # Readable by all users
fi

# Create and secure the environment file
env > /challenge/.env
chown root:root /challenge/.env
chmod 600 /challenge/.env