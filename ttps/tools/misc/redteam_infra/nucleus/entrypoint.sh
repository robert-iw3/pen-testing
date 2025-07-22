#!/bin/sh

getent hosts postgres >> /etc/hosts

# Start tailscaled in the background
tailscaled &

# Wait for the database to be ready
until nc -z postgres 5432; do
  echo "Waiting for the database to be ready..."
  sleep 2
done

# Run schema push
npm run drizzle:push

# Seed the database
npm run drizzle:seed

# Start the application
npm run nucleus:start
