#!/bin/sh

# Wait for the database to be ready
until nc -z postgres 5432; do
  echo "Waiting for the database to be ready..."
  sleep 2
done

supercronic /app/run.crontab
