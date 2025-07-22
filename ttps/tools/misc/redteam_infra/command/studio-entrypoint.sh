#!/bin/sh

# Wait for the database to be ready
until nc -z 127.0.0.1 5432; do
  echo "Waiting for the database to be ready..."
  sleep 2
done

# Run Drizzle studio
npx drizzle-kit studio --verbose --host 0.0.0.0
