FROM node:18-alpine

WORKDIR /app

# Create blank project
RUN npm init -y

# Install dependencies
RUN npm i drizzle-orm postgres argon2
RUN npm i -D drizzle-kit

# This is seperate due to cross compilation issues
RUN npm i esbuild-register --legacy-peer-deps

COPY drizzle.config.js .
COPY ./src/lib/crypto.js ./src/lib/crypto.js
COPY ./src/lib/schema/ ./src/lib/schema/
COPY ./studio-entrypoint.sh .

# Note: Don't expose ports here, Compose will handle that for us

CMD ["sh", "/app/studio-entrypoint.sh"]
