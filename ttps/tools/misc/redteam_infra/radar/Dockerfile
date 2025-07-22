FROM docker.io/node:18-alpine
WORKDIR /app

RUN apk update; apk add --no-cache supercronic
COPY package.json package-lock.json* ./
RUN npm ci

COPY . .

CMD ["sh", "/app/entrypoint.sh"]
