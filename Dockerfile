FROM node:18-buster-slim AS builder
WORKDIR /app
COPY package*.json .

RUN npm ci

COPY . .

CMD ["npm", "run", "build"]

FROM gcr.io/distroless/nodejs18-debian11
COPY --from=builder /app /app
WORKDIR /app
CMD ["dist/main.js"]