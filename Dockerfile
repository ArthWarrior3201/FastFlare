FROM node:22-alpine
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY docs ./docs
COPY config ./config
ENV NODE_ENV=production PORT=8787
EXPOSE 8787/tcp 123/udp
USER root
CMD ["node", "src/server.js"]
