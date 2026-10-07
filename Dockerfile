FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV TRUST_PROXY=1
COPY package.json ./
RUN npm install --omit=dev
COPY server.mjs ./
COPY server ./server
EXPOSE 3000
CMD ["node", "server.mjs"]
