FROM node:16
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npx tsc
CMD ["node", "dist/index.js"]
