FROM node:20

RUN mkdir -p /app

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

COPY .env .env

EXPOSE 5000

CMD [ "npm", "run", "start" ]
