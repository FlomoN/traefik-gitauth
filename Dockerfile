FROM node:12-alpine

WORKDIR /app

ADD . /app

RUN npm i
RUN npx tsc

CMD node src/index.ts