FROM node:22-alpine
WORKDIR /opt/spectyn
COPY package.json LICENSE ./
COPY bin ./bin
COPY src ./src
COPY examples ./examples
USER node
WORKDIR /work
ENTRYPOINT ["node", "/opt/spectyn/bin/spectyn.mjs"]
CMD ["--help"]
