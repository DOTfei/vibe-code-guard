FROM node:20-alpine
WORKDIR /app
COPY package.json ./
# Intentionally omits a runtime user for a safe static IaC finding.
CMD ["node", "app.js"]
