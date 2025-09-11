FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* pnpm-lock.yaml* yarn.lock* ./
RUN if [ -f pnpm-lock.yaml ]; then npm i -g pnpm && pnpm i --frozen-lockfile; \
    elif [ -f yarn.lock ]; then yarn install --frozen-lockfile; \
    elif [ -f package-lock.json ]; then npm ci; else npm i; fi
COPY . .
RUN npm run build || (echo "No build script, creating static index" && mkdir -p dist && echo '<!doctype html><html><head><meta charset="utf-8"><title>AI Proxy Logs UI</title></head><body><div id="root">Connect to Logs API</div></body></html>' > dist/index.html)

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]


