FROM node:20-slim AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# Vite 的 import.meta.env.VITE_* 是 build time 就會被替換掉的常數,不是
# runtime 讀的環境變數——這裡的預設值只在沒有指定 --build-arg 時生效,
# 實際部署要打對外的 backend 網址,build image 時務必帶
# --build-arg VITE_API_BASE_URL=https://實際網址。
ARG VITE_API_BASE_URL=http://localhost:8000
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
