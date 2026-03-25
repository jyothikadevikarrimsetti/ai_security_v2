# Dashboard - React + Vite + TypeScript
# Multi-stage build | Node 18 + Nginx

# -- Stage 1: Build -------------------------------------------------------
FROM node:18-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# -- Stage 2: Serve with Nginx --------------------------------------------
FROM nginx:alpine

# Copy built assets from builder
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom nginx config for API proxying
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]
