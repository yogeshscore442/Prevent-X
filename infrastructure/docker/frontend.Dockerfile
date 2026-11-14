# ==============================================================================
# PREVENT-X Enterprise Frontend Dockerfile
# Multi-stage build with Node 22 & hardened Nginx runtime
# ==============================================================================

# Stage 1: Build static distribution
FROM node:22-alpine AS build

WORKDIR /app

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# Stage 2: Serve via unprivileged lightweight Nginx
FROM nginx:alpine-slim

# Remove default nginx static assets
RUN rm -rf /usr/share/nginx/html/*

# Copy compiled frontend from build stage
COPY --from=build /app/dist /usr/share/nginx/html

# Copy internal container nginx config for SPA routing
COPY infrastructure/nginx/frontend-spa.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=20s --timeout=3s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]

