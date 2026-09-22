# Web image. Build from the REPO ROOT:
#   docker build -f frontend-developer/Dockerfile --build-arg VITE_API_URL=http://localhost:8000 -t ipsec-analyzer-web .
FROM node:22-alpine AS build
WORKDIR /app
COPY frontend-developer/package.json frontend-developer/package-lock.json ./
RUN npm ci
COPY frontend-developer/ .
# The API address is baked into the JavaScript at build time (Vite).
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

FROM nginx:1.27-alpine
COPY frontend-developer/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
