# --- ESTÁGIO 1: Construção (Build) ---
# Usamos uma imagem Node.js para criar os ficheiros estáticos da aplicação React
FROM node:18-alpine AS build

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .

# O comando que gera a pasta 'dist' com os ficheiros de produção
RUN npm run build


# --- ESTÁGIO 2: Servidor (Serve) ---
# Usamos uma imagem oficial do Nginx, que é leve e otimizada
FROM nginx:stable-alpine

# Copia os ficheiros estáticos construídos no estágio anterior para a pasta pública do Nginx
COPY --from=build /app/dist /usr/share/nginx/html

# Remove a configuração padrão do Nginx
RUN rm /etc/nginx/conf.d/default.conf

# Copia o nosso ficheiro de configuração personalizado do Nginx para dentro do contentor
# Este ficheiro é crucial para o proxy e para o React Router funcionar corretamente
COPY nginx.conf /etc/nginx/conf.d

# Expõe a porta 80, que é a porta padrão para tráfego web
EXPOSE 80

# O comando para iniciar o servidor Nginx
CMD ["nginx", "-g", "daemon off;"]