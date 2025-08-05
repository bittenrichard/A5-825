# --- ESTÁGIO 1: Construção (Build) ---
# Usamos uma imagem Node.js para instalar dependências e compilar o TypeScript
FROM node:18-alpine AS build

# Define o diretório de trabalho dentro do contentor
WORKDIR /usr/src/app

# Copia os ficheiros de definição do projeto
COPY package*.json ./

# Instala todas as dependências, incluindo as de desenvolvimento para a compilação
RUN npm install

# Copia todo o código fonte do backend para o contentor
COPY . .

# Compila o código TypeScript para JavaScript
RUN npm run build


# --- ESTÁGIO 2: Produção (Production) ---
# Usamos uma imagem mais leve para rodar a aplicação já compilada
FROM node:18-alpine

WORKDIR /usr/src/app

# Copia os ficheiros de definição do projeto novamente
COPY package*.json ./

# Instala APENAS as dependências de produção, resultando numa imagem final mais pequena
RUN npm install --omit=dev

# Copia o código JavaScript compilado do estágio de construção
COPY --from=build /usr/src/app/dist-server ./dist-server

# Expõe a porta que o seu servidor usa
EXPOSE 3001

# O comando para iniciar o servidor quando o contentor arrancar
CMD [ "node", "dist-server/server.js" ]