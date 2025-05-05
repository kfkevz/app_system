FROM node:18

WORKDIR /app

# Copy package.json and install deps first (better for Docker cache)
COPY package.json . 
RUN npm install

# Now copy the rest of the app files (including index.html and index.js)
COPY . .

EXPOSE 5000

CMD ["node", "index.js"]
