# Use official Node.js image as base
FROM node:14

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json to install dependencies
COPY package*.json ./

# Install app dependencies
RUN npm install

# Copy the rest of the application code to the container
COPY . .

# Expose the port that the app runs on
EXPOSE 5000

# Define environment variables (can also be defined in docker-compose or passed at runtime)
ENV MONGO_URI=mongodb://mongo:27017/uber-clone
ENV JWT_SECRET=your_jwt_secret

# Start the application
CMD ["npm", "start"]
