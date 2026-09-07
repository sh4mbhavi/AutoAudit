# Frontend Dockerfile
# Digest-pinned. `24-alpine` is a moving tag; .nvmrc pins the major and this
# pins the image the major arrives in.
FROM node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf

WORKDIR /app

# Transfer ownership of the app directory to the user node
RUN chown -R node:node /app

# Copy package files with node as the owner
COPY --chown=node:node package.json package-lock.json* ./

# Switch to a non-root user (node) for security
USER node

# Install dependencies
RUN npm ci

# Copy application code with node as the owner
COPY --chown=node:node . .

# Expose port
EXPOSE 3000

# Run development server
CMD ["npm", "start"]
