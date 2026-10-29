FROM registry.access.redhat.com/ubi10/nodejs-22-minimal:10.2
WORKDIR /app

# Zero external dependencies - only Node core modules are used, so no
# package.json / npm install step is needed.
COPY --chown=1001:0 server.js ./

EXPOSE 8080

# Run as the base image's default non-root user. This service parses
# untrusted input (cookies, query strings, POST bodies) straight off the
# network, so it should never run as root in the container.
USER 1001

CMD ["node", "server.js"]
