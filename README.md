# What is this?
blog-api-nest is a fully featured REST API written in [NestJS](https://nestjs.com/).

# Features
This API has the following features:
- Clean and easy to understand structure
- Structured logging, ready for production use
- Password reset via email
- 2-Factor Authentication using [TOTP](https://en.wikipedia.org/wiki/Time-based_one-time_password)
- Role management with [RBAC](https://en.wikipedia.org/wiki/Role-based_access_control)
- Fully documented API with [Swagger](https://swagger.io/)
- [12 Factor](https://12factor.net/) compliant

# Deployment using Docker
First, clone the repository:
```shell
git clone https://github.com/XiovV/blog-api-nest.git
```
Then build the image like this:
```shell
make build/image
```
Or, you can build it manually:
```shell
docker build -t blog-api-nest .
```
Now edit the docker-compose.yml to set your own environment variables and run it. Please note that this docker-compose.yml will run PostgreSQL as well:
```shell
docker-compose up -d
```
## Optional environment variables
All of the environment variables inside the docker-compose.yml file are required, however there are a few which are optional:
- `PORT` (defaults to 3000)
- `LOG_LEVEL` (defaults to "info")
- `NODE_ENV` (if set to "production", the logs will be logged in JSON. If it's set to something else, logs will be prettified)

# Documentation
Once the API is up and running, you can visit the docs at http://localhost:3000/docs