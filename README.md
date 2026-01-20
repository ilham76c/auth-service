# Go Auth Service

A lightweight **Authentication Service** built with **Go (Gin)** and **JWT (HS256)**.

This service is designed to be:
- 🔐 Secure
- ⚡ High performance
- 💰 Cost-efficient
- 🧠 Easy to learn & extend

It fits perfectly in a **microservice architecture** with:
- API Gateway (NGINX / FastAPI)
- AI Service (FastAPI)
- Domain Service (Flask)

---

## 🧩 Architecture Overview

**Responsibility**
- Issue JWT access tokens
- Verify tokens
- Provide authenticated user context

---

## 🚀 Tech Stack

- **Language**: Go 1.21+
- **Framework**: Gin
- **JWT**: HS256 (HMAC)
- **Linting**: golangci-lint
- **Config**: Environment variables

---

## 📁 Project Structure

> `internal/` ensures this code cannot be imported from outside the service (Go best practice).

---

## 🔐 Authentication Flow

1. Client sends credentials to `/auth/login`
2. Auth Service validates credentials
3. JWT access token is issued
4. Client sends token via `Authorization: Bearer <token>`
5. Middleware verifies token
6. User claims are attached to request context

---

## 📡 API Endpoints

### 🔑 Login

```http
POST /auth/login
```

---

## ▶️ Run Application

### Local
```bash
go run cmd/server/main.go
```

### Docker
```bash
docker build -t auth-service .
docker run -p 8080:8080 -e JWT_SECRET=super-secret-key auth-service
```


## Run Linter and Formatter
```bash
make fmt
make lint
make run
```