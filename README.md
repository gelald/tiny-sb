# tiny-sb (Multi-module: Gateway + User + Tax + Auth)

## Prerequisites
- Java 17+
- Maven 3.8+

## Build all modules
```bash
mvn -T 1C -DskipTests package
```

## Run modules (each in a separate terminal)
```bash
mvn -pl user-service spring-boot:run
mvn -pl tax-service spring-boot:run
mvn -pl auth-service spring-boot:run
mvn -pl gateway spring-boot:run
```

## Test through Gateway
```bash
curl http://localhost:8080/api/user/hello
curl http://localhost:8080/api/tax/hello
curl http://localhost:8080/api/auth/hello
```

## AuthN/Z via session cookie
Gateway listens on 19080 and enforces auth for non-auth routes. Use `JSESSIONID` from auth-service login.

1) Register:
```bash
curl -X POST http://localhost:18083/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"u1","password":"p1"}'
```

2) Login (capture cookie):
```bash
curl -i -X POST http://localhost:18083/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"u1","password":"p1"}'
```
Copy the `Set-Cookie: JSESSIONID=...` value.

3) Access services THROUGH gateway with cookie:
```bash
curl -H "Cookie: JSESSIONID=<value>" http://localhost:19080/api/user/hello
curl -H "Cookie: JSESSIONID=<value>" http://localhost:19080/api/tax/hello
```

4) Me (optional):
```bash
curl -H "Cookie: JSESSIONID=<value>" http://localhost:18083/auth/me
```

