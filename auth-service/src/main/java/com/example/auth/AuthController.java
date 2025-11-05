package com.example.auth;

import jakarta.servlet.http.HttpSession;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/auth")
@Validated
public class AuthController {

    private final Map<String, String> userStore = new ConcurrentHashMap<>();

    public record RegisterRequest(@NotBlank String username, @NotBlank String password) {}
    public record LoginRequest(@NotBlank String username, @NotBlank String password) {}

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    @GetMapping(value = "/login-page", produces = MediaType.TEXT_HTML_VALUE)
    public String loginPage(@RequestParam(value = "redirect", required = false) String redirect) {
        String redirectValue = redirect == null ? "" : redirect;
        return String.format("""
            <html>
            <head><title>Login</title></head>
            <body>
              <h3>Login</h3>
              <form method='post' action='/api/auth/login'>
                <input type='hidden' name='redirect' value='%s' />
                <div><label>Username: <input name='username' /></label></div>
                <div><label>Password: <input name='password' type='password' /></label></div>
                <div><button type='submit'>Login</button></div>
              </form>
              <div style='margin-top:12px;'>
                <a href='/api/auth/register-page'>Go to Register</a>
              </div>
            </body>
            </html>
        """, escapeHtml(redirectValue));
    }

    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<?> login(
        @RequestParam(value = "redirect", required = false) String redirect,
        @RequestParam(value = "username", required = false) String username,
        @RequestParam(value = "password", required = false) String password,
        HttpSession session
    ) {
        log.info("Login form-only: redirect={}, username={}", redirect, username);

        // 校验用户是否已存在且密码匹配
        String stored = username == null ? null : userStore.get(username);
        if (stored == null) {
            return ResponseEntity.status(401).contentType(MediaType.TEXT_PLAIN).body("user not found");
        }
        if (password == null || !stored.equals(password)) {
            return ResponseEntity.status(401).contentType(MediaType.TEXT_PLAIN).body("invalid credentials");
        }
        session.setAttribute("user", username);
        String target = (redirect == null || redirect.isBlank()) ? "/api/user/hello" : redirect;
        return ResponseEntity.status(302).header("Location", target).build();
    }

    @GetMapping(value = "/register-page", produces = MediaType.TEXT_HTML_VALUE)
    public String registerPage() {
        return """
            <html>
            <head><title>Register</title></head>
            <body>
              <h3>Register</h3>
              <form method='post' action='/api/auth/register'>
                <div><label>Username: <input name='username' /></label></div>
                <div><label>Password: <input name='password' type='password' /></label></div>
                <div><button type='submit'>Register</button></div>
              </form>
              <div style='margin-top:12px;'>
                <a href='/api/auth/login-page'>Back to Login</a>
              </div>
            </body>
            </html>
        """;
    }

    @PostMapping(value = "/register", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<?> registerForm(
        @RequestParam("username") String username,
        @RequestParam("password") String password
    ) {
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("message", "username/password required"));
        }
        if (userStore.containsKey(username)) {
            return ResponseEntity.status(409).body(Map.of("message", "user exists"));
        }
        userStore.put(username, password);
        return ResponseEntity.status(302).header("Location", "/api/auth/login-page").build();
    }

    @PostMapping(value = "/register", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> register(@org.springframework.web.bind.annotation.RequestBody RegisterRequest request) {
        String username = request.username();
        String password = request.password();
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("message", "username/password required"));
        }
        if (userStore.containsKey(username)) {
            return ResponseEntity.status(409).body(Map.of("message", "user exists"));
        }
        userStore.put(username, password);
        return ResponseEntity.ok(Map.of("message", "registered"));
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(HttpSession session) {
        Object user = session.getAttribute("user");
        if (user == null) {
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.ok(Map.of("username", user));
    }

    @GetMapping("/validate")
    public ResponseEntity<?> validate(HttpSession session) {
        log.info("Validating session: {}", session.getId());
        Object user = session.getAttribute("user");
        if (user == null) {
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.ok(Map.of("username", user));
    }
}


