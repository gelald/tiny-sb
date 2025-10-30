package com.example.auth;

import jakarta.validation.constraints.NotBlank;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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
            </body>
            </html>
        """, escapeHtml(redirectValue));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        if (userStore.containsKey(request.username())) {
            return ResponseEntity.badRequest().body(Map.of("message", "username exists"));
        }
        userStore.put(request.username(), request.password());
        return ResponseEntity.ok(Map.of("message", "registered"));
    }

    @PostMapping(value = "/login", consumes = { MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_FORM_URLENCODED_VALUE })
    public ResponseEntity<?> login(
        @RequestParam(value = "redirect", required = false) String redirect,
        @RequestBody(required = false) LoginRequest jsonBody,
        HttpSession session,
        @RequestParam(value = "username", required = false) String formUsername,
        @RequestParam(value = "password", required = false) String formPassword
    ) {
        String username = jsonBody != null ? jsonBody.username() : formUsername;
        String password = jsonBody != null ? jsonBody.password() : formPassword;

        String pwd = username == null ? null : userStore.get(username);
        if (pwd == null || password == null || !pwd.equals(password)) {
            return ResponseEntity.status(401).contentType(MediaType.TEXT_PLAIN).body("invalid credentials");
        }
        session.setAttribute("user", username);
        if (redirect != null && !redirect.isBlank()) {
            return ResponseEntity.status(302).header("Location", redirect).build();
        }
        return ResponseEntity.ok(Map.of("message", "ok", "sessionId", session.getId(), "username", username));
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
        Object user = session.getAttribute("user");
        if (user == null) {
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.ok(Map.of("username", user));
    }
}
