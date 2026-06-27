---
name: vibe-guard
description:
  Always-on security guardrails for AI-generated code. Catches the 20 things AI agents forget before
  you deploy.
metadata:
  tags: security, vibe-coding, guardrails, production
---

## When to use

This skill is always active. It applies to every project where AI agents generate code. 45% of
AI-generated code has security flaws. This skill catches them before they reach production.

## Critical Rules

### 1. Never Hardcode Secrets

**Wrong:**

```javascript
const API_KEY = "sk-1234567890abcdef";
const dbUrl = "postgres://user:password123@localhost/db";
```

**Correct:**

```javascript
const API_KEY = process.env.API_KEY;
const dbUrl = process.env.DATABASE_URL;
```

### 2. Always Validate Input

**Wrong:**

```javascript
app.post("/api/users", (req, res) => {
  db.insert(req.body);
});
```

**Correct:**

```javascript
const userSchema = z.object({ email: z.string().email(), name: z.string().min(1) });
app.post("/api/users", (req, res) => {
  const parsed = userSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json(parsed.error.flatten());
  db.insert(parsed.data);
});
```

### 3. Enforce Authentication on Every Route

**Wrong:**

```javascript
app.get('/api/users', (req, res) => {
  const users = await db.select('*').from('users');
  res.json(users);
});
```

**Correct:**

```javascript
app.get("/api/users", authMiddleware, async (req, res) => {
  const users = await db.select("*").from("users").where("tenant_id", req.user.tenantId);
  res.json(users);
});
```

### 4. Use Row-Level Security (Supabase/Postgres)

**Wrong:**

```javascript
const { data } = await supabase.from("profiles").select("*");
```

**Correct:**

```sql
CREATE POLICY "Users can only read own profile" ON profiles
  FOR SELECT USING (auth.uid() = id);
```

```javascript
const { data } = await supabase.from("profiles").select("*");
```

### 5. Sanitize Database Queries

**Wrong:**

```javascript
db.query(`SELECT * FROM users WHERE id = ${userId}`);
```

**Correct:**

```javascript
db.query("SELECT * FROM users WHERE id = $1", [userId]);
```

### 6. Set CORS Properly

**Wrong:**

```javascript
app.use(cors({ origin: "*" }));
```

**Correct:**

```javascript
app.use(cors({ origin: ["https://yourdomain.com", "https://app.yourdomain.com"] }));
```

### 7. Add Rate Limiting

**Wrong:**

```javascript
app.post("/login", loginHandler);
app.post("/signup", signupHandler);
```

**Correct:**

```javascript
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
app.post("/login", authLimiter, loginHandler);
app.post("/signup", authLimiter, signupHandler);
```

### 8. Use HTTPS Only

**Wrong:**

```javascript
const apiUrl = "http://api.example.com";
```

**Correct:**

```javascript
const apiUrl =
  process.env.NODE_ENV === "production" ? "https://api.example.com" : "http://localhost:3000";
```

```javascript
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));
```

### 9. Hash Passwords Properly

**Wrong:**

```javascript
const hash = crypto.createHash("md5").update(password).digest("hex");
// or: const hash = password; (plain text)
```

**Correct:**

```javascript
const hash = await bcrypt.hash(password, 12);
```

### 10. Set Security Headers

**Wrong:**

```javascript
app.listen(3000);
```

**Correct:**

```javascript
app.use(helmet());
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  next();
});
```

### 11. Handle Errors Without Leaking Info

**Wrong:**

```javascript
catch (err) {
  res.status(500).json({ error: err.stack, message: err.message });
}
```

**Correct:**

```javascript
catch (err) {
  if (process.env.NODE_ENV === 'production') {
    res.status(500).json({ error: 'Internal server error' });
  } else {
    res.status(500).json({ error: err.message });
  }
}
```

### 12. Validate File Uploads

**Wrong:**

```javascript
app.post("/upload", upload.single("file"), (req, res) => {
  fs.writeFileSync(`./uploads/${req.file.originalname}`, req.file.buffer);
});
```

**Correct:**

```javascript
const ALLOWED_TYPES = ["image/jpeg", "image/png"];
const MAX_SIZE = 5 * 1024 * 1024;
app.post("/upload", upload.single("file"), (req, res) => {
  if (!ALLOWED_TYPES.includes(req.file.mimetype) || req.file.size > MAX_SIZE) {
    return res.status(400).json({ error: "Invalid file" });
  }
  const ext = path.extname(req.file.originalname);
  const safeName = `${uuid()}${ext}`;
  fs.writeFileSync(`./uploads/${safeName}`, req.file.buffer);
});
```

### 13. Use Environment-Specific Config

**Wrong:**

```javascript
const config = { dbUrl: "localhost", debug: true };
```

**Correct:**

```javascript
const config = {
  dbUrl: process.env.DATABASE_URL,
  debug: process.env.NODE_ENV !== "production",
};
```

### 14. Add Logging (But Not Secrets)

**Wrong:**

```javascript
console.log("User logged in:", user);
```

**Correct:**

```javascript
const { password, ...safeUser } = user;
logger.info("User logged in", { userId: safeUser.id, email: safeUser.email });
```

### 15. Set Proper Cookie Flags

**Wrong:**

```javascript
res.cookie("session", token);
document.cookie = "session=" + token;
```

**Correct:**

```javascript
res.cookie("session", token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
  path: "/",
  maxAge: 3600000,
});
```

### 16. Implement Proper Session Management

**Wrong:**

```javascript
const token = jwt.sign({ userId }, secret, { expiresIn: "365d" });
```

**Correct:**

```javascript
const accessToken = jwt.sign({ userId }, secret, { expiresIn: "15m" });
const refreshToken = jwt.sign({ userId }, refreshSecret, { expiresIn: "7d" });
```

### 17. Protect Against CSRF

**Wrong:**

```javascript
app.post("/api/transfer", (req, res) => {
  transferMoney(req.body);
});
```

**Correct:**

```javascript
app.use(csrf({ cookie: true }));
app.post("/api/transfer", (req, res) => {
  if (req.headers["x-csrf-token"] !== req.csrfToken()) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }
  transferMoney(req.body);
});
```

### 18. Use Content Security Policy

**Wrong:**

```javascript
// No CSP header - inline scripts allowed
```

**Correct:**

```javascript
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
  );
  next();
});
```

### 19. Validate Redirects

**Wrong:**

```javascript
res.redirect(req.query.next || "/");
```

**Correct:**

```javascript
const ALLOWED_REDIRECTS = ["/dashboard", "/profile", "/settings"];
const next = req.query.next;
const target = ALLOWED_REDIRECTS.includes(next) ? next : "/";
res.redirect(target);
```

### 20. Check Dependencies for Vulnerabilities

**Wrong:**

```javascript
// Never running npm audit
```

**Correct:**

```bash
npm audit
npm audit fix
```

```yaml
# In CI: .github/workflows/ci.yml
- run: npm audit --audit-level=high
```
