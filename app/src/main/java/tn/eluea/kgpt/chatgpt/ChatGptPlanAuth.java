/*
 * KGPT ChatGPT plan sign-in. GPL-3.0-or-later.
 * See https://developers.openai.com/siwc/token-sharing-open-source/sign-in
 */
package tn.eluea.kgpt.chatgpt;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * A single locally held ChatGPT account. OAuth secrets are encrypted inside
 * KGPT's own no-backup directory, NEVER sent to the hooked keyboard process.
 */
public final class ChatGptPlanAuth {
    private static final String TAG = "KGPT-Auth";
    private static final Object LOCK = new Object();
    private static final Object REFRESH_LOCK = new Object();
    private static final SecureRandom RNG = new SecureRandom();
    private static final String AUTHORIZE = "https://auth.openai.com/api/accounts/authorize";
    private static final String TOKEN = "https://auth.openai.com/api/accounts/oauth/token";
    private static final String JWKS = "https://auth.openai.com/.well-known/jwks.json";
    private static final String RESOURCE = "https://api.openai.com/v1";
    private static final String SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
    private static final String KEY = "kgpt_chatgpt_plan_aes_v1";
    private static final String FILE = "chatgpt_plan_v1.bin";
    private static final String PENDING_FILE = "chatgpt_plan_pending_v1.bin";
    private static final long PENDING_TTL_MS = 600_000L;
    private final Context context;

    private static volatile PendingSession pendingSession;

    public interface Result { void complete(String message, boolean connected); }

    private static final class PendingSession {
        final String client;
        final String expectedSubject;
        final String redirectUri;
        final String state;
        final String nonce;
        final String verifier;
        final ServerSocket server;
        final long createdAt;
        final AtomicBoolean processing = new AtomicBoolean(false);
        final AtomicBoolean reported = new AtomicBoolean(false);

        PendingSession(String client, String expectedSubject, String redirectUri,
                       String state, String nonce, String verifier, ServerSocket server) {
            this(client, expectedSubject, redirectUri, state, nonce, verifier, server,
                    System.currentTimeMillis());
        }

        PendingSession(String client, String expectedSubject, String redirectUri,
                       String state, String nonce, String verifier, ServerSocket server,
                       long createdAt) {
            this.client = client;
            this.expectedSubject = expectedSubject;
            this.redirectUri = redirectUri;
            this.state = state;
            this.nonce = nonce;
            this.verifier = verifier;
            this.server = server;
            this.createdAt = createdAt;
        }

        void close() {
            if (server != null && !server.isClosed()) {
                try { server.close(); } catch (Exception ignored) {}
            }
        }
    }

    public ChatGptPlanAuth(Context ctx) throws Exception {
        context = ctx.getApplicationContext();
        synchronized (LOCK) {
            if (load() == null) {
                JSONObject initial = new JSONObject().put("host_id", "urn:uuid:" + UUID.randomUUID());
                save(initial);
            }
            if (pendingSession == null) {
                try {
                    pendingSession = restorePending();
                } catch (Exception e) {
                    clearPendingFile(); // Corrupt/expired attempts cannot be trusted.
                }
            }
        }
    }

    public boolean canUsePlan() throws Exception {
        synchronized (LOCK) {
            JSONObject j = load();
            return j != null && !j.optString("access_token", "").isEmpty()
                    && !j.optString("refresh_token", "").isEmpty()
                    && hasScope(j.optString("scope"));
        }
    }

    public String connectedEmail() throws Exception {
        synchronized (LOCK) {
            JSONObject j = load();
            return j == null ? "" : j.optString("email", "");
        }
    }

    public boolean isSignInPending() {
        synchronized (LOCK) { return pendingSession != null; }
    }

    public boolean requiresManualRecovery() {
        synchronized (LOCK) {
            return pendingSession != null && pendingSession.server == null;
        }
    }

    public void cancelSignIn() {
        synchronized (LOCK) {
            if (pendingSession != null) {
                pendingSession.reported.set(true);
                pendingSession.close();
            }
            pendingSession = null;
            clearPendingFile();
        }
    }

    public void signIn(Activity activity, Result result) {
        new Thread(() -> {
            try {
                authorize(activity, result);
            } catch (Exception e) {
                // Only startup errors reach here; active attempts report their own result.
                report(activity, result, "ChatGPT sign-in failed: " + safeMessage(e), false);
            }
        }, "KGPT-ChatGPT-OAuth").start();
    }

    public void completeWithManualCallback(Activity activity, String rawInput, Result result) {
        new Thread(() -> {
            final PendingSession session;
            synchronized (LOCK) { session = pendingSession; }
            if (session == null) {
                report(activity, result, "Немає активної сесії. Розпочніть вхід повторно.", false);
                return;
            }
            if (session.processing.get()) {
                report(activity, result, "Код авторизації вже обробляється.", false);
                return;
            }
            try {
                String input = rawInput != null ? rawInput.trim() : "";
                if (input.isEmpty()) throw new IllegalArgumentException("Вставте посилання або код авторизації.");
                if ("dynamic_agent_client".equals(session.client) && !input.contains("client_id=")) {
                    throw new IllegalArgumentException(
                            "Для першого входу потрібно повне посилання з code, state та client_id.");
                }
                Uri callback;
                if (input.startsWith("http://") || input.startsWith("https://")) {
                    callback = Uri.parse(input);
                } else if (input.startsWith("?") || input.startsWith("code=") || input.startsWith("error=")) {
                    callback = Uri.parse(session.redirectUri + (input.startsWith("?") ? "" : "?") + input);
                } else {
                    callback = Uri.parse(session.redirectUri + "?code="
                            + URLEncoder.encode(input, "UTF-8") + "&state=" + session.state);
                }
                // Full callback URLs/query strings MUST carry their original state.
                // A pasted code alone is protected by the pending PKCE verifier.
                completeAuthorization(session, callback, activity, result);
            } catch (Exception e) {
                report(activity, result, "Не вдалося розпізнати код: " + safeMessage(e), false);
            }
        }, "KGPT-ChatGPT-ManualCallback").start();
    }

    private static void report(Activity activity, Result result, String message, boolean connected) {
        activity.runOnUiThread(() -> result.complete(message, connected));
    }

    private static void reportOnce(PendingSession session, Activity activity, Result result,
                                   String message, boolean connected) {
        if (session.reported.compareAndSet(false, true)) report(activity, result, message, connected);
    }

    /** Exactly one of the browser listener or manual callback can exchange a code. */
    private void completeAuthorization(PendingSession session, Uri callback,
                                       Activity activity, Result result) {
        if (!session.processing.compareAndSet(false, true)) return;
        session.close(); // Unblock the browser listener when manual recovery succeeds.
        try {
            processCallback(callback, session);
            boolean connected = canUsePlan();
            reportOnce(session, activity, result,
                    connected ? "ChatGPT підключено." :
                            "Вхід виконано, але дозвіл на використання підписки не надано.",
                    connected);
        } catch (Exception e) {
            Log.w(TAG, "OAuth authorization did not complete (" + e.getClass().getSimpleName() + ")");
            reportOnce(session, activity, result, "Помилка входу: " + safeMessage(e), false);
        } finally {
            synchronized (LOCK) {
                if (pendingSession == session) {
                    pendingSession = null;
                    clearPendingFile();
                }
            }
        }
    }

    private void authorize(Activity activity, Result result) throws Exception {
        final JSONObject previous;
        synchronized (LOCK) { previous = load(); }
        if (previous == null) throw new IllegalStateException("Сховище облікового запису недоступне.");
        final String client = previous.optString("client_id", "dynamic_agent_client");
        final String expectedSubject = previous.optString("subject", "");
        final String hostId = previous.getString("host_id");
        ServerSocket server = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
        server.setSoTimeout(600_000);
        String redirect = "http://127.0.0.1:" + server.getLocalPort() + "/auth/callback";
        String state = random(32), nonce = random(32), verifier = random(48);
        String challenge = b64(MessageDigest.getInstance("SHA-256")
                .digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        PendingSession session = new PendingSession(
                client, expectedSubject, redirect, state, nonce, verifier, server);
        synchronized (LOCK) {
            if (pendingSession != null) {
                pendingSession.reported.set(true);
                pendingSession.close();
            }
            try {
                savePending(session);
            } catch (Exception e) {
                session.close();
                throw e;
            }
            pendingSession = session;
        }

        try {
            Uri.Builder builder = Uri.parse(AUTHORIZE).buildUpon()
                    .appendQueryParameter("client_id", client)
                    .appendQueryParameter("ext_agent_host_id", hostId)
                    .appendQueryParameter("redirect_uri", redirect)
                    .appendQueryParameter("response_type", "code")
                    .appendQueryParameter("scope", SCOPES)
                    .appendQueryParameter("resource", RESOURCE)
                    .appendQueryParameter("state", state)
                    .appendQueryParameter("nonce", nonce)
                    .appendQueryParameter("code_challenge_method", "S256")
                    .appendQueryParameter("code_challenge", challenge);
            if ("dynamic_agent_client".equals(client)) {
                builder.appendQueryParameter("agent_name_hint", "KGPT");
            } else if (previous.has("id_token")) {
                builder.appendQueryParameter("id_token_hint", previous.getString("id_token"));
                if (!hasScope(previous.optString("scope", ""))) {
                    // The user explicitly returned to enable a previously denied
                    // plan grant; a normal silent re-sign-in cannot upgrade scopes.
                    builder.appendQueryParameter("prompt", "consent");
                }
            }
            Intent intent = new Intent(Intent.ACTION_VIEW, builder.build());
            intent.addCategory(Intent.CATEGORY_BROWSABLE);
            activity.runOnUiThread(() -> {
                try {
                    activity.startActivity(intent);
                } catch (Exception e) {
                    reportOnce(session, activity, result,
                            "Не вдалося відкрити браузер для авторизації.", false);
                    session.close();
                }
            });
            Uri callback = receiveCallback(server, state);
            completeAuthorization(session, callback, activity, result);
        } catch (Exception e) {
            // Manual recovery owns the outcome once it begins exchanging a code.
            if (!session.processing.get()) {
                reportOnce(session, activity, result,
                        e instanceof java.net.SocketTimeoutException
                                ? "Час входу минув. Розпочніть авторизацію повторно."
                                : "Помилка авторизації: " + safeMessage(e), false);
            }
        } finally {
            session.close();
            synchronized (LOCK) {
                if (pendingSession == session && !session.processing.get()) {
                    pendingSession = null;
                    clearPendingFile();
                }
            }
        }
    }

    private void processCallback(Uri callback, PendingSession session) throws Exception {
        ChatGptPlanSecurity.verifyCallback(callback.toString(), session.redirectUri, session.state);
        String error = callback.getQueryParameter("error");
        if (error != null) {
            String desc = callback.getQueryParameter("error_description");
            throw new IllegalStateException("Authorization was declined: " + (desc != null ? desc : error));
        }
        String code = callback.getQueryParameter("code");
        if (code == null || code.isEmpty()) throw new SecurityException("Authorization code missing");
        String returned = callback.getQueryParameter("client_id");
        final String issued = ChatGptPlanSecurity.issuedClientId(session.client, returned);
        // For a new registration retain its issued client ID even if a code later
        // expires. Never replace an existing account's client before validating it.
        if ("dynamic_agent_client".equals(session.client)) {
            synchronized (LOCK) {
                if (pendingSession != session) throw new SecurityException("Authorization cancelled");
                JSONObject saved = load();
                if (saved != null && !saved.has("access_token")) {
                    saved.put("client_id", issued);
                    save(saved);
                }
            }
        }
        JSONObject tokens = postForm(TOKEN, "grant_type", "authorization_code",
                "client_id", issued, "code", code, "code_verifier", session.verifier,
                "redirect_uri", session.redirectUri, "resource", RESOURCE);
        String finalClientId = tokens.optString("client_id", issued);
        if (!issued.equals(finalClientId)) throw new SecurityException("OAuth token client mismatch");
        if (!"Bearer".equalsIgnoreCase(tokens.optString("token_type", "Bearer"))) {
            throw new SecurityException("Unexpected OAuth token type");
        }
        JSONObject claims = verifyIdentity(tokens.getString("id_token"), finalClientId, session.nonce);
        String subject = claims.getString("sub");
        if (!session.expectedSubject.isEmpty() && !session.expectedSubject.equals(subject))
            throw new SecurityException("Authenticated account is not the selected account");
        // Never infer permissions from the scopes we requested.
        String grantedScope = tokens.optString("scope", "");
        synchronized (LOCK) {
            if (pendingSession != session) throw new SecurityException("Authorization cancelled");
            JSONObject saved = load();
            if (saved == null) saved = new JSONObject();
            saved.put("client_id", finalClientId);
            saved.put("subject", subject);
            saved.put("email", claims.optString("email", ""));
            saved.put("id_token", tokens.getString("id_token"));
            saved.put("access_token", tokens.getString("access_token"));
            saved.put("refresh_token", tokens.optString("refresh_token", ""));
            saved.put("scope", grantedScope);
            saved.put("expires_at", System.currentTimeMillis() + tokens.optLong("expires_in", 3600) * 1000L);
            save(saved);
        }
        Log.i(TAG, "ChatGPT plan credentials successfully saved for " + claims.optString("email", ""));
    }

    /** Local browser HTTP callback as required by the OSS registration flow. */
    private static Uri receiveCallback(ServerSocket server, String state) throws Exception {
        while (!server.isClosed()) {
            final Socket socket;
            try {
                socket = server.accept();
            } catch (SocketException e) {
                break;
            }
            try (socket) {
                socket.setSoTimeout(10_000);
                BufferedReader in = new BufferedReader(new InputStreamReader(
                        socket.getInputStream(), StandardCharsets.US_ASCII));
                String first = in.readLine();
                if (first == null || !first.startsWith("GET ") || !first.contains(" HTTP/")) {
                    continue;
                }
                String route = first.substring(4, first.indexOf(" HTTP/"));
                int port = server.getLocalPort();
                Uri uri;
                try {
                    uri = Uri.parse(ChatGptPlanSecurity.reconstructLoopbackCallback(port, route));
                } catch (SecurityException malformed) {
                    continue; // Reject absolute-form or malformed HTTP request-targets.
                }
                boolean hostMatches = false;
                String line;
                while ((line = in.readLine()) != null && !line.isEmpty()) {
                    if (line.toLowerCase(java.util.Locale.ROOT).startsWith("host:")) {
                        String hostVal = line.substring(5).trim().toLowerCase(java.util.Locale.ROOT);
                        if (hostVal.equals("127.0.0.1:" + port) || hostVal.equals("localhost:" + port)
                                || hostVal.equals("127.0.0.1") || hostVal.equals("localhost")) {
                            hostMatches = true;
                        }
                    }
                }
                if (!"/auth/callback".equals(uri.getPath())) {
                    byte[] notFound = "Not Found".getBytes(StandardCharsets.UTF_8);
                    OutputStream out = socket.getOutputStream();
                    String headers = "HTTP/1.1 404 Not Found\r\nContent-Length: " + notFound.length
                            + "\r\nConnection: close\r\n\r\n";
                    out.write(headers.getBytes(StandardCharsets.US_ASCII));
                    out.write(notFound);
                    out.flush();
                    continue;
                }
                boolean valid = hostMatches && state.equals(uri.getQueryParameter("state"));
                byte[] body = (valid ? "Authorization received. Return to KGPT."
                        : "Invalid authorization callback.").getBytes(StandardCharsets.UTF_8);
                OutputStream out = socket.getOutputStream();
                String headers = (valid ? "HTTP/1.1 200 OK\r\n" : "HTTP/1.1 400 Bad Request\r\n")
                        + "Content-Type: text/plain; charset=utf-8\r\n"
                        + "Cache-Control: no-store\r\nContent-Length: " + body.length
                        + "\r\nConnection: close\r\n\r\n";
                out.write(headers.getBytes(StandardCharsets.US_ASCII));
                out.write(body);
                out.flush();
                if (!valid) continue; // Ignore unrelated loopback traffic; keep listener alive.
                return uri;
            }
        }
        throw new SecurityException("Callback server closed before receiving redirect");
    }

    public String validAccessToken() throws Exception {
        // A separate mutex serializes refreshes. The main thread may still read
        // connection status while an HTTP refresh is waiting on the network.
        synchronized (REFRESH_LOCK) {
            final JSONObject saved;
            synchronized (LOCK) {
                saved = load();
                if (saved == null || !hasScope(saved.optString("scope")) ||
                        saved.optString("access_token", "").isEmpty()) {
                    throw new SecurityException("Connect ChatGPT and approve plan access in KGPT.");
                }
                if (System.currentTimeMillis() + 120000L < saved.optLong("expires_at")) {
                    return saved.getString("access_token");
                }
                if (saved.optString("refresh_token", "").isEmpty()) {
                    throw new SecurityException("ChatGPT session expired; sign in again.");
                }
            }
            JSONObject tokens;
            try {
                tokens = postForm(TOKEN, "grant_type", "refresh_token",
                        "client_id", saved.getString("client_id"),
                        "refresh_token", saved.getString("refresh_token"),
                        "resource", RESOURCE);
            } catch (OAuthTokenException e) {
                if (isTerminalRefreshCode(e.code)) {
                    synchronized (LOCK) {
                        JSONObject current = load();
                        // Never erase a newly signed-in account or newer tokens.
                        if (current != null && saved.getString("refresh_token")
                                .equals(current.optString("refresh_token"))) {
                            JSONObject cleared = new JSONObject();
                            for (String key : new String[]{"host_id", "client_id", "subject", "email"}) {
                                if (saved.has(key)) cleared.put(key, saved.get(key));
                            }
                            save(cleared);
                        }
                    }
                    throw new SecurityException("ChatGPT session expired or revoked. Sign in again.");
                }
                throw e; // Preserve credentials for retry after transient HTTP errors.
            }
            synchronized (LOCK) {
                JSONObject current = load();
                if (current == null || !saved.getString("refresh_token")
                        .equals(current.optString("refresh_token"))) {
                    // User signed out or authorized another account during HTTP refresh.
                    // Do not write back the old account's credentials.
                    throw new SecurityException("ChatGPT account changed. Reconnect if needed.");
                }
                JSONObject updated = new JSONObject(saved.toString());
                updated.put("access_token", tokens.getString("access_token"));
                updated.put("refresh_token", tokens.getString("refresh_token"));
                if (tokens.has("scope")) updated.put("scope", tokens.getString("scope"));
                long expiresIn = tokens.optLong("expires_in", 0);
                if (expiresIn <= 0) throw new IOException("OAuth refresh returned no expiry.");
                updated.put("expires_at", System.currentTimeMillis() + expiresIn * 1000L);
                if (!hasScope(updated.optString("scope"))) {
                    throw new SecurityException("ChatGPT plan access was revoked.");
                }
                save(updated); // Atomic access + rotating refresh token replacement.
                return updated.getString("access_token");
            }
        }
    }

    public String refreshAfterUnauthorized(String rejectedAccessToken) throws Exception {
        synchronized (LOCK) {
            JSONObject saved = load();
            if (saved == null || !hasScope(saved.optString("scope"))) {
                throw new SecurityException("Reconnect ChatGPT in KGPT settings.");
            }
            if (rejectedAccessToken.equals(saved.optString("access_token"))) {
                saved.put("expires_at", 0);
                save(saved);
            }
        }
        return validAccessToken();
    }

    private static boolean isTerminalRefreshCode(String code) {
        return ChatGptPlanSecurity.isTerminalRefreshCode(code);
    }

    public void disconnectLocally() throws Exception {
        synchronized (LOCK) {
            if (pendingSession != null) {
                pendingSession.reported.set(true);
                pendingSession.close();
                pendingSession = null;
            }
            clearPendingFile();
            JSONObject saved = load();
            if (saved == null) return;
            JSONObject cleared = new JSONObject().put("host_id", saved.getString("host_id"));
            // Preserve only account registration metadata for later re-authorization.
            for (String key : new String[]{"client_id", "subject", "email"}) {
                if (saved.has(key)) cleared.put(key, saved.getString(key));
            }
            save(cleared);
        }
        // User can revoke access remotely in ChatGPT settings.
    }

    private static String safeMessage(Exception e) {
        if (e instanceof java.net.SocketTimeoutException) return "Перевищено час очікування відповіді мережі.";
        if (e.getMessage() != null && !e.getMessage().isEmpty()) return e.getMessage();
        return e.getClass().getSimpleName();
    }
    private static boolean hasScope(String scope) {
        return ChatGptPlanSecurity.hasScope(scope, "chatgpt.tokens.use.direct");
    }
    private static String random(int count) {
        byte[] buf = new byte[count]; RNG.nextBytes(buf); return b64(buf);
    }
    private static String b64(byte[] value) {
        return Base64.encodeToString(value, Base64.NO_PADDING | Base64.NO_WRAP | Base64.URL_SAFE);
    }

    private static final class OAuthTokenException extends IOException {
        final String code;
        OAuthTokenException(String code) {
            super("OAuth request rejected (" + code + ").");
            this.code = code;
        }
    }

    private static JSONObject postForm(String address, String... params) throws Exception {
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < params.length; i += 2) {
            if (i != 0) body.append('&');
            body.append(URLEncoder.encode(params[i], "UTF-8")).append('=')
                    .append(URLEncoder.encode(params[i + 1], "UTF-8"));
        }
        HttpURLConnection con = (HttpURLConnection) new URL(address).openConnection();
        try {
            con.setConnectTimeout(15000);
            con.setReadTimeout(30000);
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            con.setDoOutput(true);
            try (OutputStream os = con.getOutputStream()) {
                os.write(body.toString().getBytes(StandardCharsets.UTF_8));
            }
            int status = con.getResponseCode();
            String raw = readLimited(status < 400 ? con.getInputStream() : con.getErrorStream(), 128000);
            if (status >= 400) {
                String code = "http_" + status;
                try {
                    JSONObject err = new JSONObject(raw);
                    code = err.optString("error", code);
                } catch (Exception ignored) { }
                if (!code.matches("[a-zA-Z0-9_.-]{1,64}")) code = "http_" + status;
                throw new OAuthTokenException(code);
            }
            return new JSONObject(raw);
        } finally {
            con.disconnect();
        }
    }

    private static String readLimited(InputStream stream, int cap) throws IOException {
        if (stream == null) return "";
        try (InputStream in = stream; ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            byte[] chunk = new byte[4096]; int n;
            while ((n = in.read(chunk)) != -1) {
                if (buffer.size() + n > cap) throw new IOException("Oversized network response");
                buffer.write(chunk, 0, n);
            }
            return buffer.toString("UTF-8");
        }
    }

    private static JSONObject verifyIdentity(String token, String client, String nonce) throws Exception {
        if (token.length() > 65536) throw new SecurityException("Oversized ID token");
        String[] parts = token.split("\\.");
        if (parts.length != 3) throw new SecurityException("Malformed ID token");
        JSONObject header = new JSONObject(new String(Base64.decode(parts[0], Base64.URL_SAFE), StandardCharsets.UTF_8));
        JSONObject claims = new JSONObject(new String(Base64.decode(parts[1], Base64.URL_SAFE), StandardCharsets.UTF_8));
        if (!"RS256".equals(header.optString("alg"))) throw new SecurityException("Unexpected JWT algorithm");
        HttpURLConnection con = (HttpURLConnection) new URL(JWKS).openConnection();
        con.setConnectTimeout(15000); con.setReadTimeout(20000);
        JSONObject jwks;
        try { jwks = new JSONObject(readLimited(con.getInputStream(), 128000)); }
        finally { con.disconnect(); }
        JSONArray keys = jwks.getJSONArray("keys");
        JSONObject matching = null;
        for (int i = 0; i < keys.length(); i++) {
            JSONObject k = keys.getJSONObject(i);
            if ("RSA".equals(k.optString("kty")) && header.optString("kid").equals(k.optString("kid"))) {
                matching = k; break;
            }
        }
        if (matching == null) throw new SecurityException("ID token public key missing");
        BigInteger n = new BigInteger(1, Base64.decode(matching.getString("n"), Base64.URL_SAFE));
        BigInteger e = new BigInteger(1, Base64.decode(matching.getString("e"), Base64.URL_SAFE));
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e)));
        signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        if (!signature.verify(Base64.decode(parts[2], Base64.URL_SAFE)))
            throw new SecurityException("Invalid ID token signature");
        long now = System.currentTimeMillis() / 1000L;
        if (!"https://auth.openai.com".equals(claims.optString("iss")) ||
                !nonce.equals(claims.optString("nonce")) ||
                claims.optString("sub").isEmpty() ||
                claims.optLong("exp") <= now ||
                claims.optLong("nbf", 0) > now + 60 ||
                claims.optLong("iat", 0) > now + 60)
            throw new SecurityException("ID token claims invalid");
        Object audience = claims.get("aud");
        boolean correct = client.equals(audience);
        if (audience instanceof JSONArray) {
            for (int i = 0; i < ((JSONArray) audience).length(); i++)
                correct |= client.equals(((JSONArray) audience).optString(i));
        }
        if (!correct) throw new SecurityException("ID token audience mismatch");
        return claims;
    }

    private SecretKey secret() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(KEY, null);
        if (entry instanceof KeyStore.SecretKeyEntry) return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(KEY,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).build());
        return generator.generateKey();
    }

    private void savePending(PendingSession session) throws Exception {
        JSONObject saved = new JSONObject()
                .put("client", session.client)
                .put("expected_subject", session.expectedSubject)
                .put("redirect", session.redirectUri)
                .put("state", session.state)
                .put("nonce", session.nonce)
                .put("verifier", session.verifier)
                .put("created_at", session.createdAt);
        saveEncryptedFile(PENDING_FILE, saved);
    }

    private PendingSession restorePending() throws Exception {
        JSONObject saved = loadEncryptedFile(PENDING_FILE);
        if (saved == null) return null;
        long created = saved.optLong("created_at", 0);
        long age = System.currentTimeMillis() - created;
        if (created <= 0 || age < 0 || age > PENDING_TTL_MS) {
            clearPendingFile();
            return null;
        }
        return new PendingSession(saved.getString("client"),
                saved.optString("expected_subject", ""),
                saved.getString("redirect"), saved.getString("state"),
                saved.getString("nonce"), saved.getString("verifier"),
                null, created);
    }

    private void clearPendingFile() {
        new File(context.getNoBackupFilesDir(), PENDING_FILE).delete();
    }

    private JSONObject load() throws Exception {
        return loadEncryptedFile(FILE);
    }

    private JSONObject loadEncryptedFile(String fileName) throws Exception {
        File path = new File(context.getNoBackupFilesDir(), fileName);
        if (!path.exists()) return null;
        byte[] raw;
        try (FileInputStream input = new FileInputStream(path);
             ByteArrayOutputStream result = new ByteArrayOutputStream()) {
            byte[] chunk = new byte[4096]; int n;
            while ((n = input.read(chunk)) != -1) {
                if (result.size() + n > 128000) throw new SecurityException("Credential file too large");
                result.write(chunk, 0, n);
            }
            raw = result.toByteArray();
        }
        if (raw.length < 29) throw new SecurityException("Credential file corrupted");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secret(),
                new GCMParameterSpec(128, java.util.Arrays.copyOfRange(raw, 0, 12)));
        return new JSONObject(new String(cipher.doFinal(raw, 12, raw.length - 12), StandardCharsets.UTF_8));
    }

    private void save(JSONObject value) throws Exception {
        saveEncryptedFile(FILE, value);
    }

    private void saveEncryptedFile(String fileName, JSONObject value) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secret());
        byte[] encrypted = cipher.doFinal(value.toString().getBytes(StandardCharsets.UTF_8));
        File dir = context.getNoBackupFilesDir();
        File temp = new File(dir, fileName + ".tmp");
        File target = new File(dir, fileName);
        try (FileOutputStream output = new FileOutputStream(temp)) {
            output.write(cipher.getIV()); output.write(encrypted);
            output.getFD().sync();
        }
        if (!temp.renameTo(target)) throw new IOException("Could not persist ChatGPT connection");
    }
}
