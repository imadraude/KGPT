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
    private static final SecureRandom RNG = new SecureRandom();
    private static final String AUTHORIZE = "https://auth.openai.com/api/accounts/authorize";
    private static final String TOKEN = "https://auth.openai.com/api/accounts/oauth/token";
    private static final String JWKS = "https://auth.openai.com/.well-known/jwks.json";
    private static final String RESOURCE = "https://api.openai.com/v1";
    private static final String SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
    private static final String KEY = "kgpt_chatgpt_plan_aes_v1";
    private static final String FILE = "chatgpt_plan_v1.bin";
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

        PendingSession(String client, String expectedSubject, String redirectUri,
                       String state, String nonce, String verifier, ServerSocket server) {
            this.client = client;
            this.expectedSubject = expectedSubject;
            this.redirectUri = redirectUri;
            this.state = state;
            this.nonce = nonce;
            this.verifier = verifier;
            this.server = server;
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
        }
    }

    public boolean canUsePlan() throws Exception {
        synchronized (LOCK) {
            JSONObject j = load();
            return j != null && j.has("access_token") && hasScope(j.optString("scope"));
        }
    }

    public String connectedEmail() throws Exception {
        synchronized (LOCK) {
            JSONObject j = load();
            return j == null ? "" : j.optString("email", "");
        }
    }

    public void signIn(Activity activity, Result result) {
        new Thread(() -> {
            try {
                authorize(activity);
                boolean connected = canUsePlan();
                activity.runOnUiThread(() -> result.complete(
                        connected ? "ChatGPT plan connected." : "Signed in, but plan usage was not approved.", connected));
            } catch (Exception e) {
                Log.e(TAG, "Sign-in error", e);
                activity.runOnUiThread(() -> result.complete(
                        "ChatGPT sign-in failed: " + safeMessage(e), false));
            }
        }, "KGPT-ChatGPT-OAuth").start();
    }

    public void completeWithManualCallback(Activity activity, String rawInput, Result result) {
        new Thread(() -> {
            try {
                final PendingSession session;
                synchronized (LOCK) { session = pendingSession; }
                if (session == null) {
                    throw new IllegalStateException("Немає активної сесії авторизації. Натисніть «Continue with ChatGPT» спочатку.");
                }
                String input = rawInput != null ? rawInput.trim() : "";
                if (input.isEmpty()) {
                    throw new IllegalArgumentException("Введіть посилання з браузера або код авторизації.");
                }
                Uri callbackUri;
                if (input.startsWith("http://") || input.startsWith("https://")) {
                    callbackUri = Uri.parse(input);
                } else if (input.contains("code=")) {
                    callbackUri = Uri.parse("http://127.0.0.1/auth/callback?" + input);
                } else {
                    callbackUri = Uri.parse("http://127.0.0.1/auth/callback?code="
                            + URLEncoder.encode(input, "UTF-8") + "&state=" + session.state);
                }
                processCallback(callbackUri, session);
                session.close();
                boolean connected = canUsePlan();
                activity.runOnUiThread(() -> result.complete(
                        connected ? "ChatGPT plan connected." : "Signed in, but plan usage was not approved.", connected));
            } catch (Exception e) {
                Log.e(TAG, "Manual callback processing failed", e);
                activity.runOnUiThread(() -> result.complete(
                        "ChatGPT sign-in failed: " + safeMessage(e), false));
            }
        }, "KGPT-ChatGPT-ManualCallback").start();
    }

    private void authorize(Activity activity) throws Exception {
        final JSONObject previous;
        synchronized (LOCK) { previous = load(); }
        if (previous == null) throw new IllegalStateException("Local credential store unavailable");
        final String client = previous.optString("client_id", "dynamic_agent_client");
        final String expectedSubject = previous.optString("subject", "");
        final String hostId = previous.getString("host_id");
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            server.setSoTimeout(180_000);
            String redirect = "http://127.0.0.1:" + server.getLocalPort() + "/auth/callback";
            String state = random(32), nonce = random(32), verifier = random(48);
            String challenge = b64(MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII)));

            PendingSession currentSession = new PendingSession(
                    client, expectedSubject, redirect, state, nonce, verifier, server);
            synchronized (LOCK) {
                if (pendingSession != null) pendingSession.close();
                pendingSession = currentSession;
            }

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
            }
            Intent intent = new Intent(Intent.ACTION_VIEW, builder.build());
            intent.addCategory(Intent.CATEGORY_BROWSABLE);
            activity.runOnUiThread(() -> activity.startActivity(intent));
            Log.i(TAG, "OAuth sign-in listening on " + redirect);
            Uri callback = receiveCallback(server, state);
            processCallback(callback, currentSession);
        }
    }

    private void processCallback(Uri callback, PendingSession session) throws Exception {
        String error = callback.getQueryParameter("error");
        if (error != null) {
            String desc = callback.getQueryParameter("error_description");
            throw new IllegalStateException("Authorization was declined: " + (desc != null ? desc : error));
        }
        String code = callback.getQueryParameter("code");
        if (code == null || code.isEmpty()) throw new SecurityException("Authorization code missing");
        String returned = callback.getQueryParameter("client_id");
        final String issued;
        if ("dynamic_agent_client".equals(session.client)) {
            if (returned != null && returned.startsWith("oaiapp_")) {
                issued = returned;
            } else {
                issued = returned != null && !returned.isEmpty() ? returned : session.client;
            }
        } else {
            if (returned != null && !session.client.equals(returned))
                throw new SecurityException("OAuth client mismatch");
            issued = session.client;
        }
        synchronized (LOCK) {
            JSONObject saved = load();
            if (saved != null) {
                saved.put("client_id", issued); // preserve registration if code expired
                save(saved);
            }
        }
        JSONObject tokens = postForm(TOKEN, "grant_type", "authorization_code",
                "client_id", issued, "code", code, "code_verifier", session.verifier,
                "redirect_uri", session.redirectUri, "resource", RESOURCE);
        String finalClientId = tokens.optString("client_id", issued);
        JSONObject claims = verifyIdentity(tokens.getString("id_token"), finalClientId, session.nonce);
        String subject = claims.getString("sub");
        if (!session.expectedSubject.isEmpty() && !session.expectedSubject.equals(subject))
            throw new SecurityException("Authenticated account is not the selected account");
        String grantedScope = tokens.optString("scope", "");
        if (grantedScope.isEmpty()) grantedScope = SCOPES;
        synchronized (LOCK) {
            JSONObject saved = load();
            if (saved == null) saved = new JSONObject();
            saved.put("client_id", finalClientId);
            saved.put("subject", subject);
            saved.put("email", claims.optString("email", ""));
            saved.put("id_token", tokens.getString("id_token"));
            saved.put("access_token", tokens.getString("access_token"));
            saved.put("refresh_token", tokens.getString("refresh_token"));
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
                Uri uri = Uri.parse("http://127.0.0.1" + route);
                boolean hostMatches = false;
                String line;
                int port = server.getLocalPort();
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
                if (!valid) throw new SecurityException("OAuth callback state or host invalid");
                return uri;
            }
        }
        throw new SecurityException("Callback server closed before receiving redirect");
    }

    public String validAccessToken() throws Exception {
        synchronized (LOCK) {
            JSONObject saved = load();
            if (saved == null || !hasScope(saved.optString("scope")) ||
                    !saved.has("access_token"))
                throw new SecurityException("Connect ChatGPT and approve plan access in KGPT");
            if (System.currentTimeMillis() + 120000L < saved.optLong("expires_at"))
                return saved.getString("access_token");
            JSONObject tokens = postForm(TOKEN, "grant_type", "refresh_token",
                    "client_id", saved.getString("client_id"),
                    "refresh_token", saved.getString("refresh_token"), "resource", RESOURCE);
            JSONObject updated = new JSONObject(saved.toString());
            updated.put("access_token", tokens.getString("access_token"));
            updated.put("refresh_token", tokens.getString("refresh_token"));
            if (tokens.has("scope")) updated.put("scope", tokens.getString("scope"));
            updated.put("expires_at", System.currentTimeMillis() + tokens.optLong("expires_in", 3600) * 1000L);
            if (!hasScope(updated.optString("scope")))
                throw new SecurityException("ChatGPT plan access was revoked");
            save(updated); // rotated refresh token and access token saved together
            return updated.getString("access_token");
        }
    }

    public void disconnectLocally() throws Exception {
        synchronized (LOCK) {
            JSONObject saved = load();
            JSONObject cleared = new JSONObject().put("host_id", saved.getString("host_id"));
            if (saved.has("client_id")) cleared.put("client_id", saved.getString("client_id"));
            save(cleared);
        }
        // Revocation is managed separately in ChatGPT account settings.
    }

    private static String safeMessage(Exception e) {
        if (e instanceof java.net.SocketTimeoutException) return "Browser sign-in timed out (180s)";
        if (e.getMessage() != null && !e.getMessage().isEmpty()) return e.getMessage();
        return e.getClass().getSimpleName();
    }
    private static boolean hasScope(String scope) {
        for (String s : scope.split("\\s+"))
            if ("chatgpt.tokens.use.direct".equals(s)) return true;
        return false;
    }
    private static String random(int count) {
        byte[] buf = new byte[count]; RNG.nextBytes(buf); return b64(buf);
    }
    private static String b64(byte[] value) {
        return Base64.encodeToString(value, Base64.NO_PADDING | Base64.NO_WRAP | Base64.URL_SAFE);
    }

    private static JSONObject postForm(String address, String... params) throws Exception {
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < params.length; i += 2) {
            if (i != 0) body.append('&');
            body.append(URLEncoder.encode(params[i], "UTF-8")).append('=')
                    .append(URLEncoder.encode(params[i + 1], "UTF-8"));
        }
        HttpURLConnection con = (HttpURLConnection) new URL(address).openConnection();
        con.setConnectTimeout(15000); con.setReadTimeout(30000);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        con.setDoOutput(true);
        try (OutputStream os = con.getOutputStream()) {
            os.write(body.toString().getBytes(StandardCharsets.UTF_8));
        }
        int code = con.getResponseCode();
        String raw = readLimited(code < 400 ? con.getInputStream() : con.getErrorStream(), 128000);
        con.disconnect();
        if (code >= 400) {
            String desc = "OAuth HTTP " + code;
            try {
                JSONObject errObj = new JSONObject(raw);
                if (errObj.has("error_description")) {
                    desc = errObj.getString("error_description");
                } else if (errObj.has("error")) {
                    desc = errObj.getString("error");
                }
            } catch (Exception ignored) {}
            throw new IllegalStateException(desc);
        }
        return new JSONObject(raw);
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
        if (!"https://auth.openai.com".equals(claims.optString("iss")) ||
                !nonce.equals(claims.optString("nonce")) ||
                claims.optString("sub").isEmpty() ||
                claims.optLong("exp") <= System.currentTimeMillis() / 1000L)
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

    private JSONObject load() throws Exception {
        File path = new File(context.getNoBackupFilesDir(), FILE);
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
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secret());
        byte[] encrypted = cipher.doFinal(value.toString().getBytes(StandardCharsets.UTF_8));
        File dir = context.getNoBackupFilesDir();
        File temp = new File(dir, FILE + ".tmp");
        File target = new File(dir, FILE);
        try (FileOutputStream output = new FileOutputStream(temp)) {
            output.write(cipher.getIV()); output.write(encrypted);
            output.getFD().sync();
        }
        if (!temp.renameTo(target)) throw new IOException("Could not persist ChatGPT connection");
    }
}
