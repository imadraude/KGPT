/*
 * GPL-3.0-or-later. Keep OAuth access and refresh tokens in KGPT's process.
 */
package tn.eluea.kgpt.chatgpt;

import android.app.Service;
import android.content.Intent;
import android.os.*;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class ChatGptPlanService extends Service {
    public static final int REQUEST = 5101;
    public static final int RESULT = 5102;
    private static final int MAX_TEXT = 12000;
    private final ExecutorService executor = Executors.newFixedThreadPool(2);
    private final Messenger incoming = new Messenger(new Handler(Looper.getMainLooper(), msg -> {
        // Do not trust package names or identity supplied in a Bundle.
        if (msg.what != REQUEST || msg.replyTo == null || !allowedCaller(msg.sendingUid))
            return true;
        Bundle data = msg.getData();
        long id = data.getLong("id", -1);
        String prompt = data.getString("prompt", "");
        String system = data.getString("system", "");
        String model = data.getString("model", "gpt-6.1-sol");
        Messenger reply = msg.replyTo;
        if (id < 0 || prompt.isEmpty() || prompt.length() > MAX_TEXT ||
                system.length() > MAX_TEXT || model.length() > 96 ||
                !model.matches("[a-zA-Z0-9_.-]+")) {
            reply(reply, id, null, "Invalid request size or model");
            return true;
        }
        executor.execute(() -> {
            try {
                reply(reply, id, generate(model, system, prompt), null);
            } catch (Exception e) {
                // Never forward prompts, bearer tokens, HTTP response bodies, or JWTs.
                String message = e instanceof SecurityException
                        ? "Reconnect ChatGPT in KGPT settings."
                        : e instanceof PlanRequestException
                            ? e.getMessage()
                            : e instanceof UsageLimitException
                                ? "ChatGPT plan usage limit reached. Check ChatGPT settings."
                                : "ChatGPT request failed (" + e.getClass().getSimpleName() + ").";
                reply(reply, id, null, message);
            }
        });
        return true;
    }));

    private boolean allowedCaller(int uid) {
        if (uid < 0) return false;
        if (uid == android.os.Process.myUid()) return true;
        String[] packages = getPackageManager().getPackagesForUid(uid);
        if (packages == null) return false;
        for (String name : packages) {
            if ("com.touchtype.swiftkey".equals(name) ||
                    "com.touchtype.swiftkey.beta".equals(name)) return true;
        }
        return false;
    }
    @Override public IBinder onBind(Intent intent) { return incoming.getBinder(); }
    @Override public void onDestroy() { executor.shutdownNow(); super.onDestroy(); }

    private static void reply(Messenger target, long id, String value, String error) {
        Message message = Message.obtain(null, RESULT);
        Bundle payload = new Bundle();
        payload.putLong("id", id);
        if (value != null) payload.putString("text", value);
        if (error != null) payload.putString("error", error);
        message.setData(payload);
        try { target.send(message); } catch (RemoteException ignored) { }
    }

    private String generate(String model, String system, String prompt) throws Exception {
        ChatGptPlanAuth auth = new ChatGptPlanAuth(this);
        String access = auth.validAccessToken();
        JSONObject body = new JSONObject()
                .put("model", model).put("store", false).put("stream", true)
                .put("input", new JSONArray().put(new JSONObject()
                        .put("role", "user").put("content", prompt)));
        if (!system.isEmpty()) body.put("instructions", system);
        // Only a rejected request (401 before a stream starts) is retried.
        // Never replay a partially generated response.
        for (int attempt = 0; attempt < 2; attempt++) {
            HttpURLConnection con = (HttpURLConnection)
                    new URL("https://api.openai.com/v1/responses").openConnection();
            try {
                con.setConnectTimeout(20000);
                con.setReadTimeout(115000);
                con.setRequestMethod("POST");
                con.setRequestProperty("Authorization", "Bearer " + access);
                con.setRequestProperty("Content-Type", "application/json");
                con.setRequestProperty("Accept", "text/event-stream");
                con.setDoOutput(true);
                try (OutputStream output = con.getOutputStream()) {
                    output.write(body.toString().getBytes(StandardCharsets.UTF_8));
                }
                int status = con.getResponseCode();
                if (status == 401 && attempt == 0) {
                    // A server-side token revocation can precede its local expiry.
                    // Refresh once, without erasing credentials on transient failures.
                    access = auth.refreshAfterUnauthorized(access);
                    continue;
                }
                if (status != 200) throw readError(status, con.getErrorStream());

                StringBuilder text = new StringBuilder();
                boolean completed = false;
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(con.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.length() > 262144)
                            throw new PlanRequestException("ChatGPT sent an oversized event.");
                        if (!line.startsWith("data:")) continue;
                        String json = line.substring(5).trim();
                        if (json.isEmpty() || "[DONE]".equals(json)) continue;
                        JSONObject event = new JSONObject(json);
                        String type = event.optString("type");
                        if ("response.output_text.delta".equals(type)) {
                            String delta = event.optString("delta");
                            if (text.length() + delta.length() > 60000)
                                throw new PlanRequestException("ChatGPT response exceeds the keyboard limit.");
                            text.append(delta);
                        } else if ("response.completed".equals(type)) {
                            completed = true;
                        } else if ("response.failed".equals(type) ||
                                "response.incomplete".equals(type) || "error".equals(type)) {
                            JSONObject error = event.optJSONObject("error");
                            JSONObject response = event.optJSONObject("response");
                            if (error == null && response != null) error = response.optJSONObject("error");
                            String code = error == null ? "" : error.optString("code");
                            throw classifyError(200, code);
                        }
                    }
                }
                if (!completed)
                    throw new PlanRequestException("ChatGPT connection interrupted before completion.");
                return text.toString();
            } finally {
                con.disconnect();
            }
        }
        throw new PlanRequestException("ChatGPT authorization was rejected. Reconnect in KGPT.");
    }

    private static Exception readError(int status, InputStream stream) {
        String code = "";
        if (stream != null) {
            try (InputStream in = stream; ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
                byte[] part = new byte[2048];
                int n;
                while ((n = in.read(part)) != -1 && buffer.size() + n <= 16384) {
                    buffer.write(part, 0, n);
                }
                JSONObject body = new JSONObject(buffer.toString("UTF-8"));
                JSONObject error = body.optJSONObject("error");
                if (error != null) code = error.optString("code", "");
            } catch (Exception ignored) {
                // Admission errors also use {"detail": "..."}; do not expose body text.
            }
        }
        return classifyError(status, code);
    }

    private static Exception classifyError(int status, String code) {
        if (status == 429 || "subscription_sharing_usage_limit_exceeded".equals(code))
            return new UsageLimitException();
        if ("subscription_sharing_user_not_eligible".equals(code))
            return new PlanRequestException("This ChatGPT account or workspace is not eligible for plan usage.");
        if ("subscription_sharing_unsupported_capability".equals(code))
            return new PlanRequestException("The selected model or feature is not supported by ChatGPT plan usage.");
        if (status == 401 || "subscription_sharing_invalid_user".equals(code))
            return new SecurityException("ChatGPT authorization was rejected.");
        if (status == 403)
            return new PlanRequestException("ChatGPT denied permission for this model, account or region.");
        if (status == 503 || "subscription_sharing_usage_unavailable".equals(code))
            return new PlanRequestException("ChatGPT plan usage is temporarily unavailable. Try again later.");
        if (status == 400)
            return new PlanRequestException("ChatGPT rejected the request. Check the selected model.");
        return new PlanRequestException("ChatGPT request failed (HTTP " + status + ").");
    }

    private static final class PlanRequestException extends Exception {
        PlanRequestException(String message) { super(message); }
    }

    private static final class UsageLimitException extends Exception { }
}
