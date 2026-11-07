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
                        ? "Sign in with ChatGPT in KGPT settings"
                        : e instanceof UsageLimitException
                            ? "ChatGPT usage limit reached; check ChatGPT settings"
                            : "ChatGPT request failed (" + e.getClass().getSimpleName() + ")";
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
        String access = new ChatGptPlanAuth(this).validAccessToken();
        JSONObject body = new JSONObject()
                .put("model", model).put("store", false).put("stream", true)
                .put("input", new JSONArray().put(new JSONObject()
                        .put("role", "user").put("content", prompt)));
        if (!system.isEmpty()) body.put("instructions", system);
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
            if (status == 429) throw new UsageLimitException();
            if (status != 200) throw new IOException("ChatGPT HTTP " + status);
            StringBuilder text = new StringBuilder();
            boolean completed = false;
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(con.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (!line.startsWith("data:")) continue;
                    String json = line.substring(5).trim();
                    if (json.isEmpty() || "[DONE]".equals(json)) continue;
                    JSONObject event = new JSONObject(json);
                    String type = event.optString("type");
                    if ("response.output_text.delta".equals(type)) {
                        if (text.length() + event.optString("delta").length() > 60000)
                            throw new IOException("Response exceeds keyboard limit");
                        text.append(event.optString("delta"));
                    } else if ("response.completed".equals(type)) {
                        completed = true;
                    } else if ("response.failed".equals(type) || "error".equals(type)) {
                        throw new IOException("OpenAI response failed");
                    }
                }
            }
            if (!completed) throw new IOException("Incomplete ChatGPT response");
            return text.toString();
        } finally { con.disconnect(); }
    }

    private static final class UsageLimitException extends Exception { }
}
