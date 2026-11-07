/*
 * GPL-3.0-or-later.
 * Fetches the live model catalog for the connected ChatGPT plan account.
 * Tokens never leave the KGPT process.
 */
package tn.eluea.kgpt.chatgpt;

import org.json.JSONArray;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public final class ChatGptPlanModels {
    private ChatGptPlanModels() { }

    /** Ordered slug -> display name map, filtered exactly as in the official SIWC guide. */
    public static LinkedHashMap<String, String> fetch(ChatGptPlanAuth auth) throws Exception {
        if (!auth.canUsePlan()) throw new SecurityException("Connect ChatGPT Plan first");
        String accessToken = auth.validAccessToken();
        HttpURLConnection con = (HttpURLConnection)
                new URL("https://api.openai.com/v1/models").openConnection();
        try {
            con.setConnectTimeout(15000);
            con.setReadTimeout(25000);
            con.setRequestProperty("Authorization", "Bearer " + accessToken);
            con.setRequestProperty("Accept", "application/json");
            if (con.getResponseCode() != 200) {
                throw new IllegalStateException("ChatGPT model catalog unavailable");
            }

            StringBuilder raw = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(con.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (raw.length() + line.length() > 256000)
                        throw new IllegalStateException("Model catalog too large");
                    raw.append(line);
                }
            }
            JSONArray models = new JSONObject(raw.toString()).getJSONArray("models");
            LinkedHashMap<String, String> result = new LinkedHashMap<>();
            for (int i = 0; i < models.length() && result.size() < 100; i++) {
                JSONObject entry = models.getJSONObject(i);
                if (!"list".equals(entry.optString("visibility"))) continue;
                String slug = entry.optString("slug", "").trim();
                if (!slug.matches("[a-zA-Z0-9_.-]{1,96}")) continue;
                String label = entry.optString("display_name", slug).trim();
                if (label.isEmpty()) label = slug;
                result.put(slug, label);
            }
            if (result.isEmpty())
                throw new IllegalStateException("No selectable models for this account");
            return result;
        } finally {
            con.disconnect();
        }
    }
}
