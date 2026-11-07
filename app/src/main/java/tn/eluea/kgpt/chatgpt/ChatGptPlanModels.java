/*
 * GPL-3.0-or-later.
 * Fetches the live model catalog for the connected ChatGPT plan account.
 * Tokens and raw HTTP response bodies never leave the KGPT process.
 */
package tn.eluea.kgpt.chatgpt;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;

public final class ChatGptPlanModels {
    private static final String ENDPOINT = "https://api.openai.com/v1/models";
    private static final int MAX_RESPONSE = 1024 * 1024;
    private ChatGptPlanModels() { }

    public static final class CatalogException extends Exception {
        CatalogException(String explanation) { super(explanation); }
    }

    /**
     * The account-scoped model catalog defined by the Sign in with ChatGPT
     * model discovery guide: {"models":[{"visibility":"list","slug":"...",
     * "display_name":"..."}, ...]}.
     *
     * An identity-only successful login does not guarantee model access.
     */
    public static LinkedHashMap<String, String> fetch(ChatGptPlanAuth auth) throws Exception {
        if (!auth.canUsePlan()) {
            throw new CatalogException("Обліковий запис підключено без дозволу на використання підписки.");
        }

        String accessToken = auth.validAccessToken();
        for (int attempt = 0; attempt < 2; attempt++) {
            HttpURLConnection con = (HttpURLConnection) new URL(ENDPOINT).openConnection();
            try {
                con.setConnectTimeout(15000);
                con.setReadTimeout(25000);
                con.setRequestMethod("GET");
                con.setRequestProperty("Authorization", "Bearer " + accessToken);
                con.setRequestProperty("Accept", "application/json");

                int status = con.getResponseCode();
                if (status == 401 && attempt == 0) {
                    // Refresh once if a token is revoked before its local expiry.
                    // Do not erase credentials on network errors or 403 responses.
                    accessToken = auth.refreshAfterUnauthorized(accessToken);
                    continue;
                }
                if (status != 200) {
                    String code = readErrorCode(con.getErrorStream());
                    throw new CatalogException(
                            ChatGptPlanCatalogDiagnostics.httpError(status, code));
                }
                String raw = readLimited(con.getInputStream(), MAX_RESPONSE);
                return parseCatalog(raw);
            } catch (SocketTimeoutException e) {
                throw new CatalogException("Перевищено час очікування каталогу моделей OpenAI.");
            } catch (UnknownHostException e) {
                throw new CatalogException("Не вдалося знайти сервер OpenAI. Перевірте доступ до мережі або DNS.");
            } catch (CatalogException e) {
                throw e;
            } catch (IOException e) {
                // Do not show raw low-level network messages, which can contain URLs.
                throw new CatalogException("Мережева помилка під час завантаження моделей ("
                        + e.getClass().getSimpleName() + ").");
            } finally {
                con.disconnect();
            }
        }
        throw new CatalogException("Каталог моделей недоступний після поновлення авторизації.");
    }

    /** Strict parser for the documented SIWC catalog, keeping server order. */
    static LinkedHashMap<String, String> parseCatalog(String raw) throws CatalogException {
        try {
            JSONObject root = new JSONObject(raw);
            JSONArray models = root.optJSONArray("models");
            if (models == null) {
                throw new CatalogException("OpenAI повернув неочікуваний формат каталогу (немає models).");
            }
            LinkedHashMap<String, String> result = new LinkedHashMap<>();
            int visible = 0;
            for (int i = 0; i < models.length(); i++) {
                JSONObject model = models.optJSONObject(i);
                if (model == null || !"list".equals(model.optString("visibility"))) continue;
                visible++;
                String slug = model.optString("slug", "").trim();
                if (!slug.matches("[a-zA-Z0-9_.-]{1,96}")) continue;
                String name = model.optString("display_name", slug).trim();
                result.put(slug, name.isEmpty() ? slug : name);
                if (result.size() >= 100) break;
            }
            if (result.isEmpty()) {
                throw new CatalogException(
                        ChatGptPlanCatalogDiagnostics.emptyCatalog(models.length(), visible));
            }
            return result;
        } catch (JSONException e) {
            throw new CatalogException("OpenAI повернув некоректну JSON-відповідь каталогу моделей.");
        }
    }

    private static String readErrorCode(InputStream stream) {
        if (stream == null) return "";
        try {
            String raw = readLimited(stream, 16384);
            JSONObject root = new JSONObject(raw);
            JSONObject error = root.optJSONObject("error");
            if (error != null) return ChatGptPlanCatalogDiagnostics.sanitizeCode(
                    error.optString("code", error.optString("type", "")));
            return ChatGptPlanCatalogDiagnostics.sanitizeCode(
                    root.optString("code", root.optString("error", "")));
        } catch (Exception ignored) {
            return "";
        }
    }

    private static String readLimited(InputStream stream, int limit) throws IOException {
        if (stream == null) return "";
        try (InputStream input = stream; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] chunk = new byte[4096];
            int count;
            while ((count = input.read(chunk)) != -1) {
                if (output.size() + count > limit)
                    throw new IOException("Oversized model response");
                output.write(chunk, 0, count);
            }
            return new String(output.toByteArray(), StandardCharsets.UTF_8);
        }
    }
}
