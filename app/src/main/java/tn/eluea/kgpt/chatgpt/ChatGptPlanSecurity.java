/*
 * GPL-3.0-or-later. Pure-Java OAuth callback and grant validation.
 * Keep these checks independent of Android so they can be regression tested.
 */
package tn.eluea.kgpt.chatgpt;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public final class ChatGptPlanSecurity {
    private ChatGptPlanSecurity() { }

    public static void verifyCallback(String callback, String expected, String state) {
        final URI actual;
        final URI target;
        try {
            actual = URI.create(callback);
            target = URI.create(expected);
        } catch (IllegalArgumentException e) {
            throw new SecurityException("Malformed OAuth callback");
        }
        if (!"http".equals(actual.getScheme())
                || !"127.0.0.1".equals(actual.getHost())
                || actual.getRawUserInfo() != null
                || actual.getFragment() != null
                || actual.getPort() != target.getPort()
                || !target.getPath().equals(actual.getPath())) {
            throw new SecurityException("OAuth redirect URL mismatch");
        }

        String foundState = null;
        String rawQuery = actual.getRawQuery();
        if (rawQuery != null) {
            for (String parameter : rawQuery.split("&")) {
                int equals = parameter.indexOf('=');
                if (equals < 0) continue;
                String name = URLDecoder.decode(parameter.substring(0, equals), StandardCharsets.UTF_8);
                if ("state".equals(name)) {
                    if (foundState != null) throw new SecurityException("Duplicate OAuth state");
                    foundState = URLDecoder.decode(parameter.substring(equals + 1),
                            StandardCharsets.UTF_8);
                }
            }
        }
        if (state == null || !state.equals(foundState)) {
            throw new SecurityException("OAuth state mismatch");
        }
    }

    public static String issuedClientId(String requested, String returned) {
        if ("dynamic_agent_client".equals(requested)) {
            if (returned == null || !returned.matches("oaiapp_[a-zA-Z0-9_-]+")) {
                throw new SecurityException("Missing issued OAuth client ID");
            }
            return returned;
        }
        if (returned != null && !requested.equals(returned)) {
            throw new SecurityException("OAuth client mismatch");
        }
        return requested;
    }

    public static boolean hasScope(String scopes, String required) {
        if (scopes == null || required == null) return false;
        for (String scope : scopes.trim().split("\\s+")) {
            if (required.equals(scope)) return true;
        }
        return false;
    }

    public static boolean isTerminalRefreshCode(String code) {
        if (code == null) return false;
        switch (code) {
            case "invalid_grant":
            case "invalid_refresh_token":
            case "refresh_token_expired":
            case "refresh_token_invalidated":
            case "refresh_token_reused":
            case "token_expired":
                return true;
            default:
                return false;
        }
    }
}
