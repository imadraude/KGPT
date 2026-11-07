package tn.eluea.kgpt.chatgpt;

import org.junit.Test;
import static org.junit.Assert.*;

public class ChatGptPlanSecurityTest {
    private static final String CALLBACK = "http://127.0.0.1:1455/auth/callback";
    private static final String STATE = "random_state-123";

    private void rejects(String url) {
        try {
            ChatGptPlanSecurity.verifyCallback(url, CALLBACK, STATE);
            fail("Expected callback to be rejected: " + url);
        } catch (SecurityException expected) { }
    }

    @Test public void validBrowserAndManualCallbacks() {
        ChatGptPlanSecurity.verifyCallback(CALLBACK +
                "?code=temporary%2Bcode&state=random_state-123&client_id=oaiapp_demo", CALLBACK, STATE);
        ChatGptPlanSecurity.verifyCallback(CALLBACK +
                "?state=random_state-123&code=temporary", CALLBACK, STATE);
    }

    @Test public void rejectsWrongOrMissingState() {
        rejects(CALLBACK + "?code=abc");
        rejects(CALLBACK + "?state=other&code=abc");
        rejects(CALLBACK + "?state=random_state-123&state=random_state-123&code=abc");
        rejects(CALLBACK + "?state=random_state-123%00");
    }

    @Test public void rejectsWrongCallbackOriginAndPath() {
        rejects("https://127.0.0.1:1455/auth/callback?state=" + STATE);
        rejects("http://localhost:1455/auth/callback?state=" + STATE);
        rejects("http://127.0.0.1:1456/auth/callback?state=" + STATE);
        rejects("http://127.0.0.1:1455/callback?state=" + STATE);
        rejects("http://attacker@127.0.0.1:1455/auth/callback?state=" + STATE);
        rejects(CALLBACK + "?state=" + STATE + "#fragment");
    }

    @Test public void requiresIssuedClientOnRegistration() {
        assertEquals("oaiapp_abc-12", ChatGptPlanSecurity.issuedClientId(
                "dynamic_agent_client", "oaiapp_abc-12"));
        assertEquals("oaiapp_saved", ChatGptPlanSecurity.issuedClientId(
                "oaiapp_saved", null));
        try {
            ChatGptPlanSecurity.issuedClientId("dynamic_agent_client", null);
            fail("Registration must return a real client ID");
        } catch (SecurityException expected) { }
        try {
            ChatGptPlanSecurity.issuedClientId("oaiapp_saved", "oaiapp_different");
            fail("Must not switch registered client");
        } catch (SecurityException expected) { }
    }

    @Test public void permissionsMustActuallyBeGranted() {
        assertFalse(ChatGptPlanSecurity.hasScope(null, "chatgpt.tokens.use.direct"));
        assertFalse(ChatGptPlanSecurity.hasScope("", "chatgpt.tokens.use.direct"));
        assertFalse(ChatGptPlanSecurity.hasScope(
                "openid email resource.invoke", "chatgpt.tokens.use.direct"));
        assertTrue(ChatGptPlanSecurity.hasScope(
                "openid chatgpt.tokens.use.direct email", "chatgpt.tokens.use.direct"));
        assertFalse(ChatGptPlanSecurity.hasScope(
                "chatgpt.tokens.use.direct.other", "chatgpt.tokens.use.direct"));
    }

    @Test public void terminalRefreshErrorsAreDistinctFromTemporaryFailures() {
        assertTrue(ChatGptPlanSecurity.isTerminalRefreshCode("invalid_grant"));
        assertTrue(ChatGptPlanSecurity.isTerminalRefreshCode("refresh_token_reused"));
        assertFalse(ChatGptPlanSecurity.isTerminalRefreshCode("temporarily_unavailable"));
        assertFalse(ChatGptPlanSecurity.isTerminalRefreshCode("http_503"));
    }
}
