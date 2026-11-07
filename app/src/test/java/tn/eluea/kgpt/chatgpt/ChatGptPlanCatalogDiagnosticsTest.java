package tn.eluea.kgpt.chatgpt;

import org.junit.Test;
import static org.junit.Assert.*;

public class ChatGptPlanCatalogDiagnosticsTest {
    @Test public void httpStatusIsAlwaysVisible() {
        assertTrue(ChatGptPlanCatalogDiagnostics.httpError(401, "").contains("HTTP 401"));
        assertTrue(ChatGptPlanCatalogDiagnostics.httpError(403, "").contains("HTTP 403"));
        assertTrue(ChatGptPlanCatalogDiagnostics.httpError(429, "").contains("HTTP 429"));
        assertTrue(ChatGptPlanCatalogDiagnostics.httpError(503, "").contains("HTTP 503"));
    }

    @Test public void onlySafeServerErrorCodesAreDisplayed() {
        assertEquals("invalid_token", ChatGptPlanCatalogDiagnostics.sanitizeCode("invalid_token"));
        assertEquals("", ChatGptPlanCatalogDiagnostics.sanitizeCode(
                "invalid_token\nAuthorization: Bearer token"));
        assertEquals("", ChatGptPlanCatalogDiagnostics.sanitizeCode("<script>alert(1)</script>"));
        assertEquals("", ChatGptPlanCatalogDiagnostics.sanitizeCode(""));
        assertEquals("", ChatGptPlanCatalogDiagnostics.sanitizeCode(null));
        String message = ChatGptPlanCatalogDiagnostics.httpError(403, "subscription_sharing_user_not_eligible");
        assertTrue(message.contains("subscription_sharing_user_not_eligible"));
        assertFalse(message.contains("Bearer"));
    }

    @Test public void differentEmptyCatalogCausesAreDistinguished() {
        String noModels = ChatGptPlanCatalogDiagnostics.emptyCatalog(0, 0);
        String noVisible = ChatGptPlanCatalogDiagnostics.emptyCatalog(9, 0);
        String invalid = ChatGptPlanCatalogDiagnostics.emptyCatalog(9, 2);
        assertNotEquals(noModels, noVisible);
        assertNotEquals(noVisible, invalid);
        assertTrue(noVisible.contains("9"));
    }
}
