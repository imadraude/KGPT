/*
 * GPL-3.0-or-later. Safe, testable catalog failure messages.
 * Never include bearer tokens, server response bodies, or prompt contents.
 */
package tn.eluea.kgpt.chatgpt;

public final class ChatGptPlanCatalogDiagnostics {
    private ChatGptPlanCatalogDiagnostics() { }

    public static String sanitizeCode(String code) {
        return code != null && code.matches("[a-zA-Z0-9_.-]{1,64}") ? code : "";
    }

    public static String httpError(int status, String serverCode) {
        final String explanation;
        switch (status) {
            case 400:
                explanation = "Сервер відхилив запит каталогу.";
                break;
            case 401:
                explanation = "Сервер відхилив авторизацію. Спробуйте підключити ChatGPT повторно.";
                break;
            case 403:
                explanation = "Доступ до каталогу заборонено для цього облікового запису, робочого простору або регіону.";
                break;
            case 404:
                explanation = "Каталог моделей недоступний на сервері.";
                break;
            case 429:
                explanation = "Досягнуто тимчасового обмеження запитів. Спробуйте пізніше.";
                break;
            case 500:
            case 502:
            case 503:
            case 504:
                explanation = "Сервер OpenAI тимчасово недоступний. Спробуйте пізніше.";
                break;
            default:
                explanation = "Не вдалося отримати каталог моделей.";
        }
        String code = sanitizeCode(serverCode);
        return "HTTP " + status + ": " + explanation
                + (code.isEmpty() ? "" : " (код: " + code + ")");
    }

    public static String emptyCatalog(int total, int visible) {
        if (total == 0) return "OpenAI повернув порожній каталог моделей для цього облікового запису.";
        if (visible == 0) return "OpenAI повернув " + total
                + " моделей, але жодна не позначена як доступна для вибору.";
        return "OpenAI повернув моделі, але всі їхні ідентифікатори недійсні.";
    }
}
