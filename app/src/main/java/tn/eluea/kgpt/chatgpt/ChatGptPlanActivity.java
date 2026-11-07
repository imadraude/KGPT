/*
 * GPL-3.0-or-later. Explicit consent and connection UI in the KGPT process.
 */
package tn.eluea.kgpt.chatgpt;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public final class ChatGptPlanActivity extends Activity {
    private TextView status, models;
    private Button login, manual, cancelLogin, discover, disconnect;
    private ChatGptPlanAuth auth;

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (22 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad * 2, pad, pad);
        scroll.addView(root);
        TextView title = new TextView(this);
        title.setText("ChatGPT plan in KGPT");
        title.setTextSize(23);
        root.addView(title);
        status = new TextView(this);
        status.setTextSize(17);
        status.setPadding(0, pad, 0, pad);
        root.addView(status);
        TextView disclosure = new TextView(this);
        disclosure.setText("KGPT sends text to OpenAI only when you invoke an AI action. " +
                "Plan usage shares your ChatGPT usage limits. No ChatGPT token is passed " +
                "to the SwiftKey process. Do not use AI actions on passwords or private data.");
        root.addView(disclosure);
        login = new Button(this);
        login.setText("Continue with ChatGPT");
        root.addView(login);

        manual = new Button(this);
        manual.setText("Вставити посилання з браузера");
        manual.setVisibility(View.GONE);
        root.addView(manual);
        cancelLogin = new Button(this);
        cancelLogin.setText("Скасувати поточний вхід");
        cancelLogin.setVisibility(View.GONE);
        root.addView(cancelLogin);

        discover = new Button(this);
        discover.setText("Show models available to my account");
        root.addView(discover);
        models = new TextView(this);
        root.addView(models);
        Button usage = new Button(this);
        usage.setText("Manage app access in ChatGPT");
        root.addView(usage);
        disconnect = new Button(this);
        disconnect.setText("Disconnect this device (local only)");
        root.addView(disconnect);
        setContentView(scroll);

        try {
            auth = new ChatGptPlanAuth(this);
            refresh();
        } catch (Exception e) {
            status.setText("Secure credential storage unavailable.");
            login.setEnabled(false); discover.setEnabled(false); disconnect.setEnabled(false);
            return;
        }

        login.setOnClickListener(v -> {
            login.setEnabled(false);
            manual.setVisibility(View.VISIBLE);
            cancelLogin.setVisibility(View.VISIBLE);
            status.setText("Виконайте вхід у системному браузері.\n\nЯкщо браузер заблокує повернення на 127.0.0.1, вставте повне посилання з адресного рядка сюди. Під час першого входу потрібне саме повне посилання з code, state і client_id.");
            auth.signIn(this, (message, connected) -> {
                status.setText(message);
                login.setEnabled(!auth.isSignInPending());
                cancelLogin.setVisibility(auth.isSignInPending() ? View.VISIBLE : View.GONE);
                if (connected) {
                    manual.setVisibility(View.GONE);
                    refresh();
                } else if (!auth.isSignInPending()) {
                    manual.setVisibility(View.GONE);
                }
            });
        });

        manual.setOnClickListener(v -> {
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle("Вставити посилання або код");
            builder.setMessage("Вставте повну адресу з браузера. Для першого входу вона має містити code, state та client_id.");
            final EditText input = new EditText(this);
            input.setHint("http://127.0.0.1:.../auth/callback?code=...");
            // A callback can be several kilobytes long. Never let EditText grow
            // to the height of the entire screen and hide the dialog actions.
            float density = getResources().getDisplayMetrics().density;
            input.setSingleLine(false);
            input.setMinLines(2);
            input.setMaxLines(4);
            input.setMaxHeight((int) (120 * density));
            input.setVerticalScrollBarEnabled(true);
            input.setOverScrollMode(View.OVER_SCROLL_IF_CONTENT_SCROLLS);
            LinearLayout inputContainer = new LinearLayout(this);
            inputContainer.setOrientation(LinearLayout.VERTICAL);
            int horizontalPadding = (int) (24 * density);
            inputContainer.setPadding(horizontalPadding, 0, horizontalPadding, 0);
            inputContainer.addView(input, new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT));
            builder.setView(inputContainer);
            builder.setPositiveButton("Підтвердити", (dialog, which) -> {
                String text = input.getText() != null ? input.getText().toString().trim() : "";
                if (!text.isEmpty()) {
                    status.setText("Обробка коду авторизації...");
                    auth.completeWithManualCallback(this, text, (message, connected) -> {
                        status.setText(message);
                        login.setEnabled(!auth.isSignInPending());
                        cancelLogin.setVisibility(auth.isSignInPending() ? View.VISIBLE : View.GONE);
                        if (connected) {
                            manual.setVisibility(View.GONE);
                            refresh();
                        } else if (!auth.isSignInPending()) {
                            manual.setVisibility(View.GONE);
                        }
                    });
                }
            });
            builder.setNegativeButton("Скасувати", null);
            AlertDialog dialog = builder.create();
            // Keep action buttons visible when the soft keyboard is shown.
            dialog.setOnShowListener(ignored -> {
                if (dialog.getWindow() != null) {
                    dialog.getWindow().setSoftInputMode(
                            android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE
                                    | android.view.WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);
                }
            });
            dialog.show();
        });

        cancelLogin.setOnClickListener(v -> {
            auth.cancelSignIn();
            refresh();
        });
        discover.setOnClickListener(v -> loadModels());
        usage.setOnClickListener(v -> startActivity(new Intent(Intent.ACTION_VIEW,
                Uri.parse("https://chatgpt.com"))));
        disconnect.setOnClickListener(v -> {
            try { auth.disconnectLocally(); models.setText(""); refresh(); }
            catch (Exception e) { status.setText("Could not clear local connection"); }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (auth != null) refresh();
    }

    private void refresh() {
        try {
            boolean pending = auth.isSignInPending();
            boolean connected = auth.canUsePlan();
            login.setEnabled(!pending);
            cancelLogin.setVisibility(pending ? View.VISIBLE : View.GONE);
            if (pending) {
                status.setText(auth.requiresManualRecovery()
                        ? "Android перезапустив KGPT під час входу. Вставте повне посилання з браузера або скасуйте вхід."
                        : "Очікування завершення авторизації у браузері…");
                manual.setVisibility(View.VISIBLE);
            } else {
                status.setText(connected
                        ? "Підключено: " + auth.connectedEmail()
                        : "Не підключено. Увійдіть і дозвольте використання підписки.");
                manual.setVisibility(View.GONE);
            }
            discover.setEnabled(connected);
        } catch (Exception e) {
            status.setText("Не вдалося прочитати дані авторизації.");
            login.setEnabled(false);
            discover.setEnabled(false);
        }
    }

    private void loadModels() {
        discover.setEnabled(false);
        models.setText("Отримання моделей, доступних цьому обліковому запису…");
        new Thread(() -> {
            String result;
            try {
                java.util.LinkedHashMap<String, String> available =
                        ChatGptPlanModels.fetch(auth);
                StringBuilder list = new StringBuilder(
                        "Доступні моделі (вибір: KGPT → Models):\n");
                for (java.util.Map.Entry<String, String> m : available.entrySet()) {
                    if (list.length() > 5000) break;
                    list.append(m.getValue()).append(" — ")
                            .append(m.getKey()).append('\n');
                }
                result = list.toString();
            } catch (ChatGptPlanModels.CatalogException e) {
                // Purposefully expose only categorized failure information,
                // never bearer tokens, OAuth responses or raw server bodies.
                result = "Не вдалося отримати моделі:\n" + e.getMessage();
            } catch (SecurityException e) {
                result = "Доступ до підписки втрачено. Повторно підключіть ChatGPT у KGPT.";
            } catch (Exception e) {
                result = "Не вдалося отримати моделі (" + e.getClass().getSimpleName()
                        + "). Перевірте підключення і спробуйте ще раз.";
            }
            String message = result;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                models.setText(message);
                try { discover.setEnabled(auth.canUsePlan()); }
                catch (Exception e) { discover.setEnabled(false); }
            });
        }, "KGPT-ChatGPT-Models").start();
    }
}
