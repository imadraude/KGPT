/*
 * GPL-3.0-or-later. This file runs in the hooked keyboard process.
 * It never handles OAuth access tokens or refresh tokens.
 */
package tn.eluea.kgpt.llm.client;

import android.content.*;
import android.os.*;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscription;
import java.util.concurrent.atomic.AtomicBoolean;
import tn.eluea.kgpt.chatgpt.ChatGptPlanService;
import tn.eluea.kgpt.llm.LanguageModel;
import tn.eluea.kgpt.ui.UiInteractor;

public final class ChatGptPlanClient extends LanguageModelClient {
    @Override public LanguageModel getLanguageModel() { return LanguageModel.ChatGPTPlan; }

    @Override public Publisher<String> submitPrompt(String prompt, String systemMessage) {
        String model = getSubModel();
        String instructions = systemMessage == null ? getDefaultSystemMessage() : systemMessage;
        return subscriber -> {
            Context context = UiInteractor.getInstance().getContext().getApplicationContext();
            Handler ui = new Handler(Looper.getMainLooper());
            AtomicBoolean done = new AtomicBoolean(false);
            AtomicBoolean bound = new AtomicBoolean(false);
            ServiceConnection[] connection = new ServiceConnection[1];
            Runnable[] timer = new Runnable[1];
            Runnable cleanup = () -> {
                if (timer[0] != null) ui.removeCallbacks(timer[0]);
                if (bound.getAndSet(false)) {
                    try { context.unbindService(connection[0]); }
                    catch (IllegalArgumentException ignored) { }
                }
            };
            subscriber.onSubscribe(new Subscription() {
                @Override public void request(long n) {
                    if (n <= 0 && done.compareAndSet(false, true)) {
                        cleanup.run();
                        subscriber.onError(new IllegalArgumentException("Demand must be positive"));
                    }
                }
                @Override public void cancel() {
                    if (done.compareAndSet(false, true)) cleanup.run();
                }
            });
            if (done.get()) return;
            Messenger response = new Messenger(new Handler(Looper.getMainLooper(), msg -> {
                if (msg.what != ChatGptPlanService.RESULT) return true;
                if (!done.compareAndSet(false, true)) return true;
                cleanup.run();
                Bundle data = msg.getData();
                String error = data.getString("error");
                if (error != null) subscriber.onError(new IllegalStateException(error));
                else {
                    String value = data.getString("text", "");
                    if (!value.isEmpty()) subscriber.onNext(value);
                    subscriber.onComplete();
                }
                return true;
            }));
            connection[0] = new ServiceConnection() {
                @Override public void onServiceConnected(ComponentName name, IBinder binder) {
                    if (done.get()) return;
                    Message request = Message.obtain(null, ChatGptPlanService.REQUEST);
                    Bundle data = new Bundle();
                    data.putLong("id", 1);
                    data.putString("prompt", prompt);
                    data.putString("system", instructions);
                    data.putString("model", model);
                    request.setData(data);
                    request.replyTo = response;
                    try { new Messenger(binder).send(request); }
                    catch (RemoteException e) { onServiceDisconnected(name); }
                }
                @Override public void onServiceDisconnected(ComponentName name) {
                    if (done.compareAndSet(false, true)) {
                        cleanup.run();
                        subscriber.onError(new IllegalStateException("KGPT ChatGPT service disconnected"));
                    }
                }
                @Override public void onBindingDied(ComponentName name) {
                    onServiceDisconnected(name);
                }
                @Override public void onNullBinding(ComponentName name) {
                    onServiceDisconnected(name);
                }
            };
            timer[0] = () -> {
                if (done.compareAndSet(false, true)) {
                    cleanup.run();
                    subscriber.onError(new IllegalStateException("ChatGPT request timed out"));
                }
            };
            ui.postDelayed(timer[0], 185000); // refresh (up to 45s) + inference (up to 115s) + IPC
            Intent intent = new Intent().setClassName("tn.eluea.kgpt",
                    "tn.eluea.kgpt.chatgpt.ChatGptPlanService");
            try {
                bound.set(context.bindService(intent, connection[0], Context.BIND_AUTO_CREATE));
                if (!bound.get() && done.compareAndSet(false, true)) {
                    cleanup.run();
                    subscriber.onError(new IllegalStateException("KGPT service unavailable"));
                }
            } catch (Exception e) {
                if (done.compareAndSet(false, true)) {
                    cleanup.run();
                    subscriber.onError(new IllegalStateException("Cannot connect to KGPT service"));
                }
            }
        };
    }
}
