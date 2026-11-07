/*
 * Copyright (c) 2025 Amr Aldeeb @Eluea
 * GitHub: https://github.com/Eluea
 * Telegram: https://t.me/Eluea
 *
 * Licensed under the GPLv3.
 */
package tn.eluea.kgpt.util;

import java.util.HashMap;
import java.util.Map;

import tn.eluea.kgpt.llm.LanguageModel;

/**
 * SINGLE SOURCE OF TRUTH for per-provider sub-model presets and valid model
 * names. Used by BOTH the in-app ModelsFragment and the floating
 * ConfigureModelDialogBox so validation/presets can never drift apart again
 * (H1). Data authored from the in-app catalog (the newer of the two).
 */
public final class ModelCatalog {
    private ModelCatalog() {}

    public static final Map<LanguageModel, String[]> PRESETS = new HashMap<>();
    public static final Map<LanguageModel, java.util.Set<String>> VALID = new HashMap<>();

        static {
        // Verified against official OpenAI and Google model docs (November 2026).
        // Gemini: only text-capable generation endpoints, not live/image/TTS.
        PRESETS.put(LanguageModel.Gemini, new String[] {
                "gemini-3.8-flash",
                "gemini-3.7-flash",
                "gemini-3.6-flash",
                "gemini-3.5-flash",
                "gemini-3.5-flash-lite",
                "gemini-3.1-pro-preview",
                "gemini-3.1-flash-lite",
                "gemini-3-flash-preview"
        });
        VALID.put(LanguageModel.Gemini, new java.util.HashSet<>(java.util.Arrays.asList(
                "gemini-3.8-flash", "gemini-3.7-flash", "gemini-3.6-flash",
                "gemini-3.5-flash", "gemini-3.5-flash-lite",
                "gemini-3.1-pro-preview", "gemini-3.1-flash-lite", "gemini-3-flash-preview",
                "gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.5-flash-lite")));

        // OpenAI API keys use the API catalog, independent of ChatGPT subscription.
        PRESETS.put(LanguageModel.ChatGPT, new String[] {
                "gpt-6.1-sol",
                "gpt-6.1-terra",
                "gpt-6-luna",
                "gpt-6-astra",
                "gpt-6-sol",
                "gpt-5.6-sol",
                "gpt-5.6-terra"
        });
        VALID.put(LanguageModel.ChatGPT, new java.util.HashSet<>(java.util.Arrays.asList(
                "gpt-6-astra", "gpt-6.1-sol", "gpt-6.1-terra", "gpt-6-sol",
                "gpt-6-luna", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna",
                "gpt-5.5", "gpt-5.4", "gpt-5.4-mini", "gpt-5")));

        // Plan model availability is account-specific; replace this fallback
        // with GET /v1/models after the user signs in. Never hard-block slugs.
        PRESETS.put(LanguageModel.ChatGPTPlan, new String[] {"gpt-6.1-sol"});
        VALID.put(LanguageModel.ChatGPTPlan, null);

                // Groq: remove the retired groq/compound model (September 2026).
        PRESETS.put(LanguageModel.Groq, new String[] {
                "openai/gpt-oss-120b",
                "openai/gpt-oss-20b",
                "qwen/qwen3.8-27b"
        });
        VALID.put(LanguageModel.Groq, null); // provider catalog varies by account

                // OpenRouter models - August 2026 (Free tier available)
        PRESETS.put(LanguageModel.OpenRouter, new String[] {
                "openrouter/free",
                "nvidia/nemotron-3-ultra:free",
                "openai/gpt-oss-120b:free",
                "qwen/qwen3-coder:free",
                "google/gemini-2.5-flash:free",
                "openai/gpt-4o-mini"
        });
        VALID.put(LanguageModel.OpenRouter, null); // Allow any for OpenRouter

        // Anthropic and Mistral official model catalogs (November 2026).
        PRESETS.put(LanguageModel.Claude, new String[] {
                "claude-sonnet-5-5",
                "claude-haiku-5-5",
                "claude-opus-5-5",
                "claude-fable-5-1",
                "claude-sonnet-5"
        });
        VALID.put(LanguageModel.Claude, null); // allow newly released model aliases

        PRESETS.put(LanguageModel.Mistral, new String[] {
                "mistral-small-2603",
                "mistral-large-4",
                "mistral-small-latest",
                "codestral-latest"
        });
        VALID.put(LanguageModel.Mistral, null);

                // Chutes models - August 2026 latest
        PRESETS.put(LanguageModel.Chutes, new String[] {
                "deepseek-ai/DeepSeek-V3.2",
                "deepseek-ai/DeepSeek-V4-Flash-0731",
                "deepseek-ai/DeepSeek-R1",
                "meta-llama/Llama-3.3-70B-Instruct",
                "Qwen/Qwen2.5-72B-Instruct"
        });
        VALID.put(LanguageModel.Chutes, null); // Allow any model

        // Perplexity models - August 2026 latest (Search-grounded)
        PRESETS.put(LanguageModel.Perplexity, new String[] {
                "sonar-pro",
                "sonar",
                "sonar-reasoning-pro",
                "sonar-deep-research"
        });
        VALID.put(LanguageModel.Perplexity, new java.util.HashSet<>(java.util.Arrays.asList(
                "sonar-pro", "sonar", "sonar-reasoning-pro", "sonar-deep-research")));

        // GLM (ZhipuAI / Z.ai) models - August 2026 latest (GLM-5 generation)
        PRESETS.put(LanguageModel.GLM, new String[] {
                "glm-5.3",
                "glm-5.2",
                "glm-5.1",
                "glm-5",
                "glm-4-plus",
                "glm-4-flash"
        });
        VALID.put(LanguageModel.GLM, new java.util.HashSet<>(java.util.Arrays.asList(
                "glm-5.3", "glm-5.2", "glm-5.1", "glm-5",
                "glm-4-plus", "glm-4-flash", "glm-4-air")));

        // Grok (xAI) models - August 2026 latest
        PRESETS.put(LanguageModel.Grok, new String[] {
                "grok-4.6",
                "grok-4.5",
                "grok-4.3",
                "grok-4",
                "grok-3",
                "grok-2-latest",
                "grok-2",
                "grok-beta"
        });
        VALID.put(LanguageModel.Grok, new java.util.HashSet<>(java.util.Arrays.asList(
                "grok-4.6", "grok-4.5", "grok-4.3", "grok-4", "grok-3",
                "grok-2-latest", "grok-2", "grok-2-vision-1212", "grok-beta")));

        // DeepSeek legacy deepseek-chat/reasoner have been discontinued.
        PRESETS.put(LanguageModel.DeepSeek, new String[] {
                "deepseek-flash",
                "deepseek-v4-pro"
        });
        VALID.put(LanguageModel.DeepSeek, new java.util.HashSet<>(java.util.Arrays.asList(
                "deepseek-flash", "deepseek-v4-pro")));

                // Kimi (Moonshot AI) models - August 2026 latest
        PRESETS.put(LanguageModel.Kimi, new String[] {
                "kimi-k3",
                "kimi-k2.6",
                "kimi-k2.7-code",
                "kimi-k2.5",
                "moonshot-v1-auto",
                "moonshot-v1-8k",
                "moonshot-v1-32k",
                "moonshot-v1-128k"
        });
        VALID.put(LanguageModel.Kimi, new java.util.HashSet<>(java.util.Arrays.asList(
                "kimi-k3", "kimi-k2.6", "kimi-k2.7-code", "kimi-k2.5", "kimi-k2-instruct",
                "moonshot-v1-auto", "moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k")));
    }
}
