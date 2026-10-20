package com.packetanalyzer;

import java.util.Locale;

enum AppType {
    UNKNOWN("Unknown"),
    HTTP("HTTP"),
    HTTPS("HTTPS"),
    DNS("DNS"),
    TLS("TLS"),
    QUIC("QUIC"),
    GOOGLE("Google"),
    FACEBOOK("Facebook"),
    YOUTUBE("YouTube"),
    TWITTER("Twitter/X"),
    INSTAGRAM("Instagram"),
    NETFLIX("Netflix"),
    AMAZON("Amazon"),
    MICROSOFT("Microsoft"),
    APPLE("Apple"),
    WHATSAPP("WhatsApp"),
    TELEGRAM("Telegram"),
    TIKTOK("TikTok"),
    SPOTIFY("Spotify"),
    ZOOM("Zoom"),
    DISCORD("Discord"),
    GITHUB("GitHub"),
    CLOUDFLARE("Cloudflare");

    final String displayName;

    AppType(String displayName) {
        this.displayName = displayName;
    }

    static AppType fromName(String name) {
        String sought = name.trim().toLowerCase(Locale.ROOT);
        for (AppType type : values()) {
            if (type.displayName.toLowerCase(Locale.ROOT).equals(sought) ||
                    type.name().toLowerCase(Locale.ROOT).equals(sought)) {
                return type;
            }
        }
        return null;
    }

    static AppType classify(String domain) {
        if (domain == null || domain.isEmpty()) return UNKNOWN;
        String value = domain.toLowerCase(Locale.ROOT);
        if (containsAny(value, "youtube", "ytimg", "youtu.be")) return YOUTUBE;
        if (containsAny(value, "instagram", "cdninstagram")) return INSTAGRAM;
        if (containsAny(value, "whatsapp", "wa.me")) return WHATSAPP;
        if (containsAny(value, "facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")) return FACEBOOK;
        if (containsAny(value, "twitter", "twimg", "x.com", "t.co")) return TWITTER;
        if (containsAny(value, "netflix", "nflxvideo", "nflximg")) return NETFLIX;
        if (containsAny(value, "amazon", "amazonaws", "cloudfront")) return AMAZON;
        if (containsAny(value, "microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")) return MICROSOFT;
        if (containsAny(value, "apple", "icloud", "mzstatic", "itunes")) return APPLE;
        if (containsAny(value, "telegram", "t.me")) return TELEGRAM;
        if (containsAny(value, "tiktok", "musical.ly", "bytedance")) return TIKTOK;
        if (containsAny(value, "spotify", "scdn.co")) return SPOTIFY;
        if (value.contains("zoom")) return ZOOM;
        if (containsAny(value, "discord", "discordapp")) return DISCORD;
        if (containsAny(value, "github", "githubusercontent")) return GITHUB;
        if (containsAny(value, "cloudflare", "cf-")) return CLOUDFLARE;
        if (containsAny(value, "google", "gstatic", "googleapis", "ggpht", "gvt1")) return GOOGLE;
        return HTTPS;
    }

    private static boolean containsAny(String value, String... tokens) {
        for (String token : tokens) {
            if (value.contains(token)) return true;
        }
        return false;
    }
}
