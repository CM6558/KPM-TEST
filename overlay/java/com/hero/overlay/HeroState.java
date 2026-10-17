package com.hero.overlay;

/**
 * OverlayService 与 MainActivity 之间的共享状态 (同一进程, 静态即可)。
 * 悬浮窗只显示 line; 原文/状态 raw 只在 App 界面里展示。
 */
public final class HeroState {
    public static volatile String line = "-- · --";   // 悬浮窗那一行: 人数 · 距离 · 箭头
    public static volatile String raw  = "...";       // 原始 JSON / 状态 (App 内显示)
    public static volatile String json = null;        // 最新完整 JSON (供 App 解析成表格)
    public static volatile long   ts   = 0L;          // 最近更新时间

    private HeroState() {}
}
