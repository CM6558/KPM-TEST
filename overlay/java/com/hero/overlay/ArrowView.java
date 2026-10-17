package com.hero.overlay;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.drawable.GradientDrawable;
import android.view.View;

/** 只画一根精确指向最近敌人的箭头（无任何数字/文字）。 */
public class ArrowView extends View {
    private float deg = -1f;                    // 0..360，-1 = 无敌人
    private final Paint ring = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint head = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint tail = new Paint(Paint.ANTI_ALIAS_FLAG);

    public ArrowView(Context c) {
        super(c);
        ring.setStyle(Paint.Style.STROKE);
        ring.setColor(0x55FFFFFF);
        head.setStyle(Paint.Style.STROKE);
        head.setColor(0xFF39FF14);
        tail.setStyle(Paint.Style.STROKE);
        tail.setColor(0x8839FF14);
        GradientDrawable bg = new GradientDrawable();
        bg.setShape(GradientDrawable.OVAL);
        bg.setColor(0x59000000);
        setBackground(bg);
    }

    /** 屏幕方向角（已按阵营做世界→屏幕变换）：0°=屏幕右，90°=屏幕上 */
    public void setAngle(float d) {
        if ((d < 0) != (deg < 0) || Math.abs(d - deg) > 0.2f) {
            deg = d;
            invalidate();
        }
    }

    @Override protected void onDraw(Canvas c) {
        int w = getWidth(), h = getHeight();
        float cx = w / 2f, cy = h / 2f;
        float r = Math.min(w, h) / 2f - 6f;

        ring.setStrokeWidth(Math.max(2f, r * 0.045f));
        c.drawCircle(cx, cy, r * 0.97f, ring);

        if (deg < 0) return;                    // 无敌人：只留一个空圈

        double a = Math.toRadians(deg);
        /* 屏幕 y 向下，世界 z 向上 -> 用 -sin */
        float ux = (float) Math.cos(a), uy = (float) -Math.sin(a);
        float sx = cx + ux * r * 0.20f, sy = cy + uy * r * 0.20f;
        float ex = cx + ux * r * 0.86f, ey = cy + uy * r * 0.86f;

        tail.setStrokeWidth(Math.max(3f, r * 0.10f));
        tail.setStrokeCap(Paint.Cap.ROUND);
        c.drawLine(sx, sy, ex, ey, tail);

        head.setStrokeWidth(Math.max(4f, r * 0.12f));
        head.setStrokeCap(Paint.Cap.ROUND);
        double d1 = a + Math.toRadians(148), d2 = a - Math.toRadians(148);
        float L = r * 0.30f;
        c.drawLine(ex, ey, ex + (float) Math.cos(d1) * L, ey - (float) Math.sin(d1) * L, head);
        c.drawLine(ex, ey, ex + (float) Math.cos(d2) * L, ey - (float) Math.sin(d2) * L, head);

        /* 小圆点表示"我" */
        head.setStyle(Paint.Style.FILL);
        c.drawCircle(cx, cy, Math.max(3f, r * 0.09f), head);
        head.setStyle(Paint.Style.STROKE);
    }
}
