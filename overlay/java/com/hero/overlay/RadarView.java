package com.hero.overlay;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.drawable.GradientDrawable;
import android.view.View;

import java.util.ArrayList;

/** 全图浮窗：固定地图坐标系（不跟随我），红点=人，绿点=我，带名字。
 *  阵营1（蓝，左下）：x→右, z→上；阵营2（红，右上）：旋转 180°。 */
public class RadarView extends View {
    public static class Item {
        public String name;
        public float x, z;          /* 世界坐标 (cm) */
        public boolean enemy, me, dead, vis;
        public Item(String n, float x, float z, boolean e, boolean m, boolean d, boolean vis) {
            this.name = n; this.x = x; this.z = z; this.enemy = e; this.me = m; this.dead = d; this.vis = vis;
        }
    }

    private final ArrayList<Item> items = new ArrayList<>();
    private float halfCm = 6000f;    /* 地图半径 60m (坐标单位 cm) */
    private int myCamp = 1;
    private final Paint ring = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint dot  = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint txt  = new Paint(Paint.ANTI_ALIAS_FLAG);

    public RadarView(Context c) {
        super(c);
        ring.setStyle(Paint.Style.STROKE);
        ring.setColor(0x55FFFFFF);
        dot.setStyle(Paint.Style.FILL);
        txt.setColor(0xFFFFFFFF);
        GradientDrawable bg = new GradientDrawable();
        bg.setShape(GradientDrawable.RECTANGLE);
        bg.setColor(0x59000000);
        setBackground(bg);
    }

    public void setData(ArrayList<Item> list, int camp, float halfCm) {
        items.clear();
        if (list != null) items.addAll(list);
        this.myCamp = camp;
        this.halfCm = halfCm > 1000 ? halfCm : 6000f;
        invalidate();
    }

    @Override protected void onDraw(Canvas c) {
        int w = getWidth(), h = getHeight();
        float cx = w / 2f, cy = h / 2f;
        float half = Math.min(w, h) / 2f - 6f;
        ring.setStrokeWidth(Math.max(2f, half * 0.02f));
        c.drawRect(cx - half, cy - half, cx + half, cy + half, ring);
        Paint thin = new Paint(ring);
        thin.setStrokeWidth(Math.max(1f, half * 0.008f));
        c.drawLine(cx, cy - half, cx, cy + half, thin);
        c.drawLine(cx - half, cy, cx + half, cy, thin);

        float dotR = Math.max(3f, half * 0.045f);
        txt.setTextSize(Math.max(8f, half * 0.10f));
        txt.setShadowLayer(2f, 0f, 1f, 0xFF000000);

        for (Item it : items) {
            float fx = it.x / halfCm, fz = it.z / halfCm;      /* -1..1 */
            if (fx > 1f) fx = 1f; if (fx < -1f) fx = -1f;
            if (fz > 1f) fz = 1f; if (fz < -1f) fz = -1f;
            float px, py;
            if (myCamp == 2) { px = cx - fx * half * 0.94f; py = cy + fz * half * 0.94f; }
            else             { px = cx + fx * half * 0.94f; py = cy - fz * half * 0.94f; }

            if (it.me) dot.setColor(0xFF39FF14);
            else if (it.dead) dot.setColor(0xFF777777);
            else if (it.enemy) dot.setColor(0xFFFF2D2D);
            else dot.setColor(0xFFFF9A9A);
            c.drawCircle(px, py, it.me ? dotR * 1.15f : dotR, dot);
            if (it.name != null && it.name.length() > 0) {
                float tw = txt.measureText(it.name);
                float tx = px - tw / 2f;
                float ty = py - dotR - 3f;
                if (ty < txt.getTextSize()) ty = py + dotR + txt.getTextSize();
                c.drawText(it.name, tx, ty, txt);
            }
        }
    }
}
