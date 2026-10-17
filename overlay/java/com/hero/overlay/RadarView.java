package com.hero.overlay;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.drawable.GradientDrawable;
import android.view.View;

import java.util.ArrayList;

/** 小地图式浮窗：以我为圆心，红点=人（深红=敌方，浅红=队友），绿点=我，带名字。 */
public class RadarView extends View {
    public static class Item {
        public String name;
        public float u, v;          /* 屏幕基投影: u=上, v=右 (cm) */
        public boolean enemy, me, dead, vis;
        public Item(String n, float u, float v, boolean e, boolean m, boolean d, boolean vis) {
            this.name = n; this.u = u; this.v = v; this.enemy = e; this.me = m; this.dead = d; this.vis = vis;
        }
    }

    private final ArrayList<Item> items = new ArrayList<>();
    private float rangeCm = 4000f;   /* 半径对应 40m */
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
        bg.setShape(GradientDrawable.OVAL);
        bg.setColor(0x59000000);
        setBackground(bg);
    }

    public void setData(ArrayList<Item> list, float rangeCm) {
        items.clear();
        if (list != null) items.addAll(list);
        this.rangeCm = rangeCm > 100 ? rangeCm : 4000f;
        invalidate();
    }

    @Override protected void onDraw(Canvas c) {
        int w = getWidth(), h = getHeight();
        float cx = w / 2f, cy = h / 2f;
        float r = Math.min(w, h) / 2f - 6f;
        ring.setStrokeWidth(Math.max(2f, r * 0.03f));
        c.drawCircle(cx, cy, r * 0.97f, ring);
        /* 十字参考线 */
        Paint thin = new Paint(ring);
        thin.setStrokeWidth(Math.max(1f, r * 0.008f));
        c.drawLine(cx, cy - r * 0.97f, cx, cy + r * 0.97f, thin);
        c.drawLine(cx - r * 0.97f, cy, cx + r * 0.97f, cy, thin);

        float dotR = Math.max(3f, r * 0.055f);
        txt.setTextSize(Math.max(8f, r * 0.115f));
        txt.setShadowLayer(2f, 0f, 1f, 0xFF000000);

        for (Item it : items) {
            float px, py;
            if (it.me) { px = cx; py = cy; }
            else {
                float d = (float) Math.hypot(it.u, it.v);
                float k = d > rangeCm ? rangeCm / d : 1f;   /* 超出半径贴边 */
                px = cx + (it.v * k / rangeCm) * r * 0.92f;
                py = cy - (it.u * k / rangeCm) * r * 0.92f;
            }
            if (it.me) dot.setColor(0xFF39FF14);                 /* 我: 绿 */
            else if (it.dead) dot.setColor(0xFF777777);          /* 死亡: 灰 */
            else if (it.enemy) dot.setColor(0xFFFF2D2D);         /* 敌方: 红 */
            else dot.setColor(0xFFFF9A9A);                       /* 队友: 浅红 */
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
