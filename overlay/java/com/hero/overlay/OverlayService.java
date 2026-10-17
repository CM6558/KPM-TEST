package com.hero.overlay;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.graphics.Typeface;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Random;

/**
 * 前景服务: 连 ws://127.0.0.1:8787/ws, 悬浮窗只显示:
 *   相机范围内敌人数 · 最近敌人距离m · 方向箭头
 * 原文/状态不显示在悬浮窗, 只写入 HeroState 供 App(MainActivity) 查看。
 * 可拖动。
 */
public class OverlayService extends Service {
    private static final String TAG = "heroov";
    /* 相机可见区模型: 以我为原点, 沿地图对角 (+x+z) 为前向的矩形
     * 单位 = 世界坐标 ×100 (cm)。前方比后方远, 横向 = 屏幕宽度。 */
    private static final double CAM_HALF_W = 1150;   /* 横向半宽 11.5m (实测标定) */
    private static final double CAM_FRONT  = 1900;   /* 前方 19m */
    private static final double CAM_BACK   = 1400;   /* 后方 14m */

    private WindowManager wm;
    private FrameLayout box;
    private ArrowView arrow;
    private TextView info;
    private WindowManager.LayoutParams lp;
    private float downX, downY; private int startX, startY;

    private volatile boolean running = true;
    private double myX, myZ; private int myCamp, myFyaw;
    private boolean haveMe;

    @Override public IBinder onBind(Intent i) { return null; }

    @Override public void onCreate() {
        super.onCreate();
        startForeground(1, notif());
        wm = (WindowManager) getSystemService(Context.WINDOW_SERVICE);

        float dens = getResources().getDisplayMetrics().density;
        int sz = (int) (62 * dens);

        box = new FrameLayout(this);
        box.setBackgroundColor(Color.TRANSPARENT);
        box.setPadding(0, 0, 0, 0);

        arrow = new ArrowView(this);
        box.addView(arrow, new FrameLayout.LayoutParams(sz, sz));

        info = new TextView(this);
        info.setTextColor(Color.parseColor("#39FF14"));
        info.setTextSize(9.5f);
        info.setTypeface(Typeface.MONOSPACE);
        info.setGravity(Gravity.CENTER);
        info.setText("--·--");
        FrameLayout.LayoutParams ip = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.WRAP_CONTENT, FrameLayout.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL);
        ip.bottomMargin = (int) (7 * dens);
        box.addView(info, ip);

        int type = (Build.VERSION.SDK_INT >= 26)
                ? WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
                : WindowManager.LayoutParams.TYPE_PHONE;
        lp = new WindowManager.LayoutParams(
                WindowManager.LayoutParams.WRAP_CONTENT,
                WindowManager.LayoutParams.WRAP_CONTENT, type,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                        | WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
                PixelFormat.TRANSLUCENT);
        lp.gravity = Gravity.TOP | Gravity.START; lp.x = 60; lp.y = 220;

        box.setOnTouchListener((v, e) -> {
            switch (e.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    downX = e.getRawX(); downY = e.getRawY();
                    startX = lp.x; startY = lp.y;
                    return true;
                case MotionEvent.ACTION_MOVE:
                    lp.x = startX + (int) (e.getRawX() - downX);
                    lp.y = startY + (int) (e.getRawY() - downY);
                    try { wm.updateViewLayout(box, lp); } catch (Exception ignored) {}
                    return true;
            }
            return false;
        });
        wm.addView(box, lp);

        Thread t = new Thread(this::loop); t.setDaemon(true); t.start();
    }

    private Notification notif() {
        String ch = "hero_overlay";
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationManager nm = getSystemService(NotificationManager.class);
            nm.createNotificationChannel(new NotificationChannel(ch, "Hero", NotificationManager.IMPORTANCE_LOW));
        }
        Notification.Builder b = (Build.VERSION.SDK_INT >= 26)
                ? new Notification.Builder(this, ch) : new Notification.Builder(this);
        return b.setContentTitle("Hero Overlay").setContentText("运行中")
                .setSmallIcon(android.R.drawable.ic_menu_view).build();
    }

    private void loop() {
        while (running) {
            try { runWs(); } catch (Exception e) { setText("-- · --", "断线: " + e); }
            try { Thread.sleep(1000); } catch (InterruptedException e) { break; }
        }
    }

    private void runWs() throws Exception {
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress("127.0.0.1", 8787), 3000);
            s.setSoTimeout(15000);
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();
            byte[] rnd = new byte[16]; new Random().nextBytes(rnd);
            String key = android.util.Base64.encodeToString(rnd, android.util.Base64.NO_WRAP);
            String req = "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
                    + "Connection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\n"
                    + "Sec-WebSocket-Version: 13\r\n\r\n";
            out.write(req.getBytes("UTF-8")); out.flush();
            if (!readHttpLine(in).startsWith("HTTP/1.1 101")) { setText("-- · --", "握手失败"); return; }
            { String h; while (!(h = readHttpLine(in)).isEmpty()) { } }
            setText("-- · --", "已连接, 等待数据...");
            while (running) {
                String payload = readFrame(in);
                if (payload == null) break;
                parseAndShow(payload);
            }
        } finally { s.close(); }
    }

    private String readHttpLine(InputStream in) throws Exception {
        StringBuilder sb = new StringBuilder(); int prev = -1;
        while (true) {
            int c = in.read(); if (c < 0) break;
            if (prev == '\r' && c == '\n') { sb.setLength(sb.length() - 1); break; }
            sb.append((char) c); prev = c;
        }
        return sb.toString();
    }

    private String readFrame(InputStream in) throws Exception {
        int b0 = in.read(); if (b0 < 0) return null;
        int b1 = in.read(); if (b1 < 0) return null;
        int len = b1 & 0x7f;
        if (len == 126) len = (in.read() << 8) | in.read();
        else if (len == 127) { long l = 0; for (int i = 0; i < 8; i++) l = (l << 8) | in.read(); len = (int) l; }
        boolean masked = (b1 & 0x80) != 0;
        byte[] mask = null;
        if (masked) { mask = new byte[4]; readFully(in, mask); }
        byte[] data = new byte[len];
        readFully(in, data);
        if (masked) for (int i = 0; i < data.length; i++) data[i] ^= mask[i % 4];
        return new String(data, "UTF-8");
    }
    private void readFully(InputStream in, byte[] buf) throws Exception {
        int off = 0;
        while (off < buf.length) { int n = in.read(buf, off, buf.length - off); if (n < 0) throw new java.io.EOFException(); off += n; }
    }

    private void parseAndShow(String json) throws Exception {
        JSONObject o = new JSONObject(json);
        JSONArray arr = o.getJSONArray("heroes");
        haveMe = false;
        for (int i = 0; i < arr.length(); i++) {
            JSONObject h = arr.getJSONObject(i);
            if (h.optInt("me") == 1) { myX = h.getInt("x"); myZ = h.getInt("z"); myCamp = h.getInt("camp"); myFyaw = h.optInt("fyaw"); haveMe = true; break; }
        }
        int near = 0;
        double nearest = Double.MAX_VALUE, ndx = 0, ndz = 0;
        int nlvis = -1, nhero = 0;
        if (haveMe) {
            for (int i = 0; i < arr.length(); i++) {
                JSONObject h = arr.getJSONObject(i);
                if (h.getInt("camp") == myCamp) continue;
                if (h.optInt("dead") == 1) continue;
                int hx = h.optInt("x"), hz = h.optInt("z");
                if (Math.abs(hx) > 50000 || Math.abs(hz) > 50000) continue;   /* 哨兵值/无效坐标, 不算敌人 */
                double dx = hx - myX, dz = hz - myZ;
                double d = Math.hypot(dx, dz);
                /* 几何判定(与视野无关): 沿地图对角旋转 45° 的矩形
                 * u=前向, v=横向; 常量由 68 个进出点标定 */
                double u = (dx + dz) * 0.70710678;
                double v = (dx - dz) * 0.70710678;
                if (Math.abs(v) <= CAM_HALF_W && u <= CAM_FRONT && u >= -CAM_BACK) near++;
                if (d < nearest) { nearest = d; ndx = dx; ndz = dz; nlvis = h.optInt("lvis"); nhero = h.getInt("heroid"); }
            }
        }
        String arrowCh = "-";
        String dir = "-";
        double degAll = -1;
        if (nearest != Double.MAX_VALUE) {
            /* (ndx,ndz) = 敌 - 我 (世界坐标), +x=右 +z=上 */
            double deg = Math.toDegrees(Math.atan2(ndz, ndx));
            if (deg < 0) deg += 360.0;
            degAll = deg;
            int k = (int) Math.round(deg / 45.0) % 8;
            arrowCh = new String[]{"→", "↗", "↑", "↖", "←", "↙", "↓", "↘"}[k];
            dir = String.format(Locale.US, "%s%3d°", arrowCh, (int) Math.round(deg) % 360);
        }
        /* 浮窗只画箭头: 把精确角度交给 ArrowView */
        { final float fdeg = (degAll < 0) ? -1f : (float) degAll;
          final String itxt = haveMe
                  ? String.format(Locale.US, "%d \u00b7 %.1fm", near,
                                  nearest == Double.MAX_VALUE ? 0.0 : nearest / 100.0)
                  : "--";
          box.post(() -> { if (arrow != null) arrow.setAngle(fdeg);
                           if (info != null) info.setText(itxt); }); }
        String line1 = haveMe ? String.format(Locale.US, "%2d·%5.1fm %s", near,
                                nearest == Double.MAX_VALUE ? 0.0 : nearest / 100.0, dir)
                              : "no-me";
        String ts = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
        String raw = "seq=" + o.optInt("seq") + " n=" + o.optInt("n") + " me=" + (haveMe ? nhero : -1)
                + " near=" + near + " lvis=" + nlvis
                + " d=(" + (nearest == Double.MAX_VALUE ? "-" : ((int) ndx + "," + (int) ndz)) + ")"
                + " arrow=" + arrowCh + " " + ts + "\n" + json;
        if (raw.length() > 600) raw = raw.substring(0, 600) + " …";
        HeroState.json = json;
        setText(line1, raw);
        Log.d(TAG, "show: " + line1);
    }

    /* 悬浮窗只更新那一行; 原文/状态写入 HeroState, 由 App 界面(MainActivity)显示 */
    private void setText(final String a, final String b) {
        HeroState.line = a;
        HeroState.raw = b;
        HeroState.ts = System.currentTimeMillis();
        /* 浮窗只画箭头，不再显示文字 */
    }

    @Override public void onDestroy() {
        running = false;
        try { wm.removeView(box); } catch (Exception ignored) {}
        super.onDestroy();
    }
}
