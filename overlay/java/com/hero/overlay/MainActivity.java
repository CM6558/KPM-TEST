package com.hero.overlay;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/** 申请悬浮窗权限并启动 OverlayService；全部英雄数据在本界面表格里展示。 */
public class MainActivity extends Activity {
    private TextView status;
    private TextView table;
    private String lastJson = null;
    private final Handler h = new Handler(Looper.getMainLooper());

    private final Runnable tick = new Runnable() {
        @Override public void run() {
            if (status != null) {
                String line = HeroState.line == null ? "-- · --" : HeroState.line;
                String ts = HeroState.ts == 0 ? "从未更新"
                        : new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date(HeroState.ts));
                status.setText("悬浮窗: " + line + "\n最后更新: " + ts
                        + "\n(悬浮窗只显示: 人数 · 距离 · 方向°)");
            }
            String j = HeroState.json;
            if (table != null && j != null && !j.equals(lastJson)) {
                lastJson = j;
                table.setText(buildTable(j));
            }
            h.postDelayed(this, 300);
        }
    };

    /** 把 WS 的完整 JSON 渲染成等宽表格: 每英雄一行 + 技能一行 */
    private String buildTable(String json) {
        StringBuilder sb = new StringBuilder();
        try {
            JSONObject o = new JSONObject(json);
            JSONArray arr = o.getJSONArray("heroes");
            int meCamp = 0, meX = 0, meZ = 0;
            boolean haveMe = false;
            for (int i = 0; i < arr.length(); i++) {
                JSONObject x = arr.getJSONObject(i);
                if (x.optInt("me") == 1) {
                    meCamp = x.optInt("camp"); meX = x.optInt("x"); meZ = x.optInt("z");
                    haveMe = true; break;
                }
            }
            sb.append(String.format(Locale.US, "seq=%d  n=%d  我方=%s\n",
                    o.optInt("seq"), o.optInt("n"), haveMe ? ("阵营" + meCamp) : "未识别"));
            sb.append("阵 英雄 对象   HP/HPmax  Lv   金币   距离  C#坐标(x,z)     原生坐标(x,z)   V C D 装备\n");
            for (int i = 0; i < arr.length(); i++) {
                JSONObject x = arr.getJSONObject(i);
                int camp = x.optInt("camp"), hero = x.optInt("heroid"), objid = x.optInt("objid");
                int hp = x.optInt("hp"), hpmax = x.optInt("hpmax");
                int lvl = x.optInt("lvl"), gold = x.optInt("gold");
                int px = x.optInt("x"), pz = x.optInt("z");
                int mx = x.optInt("mx"), mz = x.optInt("mz");
                int lvis = x.optInt("lvis"), cam = x.optInt("cam"), dead = x.optInt("dead");
                boolean enemy = haveMe && camp != meCamp;
                double d = enemy ? Math.hypot(px - meX, pz - meZ) / 100.0 : -1;

                StringBuilder eq = new StringBuilder();
                JSONArray eqa = x.optJSONArray("eq");
                if (eqa != null) for (int k = 0; k < eqa.length(); k++) {
                    JSONArray e = eqa.optJSONArray(k);
                    if (e != null && e.length() >= 2 && e.optInt(0) != 0)
                        eq.append(e.optInt(0)).append('/').append(e.optInt(1)).append(' ');
                }
                sb.append(String.format(Locale.US,
                        "%s %-4d %-4d %5d/%-5d %2d %6d %6s (%6.1f,%6.1f) (%6.1f,%6.1f) %d %d %d %s\n",
                        camp == 1 ? "蓝" : (camp == 2 ? "红" : "?"), hero, objid,
                        hp, hpmax, lvl, gold,
                        d < 0 ? "-" : String.format(Locale.US, "%.1f", d),
                        px / 100.0, pz / 100.0, mx / 100.0, mz / 100.0,
                        lvis, cam, dead, eq));

                JSONArray sk = x.optJSONArray("skills");
                if (sk != null && sk.length() > 0) {
                    sb.append("     技: ");
                    for (int k = 0; k < sk.length(); k++) {
                        JSONObject s = sk.optJSONObject(k);
                        if (s == null) continue;
                        sb.append(String.format(Locale.US, "%d:%d/%d%s%s ",
                                k, s.optInt("cd"), s.optInt("cdmax"),
                                s.optInt("ready") == 1 ? "R" : "",
                                s.optInt("lvlup") == 1 ? "+" : ""));
                    }
                    sb.append('\n');
                }
            }
            sb.append("\nV=逻辑可见 C=在相机内 D=死亡；技能 cd/cdmax，R=就绪，+=可升级");
        } catch (Exception e) {
            sb.append("解析失败: ").append(e);
        }
        return sb.toString();
    }

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(40, 100, 40, 40);

        Button b1 = new Button(this); b1.setText("1) 授予悬浮窗权限");
        b1.setOnClickListener(v -> {
            if (Build.VERSION.SDK_INT >= 23 && !Settings.canDrawOverlays(this)) {
                startActivity(new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                        Uri.parse("package:" + getPackageName())));
            } else Toast.makeText(this, "已授权", Toast.LENGTH_SHORT).show();
        });
        root.addView(b1);

        Button b2 = new Button(this); b2.setText("2) 启动悬浮窗");
        b2.setOnClickListener(v -> {
            if (Build.VERSION.SDK_INT >= 23 && !Settings.canDrawOverlays(this))
                Toast.makeText(this, "请先授予悬浮窗权限", Toast.LENGTH_SHORT).show();
            else {
                startForegroundService(new Intent(this, OverlayService.class));
                Toast.makeText(this, "已启动 (需桥接在跑)", Toast.LENGTH_SHORT).show();
            }
        });
        root.addView(b2);

        Button b3 = new Button(this); b3.setText("3) 停止");
        b3.setOnClickListener(v -> stopService(new Intent(this, OverlayService.class)));
        root.addView(b3);

        status = new TextView(this);
        status.setTextSize(11f);
        status.setTypeface(Typeface.MONOSPACE);
        status.setTextIsSelectable(true);
        status.setText("...(等待数据)");
        root.addView(status);

        table = new TextView(this);
        table.setTextSize(9.5f);
        table.setTypeface(Typeface.MONOSPACE);
        table.setTextIsSelectable(true);
        table.setText("...(等待英雄数据)");
        root.addView(table);

        ScrollView sv = new ScrollView(this);
        sv.addView(root, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        setContentView(sv);

        h.post(tick);
    }

    @Override protected void onDestroy() { h.removeCallbacks(tick); super.onDestroy(); }
}
