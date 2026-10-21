package com.hero.overlay;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Hero 监控主界面:
 * 1. 服务状态看板 (悬浮窗服务、WS桥接状态、KPM后端模块、数据流统计)
 * 2. 一键启动 / 停止功能 (一键启动全套 Root 模块+桥接+悬浮窗、模块化控制)
 * 3. 实时英雄战局状态等宽表格展示
 */
public class MainActivity extends Activity {
    private TextView statusCard;
    private TextView table;
    private String lastJson = null;
    private final Handler h = new Handler(Looper.getMainLooper());

    private final Runnable tick = new Runnable() {
        @Override public void run() {
            updateStatusView();
            String j = HeroState.json;
            if (table != null && j != null && !j.equals(lastJson)) {
                lastJson = j;
                table.setText(buildTable(j));
            }
            h.postDelayed(this, 300);
        }
    };

    private void updateStatusView() {
        if (statusCard == null) return;
        StringBuilder sb = new StringBuilder();

        // 1. 悬浮窗前台服务状态
        boolean ovRunning = HeroState.overlayRunning;
        sb.append(ovRunning ? "【悬浮窗服务: 🟢 运行中】" : "【悬浮窗服务: ⚪ 未运行】");

        // 2. WS 桥接通信状态
        sb.append("  ").append(HeroState.wsConnected ? "【WS通信: 🟢 正常】" : "【WS通信: 🔴 断开】").append("\n");
        sb.append("WS状态详情: ").append(HeroState.wsStatus).append("\n");

        // 3. 后端环境与模块状态
        sb.append("底层服务状态: ").append(HeroState.backendStatus).append("\n");

        // 4. 数据帧与英雄统计
        String ts = HeroState.ts == 0 ? "未收到数据"
                : new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date(HeroState.ts));
        sb.append(String.format(Locale.US, "数据统计: 接收 %d 帧 | 当前英雄: %d 人 | 更新: %s\n",
                HeroState.frameCount, HeroState.heroCount, ts));

        // 5. 悬浮窗实时内容摘要
        String line = (HeroState.line == null || HeroState.line.isEmpty()) ? "-- · --" : HeroState.line;
        sb.append("悬浮窗预览: ").append(line);

        statusCard.setText(sb.toString());
    }

    /** 执行 Root 命令 (子线程) */
    private void executeRootCommand(final String cmd, final String hintMsg, final Runnable onDone) {
        Toast.makeText(this, hintMsg, Toast.LENGTH_SHORT).show();
        new Thread(() -> {
            try {
                Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", cmd});
                p.waitFor();
            } catch (Exception e) {
                // ignore
            }
            // 稍等 800ms 后检测后端状态
            try { Thread.sleep(800); } catch (Exception ignored) {}
            checkBackendStatus(onDone);
        }).start();
    }

    /** 检测后端 (KPM模块 + 端口8787 + 游戏状态) */
    private void checkBackendStatus(final Runnable onDone) {
        new Thread(() -> {
            boolean wsPortOpen = false;
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress("127.0.0.1", 8787), 400);
                wsPortOpen = true;
            } catch (Exception ignored) {}

            String modInfo = "未加载";
            String gameInfo = "未运行";
            try {
                Process p = Runtime.getRuntime().exec(new String[]{"su", "-c",
                        "/data/adb/ksud kpm list 2>/dev/null; pidof com.tencent.tmgp.sgame 2>/dev/null"});
                BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.contains("hero-reader")) modInfo = "已加载";
                    else if (line.matches("^[0-9 ]+$")) gameInfo = "PID:" + line.trim().split(" ")[0];
                }
                p.waitFor();
            } catch (Exception e) {
                modInfo = "免Root(未探测)";
            }

            final String res = (wsPortOpen ? "WS(8787)🟢" : "WS(8787)🔴")
                    + " | 模块:" + modInfo
                    + " | 游戏:" + gameInfo;

            runOnUiThread(() -> {
                HeroState.backendStatus = res;
                updateStatusView();
                if (onDone != null) onDone.run();
            });
        }).start();
    }

    /** 把 WS 的完整 JSON 渲染成等宽表格 */
    private String buildTable(String json) {
        StringBuilder sb = new StringBuilder();
        try {
            JSONObject o = new JSONObject(json);
            JSONArray arr = o.getJSONArray("heroes");
            int meCamp = 0, meX = 0, meZ = 0;
            boolean haveMe = false;
            int savedMe = getSharedPreferences("hero", MODE_PRIVATE).getInt("me_heroid", 0);
            for (int i = 0; i < arr.length(); i++) {
                JSONObject x = arr.getJSONObject(i);
                if (x.optInt("me") == 1 || (savedMe > 0 && x.optInt("heroid") == savedMe)) {
                    meCamp = x.optInt("camp"); meX = x.optInt("x"); meZ = x.optInt("z");
                    haveMe = true; break;
                }
            }
            if (!haveMe && arr.length() > 0) {
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject x = arr.getJSONObject(i);
                    if (x.optInt("camp") == 1) {
                        meCamp = x.optInt("camp"); meX = x.optInt("x"); meZ = x.optInt("z");
                        haveMe = true; break;
                    }
                }
            }
            sb.append(String.format(Locale.US, "seq=%d  n=%d  我方=%s\n",
                    o.optInt("seq"), o.optInt("n"), haveMe ? ("阵营" + meCamp) : "未锁定(默认推导)"));
            sb.append("名称(ID)   阵 距离   位置(x,z) m     视野 屏   HP/HPmax    Lv 金币    装备\n");
            sb.append("----------------------------------------------------------------------------\n");
            for (int i = 0; i < arr.length(); i++) {
                JSONObject x = arr.getJSONObject(i);
                int camp = x.optInt("camp"), hero = x.optInt("heroid"), objid = x.optInt("objid");
                int hp = x.optInt("hp"), hpmax = x.optInt("hpmax");
                int lvl = x.optInt("lvl"), gold = x.optInt("gold");
                int px = x.optInt("x"), pz = x.optInt("z");
                int mx = x.optInt("mx"), mz = x.optInt("mz");
                int lvis = x.optInt("lvis"), cam = x.optInt("cam"), dead = x.optInt("dead");
                boolean enemy = haveMe && camp != meCamp;
                double d = (enemy && haveMe) ? Math.hypot(px - meX, pz - meZ) / 100.0 : -1;

                StringBuilder eq = new StringBuilder();
                JSONArray eqa = x.optJSONArray("eq");
                if (eqa != null) for (int k = 0; k < eqa.length(); k++) {
                    JSONArray e = eqa.optJSONArray(k);
                    if (e != null && e.length() >= 2 && e.optInt(0) != 0)
                        eq.append(e.optInt(0)).append('/').append(e.optInt(1)).append(' ');
                }
                String nm = x.optString("name", "?");
                String vis = dead == 1 ? "死亡" : (lvis == 1 ? "可见" : "雾中");
                String scr = cam == 1 ? "屏内" : "屏外";
                boolean nativeOk = (mx != 0 || mz != 0);
                sb.append(String.format(Locale.US,
                        "%-9s %s %5s (%6.1f,%6.1f)%s %-3s %-3s %5d/%-5d %2d %6d %s\n",
                        nm + "(" + hero + ")",
                        camp == 1 ? "蓝" : (camp == 2 ? "红" : "?"),
                        d < 0 ? "-" : String.format(Locale.US, "%.1fm", d),
                        px / 100.0, pz / 100.0, nativeOk ? "" : "*",
                        vis, scr, hp, hpmax, lvl, gold, eq));

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
            sb.append("\n视野=逻辑可见(可见/雾中)  屏=在相机内  *=原生缺失，用C#兜底");
        } catch (Exception e) {
            sb.append("解析失败: ").append(e);
        }
        return sb.toString();
    }

    private Button createStyledButton(String text, int bgColor, int textColor) {
        Button btn = new Button(this);
        btn.setText(text);
        btn.setTextColor(textColor);
        btn.setTextSize(13f);
        btn.setTypeface(Typeface.DEFAULT_BOLD);
        GradientDrawable gd = new GradientDrawable();
        gd.setColor(bgColor);
        gd.setCornerRadius(16);
        btn.setBackground(gd);
        btn.setPadding(20, 20, 20, 20);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 8, 0, 8);
        btn.setLayoutParams(lp);
        return btn;
    }

    private void showHeroSelectDialog() {
        String json = HeroState.json;
        if (json == null || json.isEmpty()) {
            Toast.makeText(this, "暂未收到英雄数据，请稍候...", Toast.LENGTH_SHORT).show();
            return;
        }
        try {
            JSONObject o = new JSONObject(json);
            JSONArray arr = o.getJSONArray("heroes");
            if (arr.length() == 0) {
                Toast.makeText(this, "当前无活跃英雄", Toast.LENGTH_SHORT).show();
                return;
            }
            final String[] items = new String[arr.length()];
            final int[] heroIds = new int[arr.length()];
            final int[] camps = new int[arr.length()];
            for (int i = 0; i < arr.length(); i++) {
                JSONObject h = arr.getJSONObject(i);
                int hid = h.optInt("heroid");
                int cmp = h.optInt("camp");
                String name = h.optString("name", "英雄");
                items[i] = String.format(Locale.US, "%s (ID: %d) [%s方]",
                        name, hid, cmp == 1 ? "蓝" : (cmp == 2 ? "红" : "?"));
                heroIds[i] = hid;
                camps[i] = cmp;
            }
            new AlertDialog.Builder(this)
                    .setTitle("选择您正在操作的本机英雄")
                    .setItems(items, (dialog, which) -> {
                        int selectedId = heroIds[which];
                        int selectedCamp = camps[which];
                        getSharedPreferences("hero", MODE_PRIVATE).edit()
                                .putInt("me_heroid", selectedId).apply();
                        executeRootCommand("/data/adb/ksud kpm control hero-reader 'setme " + selectedId + " " + selectedCamp + "'",
                                "已锁定操作英雄: " + items[which], null);
                    })
                    .setNegativeButton("取消", null)
                    .show();
        } catch (Exception e) {
            Toast.makeText(this, "解析失败: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(30, 60, 30, 40);

        // 标题
        TextView title = new TextView(this);
        title.setText("Hero 实时雷达与测距管理");
        title.setTextSize(18f);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setPadding(0, 0, 0, 16);
        root.addView(title);

        // 1. 服务状态看板 Card
        statusCard = new TextView(this);
        statusCard.setTextSize(11.5f);
        statusCard.setTypeface(Typeface.MONOSPACE);
        statusCard.setTextIsSelectable(true);
        statusCard.setPadding(24, 20, 24, 20);
        statusCard.setTextColor(Color.parseColor("#E0E0E0"));
        GradientDrawable cardBg = new GradientDrawable();
        cardBg.setColor(Color.parseColor("#1E2430"));
        cardBg.setCornerRadius(18);
        cardBg.setStroke(2, Color.parseColor("#34495E"));
        statusCard.setBackground(cardBg);
        LinearLayout.LayoutParams cardLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        cardLp.setMargins(0, 4, 0, 16);
        statusCard.setLayoutParams(cardLp);
        statusCard.setText("正在检测服务状态...");
        root.addView(statusCard);

        // 2. 一键启动核心大按钮
        Button btnStartAll = createStyledButton("🚀 一键启动全部服务 (Root + 悬浮窗)",
                Color.parseColor("#27AE60"), Color.WHITE);
        btnStartAll.setOnClickListener(v -> {
            String startCmd = "if [ -f /data/local/tmp/hero_start.sh ]; then sh /data/local/tmp/hero_start.sh; "
                    + "elif [ -f /data/data/com.termux/files/home/kpmwork/hero_start.sh ]; then sh /data/data/com.termux/files/home/kpmwork/hero_start.sh; fi";

            executeRootCommand(startCmd, "正在一键拉起后端与模块...", () -> {
                if (Build.VERSION.SDK_INT >= 23 && !Settings.canDrawOverlays(this)) {
                    Toast.makeText(this, "后端已启动，请授予悬浮窗权限", Toast.LENGTH_LONG).show();
                    startActivity(new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                            Uri.parse("package:" + getPackageName())));
                } else {
                    startForegroundService(new Intent(this, OverlayService.class));
                    Toast.makeText(this, "全部服务与悬浮窗已成功启动！", Toast.LENGTH_SHORT).show();
                }
            });
        });
        root.addView(btnStartAll);

        Button btnStopAll = createStyledButton("⏹ 一键停止全部服务 (Root + 悬浮窗)",
                Color.parseColor("#C0392B"), Color.WHITE);
        btnStopAll.setOnClickListener(v -> {
            stopService(new Intent(this, OverlayService.class));
            String stopCmd = "if [ -f /data/local/tmp/hero_stop.sh ]; then sh /data/local/tmp/hero_stop.sh; "
                    + "elif [ -f /data/data/com.termux/files/home/kpmwork/hero_stop.sh ]; then sh /data/data/com.termux/files/home/kpmwork/hero_stop.sh; fi";
            executeRootCommand(stopCmd, "正在停止全部底层服务...", () -> {
                Toast.makeText(this, "已彻底停止后台与悬浮窗", Toast.LENGTH_SHORT).show();
            });
        });
        root.addView(btnStopAll);

        // 3. 悬浮窗分步控制行
        LinearLayout row1 = new LinearLayout(this);
        row1.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rowLp.setMargins(0, 4, 0, 4);
        row1.setLayoutParams(rowLp);

        Button btnOvStart = new Button(this);
        btnOvStart.setText("启动悬浮窗");
        btnOvStart.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnOvStart.setOnClickListener(v -> {
            if (Build.VERSION.SDK_INT >= 23 && !Settings.canDrawOverlays(this)) {
                Toast.makeText(this, "请先授予悬浮窗权限", Toast.LENGTH_SHORT).show();
            } else {
                startForegroundService(new Intent(this, OverlayService.class));
                Toast.makeText(this, "悬浮窗已启动", Toast.LENGTH_SHORT).show();
            }
        });
        row1.addView(btnOvStart);

        Button btnOvStop = new Button(this);
        btnOvStop.setText("关闭悬浮窗");
        btnOvStop.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnOvStop.setOnClickListener(v -> {
            stopService(new Intent(this, OverlayService.class));
            Toast.makeText(this, "悬浮窗已关闭", Toast.LENGTH_SHORT).show();
        });
        row1.addView(btnOvStop);

        Button btnPerm = new Button(this);
        btnPerm.setText("悬浮窗权限");
        btnPerm.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnPerm.setOnClickListener(v -> {
            if (Build.VERSION.SDK_INT >= 23 && !Settings.canDrawOverlays(this)) {
                startActivity(new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                        Uri.parse("package:" + getPackageName())));
            } else {
                Toast.makeText(this, "悬浮窗权限已就绪", Toast.LENGTH_SHORT).show();
            }
        });
        row1.addView(btnPerm);
        root.addView(row1);

        // 4. 刷新状态与自身英雄锁定按钮行
        LinearLayout row2 = new LinearLayout(this);
        row2.setOrientation(LinearLayout.HORIZONTAL);
        row2.setLayoutParams(rowLp);

        Button btnLockMe = new Button(this);
        btnLockMe.setText("🎯 锁定本机英雄");
        btnLockMe.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnLockMe.setOnClickListener(v -> showHeroSelectDialog());
        row2.addView(btnLockMe);

        Button btnRefresh = new Button(this);
        btnRefresh.setText("🔄 刷新状态");
        btnRefresh.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnRefresh.setOnClickListener(v -> checkBackendStatus(() -> {
            Toast.makeText(this, "状态已刷新", Toast.LENGTH_SHORT).show();
        }));
        row2.addView(btnRefresh);
        root.addView(row2);

        // 5. 战局表格展示
        TextView tblLabel = new TextView(this);
        tblLabel.setText("\n实时战局数据详情 (等宽监控表):");
        tblLabel.setTypeface(Typeface.DEFAULT_BOLD);
        tblLabel.setTextSize(13f);
        root.addView(tblLabel);

        table = new TextView(this);
        table.setTextSize(9.5f);
        table.setTypeface(Typeface.MONOSPACE);
        table.setTextIsSelectable(true);
        table.setText("...(等待战局数据)");
        root.addView(table);

        ScrollView sv = new ScrollView(this);
        sv.addView(root, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        setContentView(sv);

        // 初始化
        checkBackendStatus(null);
        h.post(tick);
    }

    @Override protected void onDestroy() {
        h.removeCallbacks(tick);
        super.onDestroy();
    }
}
