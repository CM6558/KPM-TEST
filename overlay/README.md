# Hero 实时数据 · 方案B（模块 → 定长seqlock文件 → C桥接 → WebSocket → App悬浮窗）

## 架构
```
[KPM hero-reader] --原地写(seqlock)--> /data/local/tmp/heroes.bin
                                          │ mmap (零拷贝, ~5ms轮询)
                              [hero_bridge (C, root)]  --> ws://127.0.0.1:8787/ws
                                          │
                              [App com.hero.overlay (Java, 无需root)] --> 悬浮窗:「附近敌人数 · 最近距离m」
```
零内核对象（无 /dev、/proc、/sys 新增）；游戏进程（untrusted_app）读不到 `/data/local/tmp`。

---

## 一、模块侧（KPM）
```sh
cd KPM-TEST-work && make KP_DIR=<KP目录>          # 生成 hero_reader.kpm
su -c 'cp hero_reader.kpm /data/local/tmp/'
su -c '/data/adb/ksud kpm load /data/local/tmp/hero_reader.kpm'
su -c '/data/adb/ksud kpm control hero-reader "set <游戏pid>"'
su -c '/data/adb/ksud kpm control hero-reader "herobin /data/local/tmp/heroes.bin 100"'
# 停止: herobin stop ; 卸载: ksud kpm unload hero-reader
```

**一键脚本**（已部署到 `/data/local/tmp/`）：
```sh
su -c 'sh /data/local/tmp/hero_start.sh'          # 启动; 若已在运行 → 默认先停止再重启
su -c 'sh /data/local/tmp/hero_start.sh 100'      # 指定周期 ms (默认 200)
su -c 'sh /data/local/tmp/hero_start.sh keep'     # 已在运行则保持不变(不重启)
su -c 'sh /data/local/tmp/hero_start.sh status'   # 看状态
su -c 'sh /data/local/tmp/hero_stop.sh'           # 结束全部 (herobin/模块/桥接/守护)
su -c 'sh /data/local/tmp/hero_stop.sh clean'     # 结束并删除 heroes.bin
```
- `hero_start.sh` 后台起一个守护：等游戏 → `set <pid>` → `herobin` → 保活桥接；**对局切换/游戏进程重启会自动重新 `set`**。
- 脚本**不含"打开 App"的动作**，悬浮窗仍需在 App 里点「启动悬浮窗」。
- 源码在 `kpmwork/hero_start.sh`、`kpmwork/hero_stop.sh`。

**输出格式**（定长, 原地覆盖, seqlock）：
- 头 64B: `magic=0x48523031("HR01") version=1 seq rec_size=316 max_rec=16 n ts_ms flags rsv[7]`
- 记录 316B × 16（`packed` 小端）:
  `heroid camp objid | hp hpmax exp expmax lvl gold incgold | charge chargemax shield shieldmax | x y z fx fz move groundy | ad def res | atktarget | dead dying grass freeze battle nomove inroom fantasy autoai lvis cam me | eqn | eq[8]{id,cnt} | sk[6]{lvl,ready,lvlup,bean,cd,cdmax,power,powermax,tgt,hit}`
- **seqlock**：`seq` 奇=写入中，偶=稳定；客户端只在偶且前后一致时采用。

## 二、C 桥接
```sh
clang -O2 -o bridge/hero_bridge bridge/hero_bridge.c
su -c 'cp bridge/hero_bridge /data/local/tmp/; chmod 755 /data/local/tmp/hero_bridge'
su -c '/data/local/tmp/hero_bridge /data/local/tmp/heroes.bin 8787'     # 常驻(root)
```
监听 **`ws://127.0.0.1:8787/ws`**，每有新帧推一条文本 JSON；**无新帧时也至少每 1s 推一次心跳**（避免客户端读超时反复重连）。单客户端。

## 三、App（Java，悬浮窗）
源码：`overlay/build/java/com/hero/overlay/{MainActivity,OverlayService}.java` + `AndroidManifest.xml`

**本机构建（Termux，无需 Android Studio）**：
```sh
sh overlay/build/build.sh          # javac → d8 → aapt2 → apksigner, 产物 overlay/build/hero.apk
# 需要 android.jar (SDK platform); 默认路径见脚本 ANDROID_JAR
```

**安装 + 授权 + 启动（root）**：
```sh
su -c 'cp overlay/build/hero.apk /data/local/tmp/; pm install -r /data/local/tmp/hero.apk'
su -c 'appops set com.hero.overlay SYSTEM_ALERT_WINDOW allow'                       # 授悬浮窗权限
su -c 'am start-foreground-service -n com.hero.overlay/.OverlayService'              # 启动悬浮窗
```
或手动：打开 App → 「1) 授予悬浮窗权限」→「2) 启动悬浮窗」→「3) 停止」。
- 显示内容：**`相机内敌人数 · 最近敌人距离m · 方向箭头`**，深色底 + 荧光绿字，仅两个数字+一个箭头。
  - **悬浮窗只显示这一行**；原始 JSON/状态/时间只在 **App 界面**里显示（`MainActivity` 每 0.5s 读 `HeroState`，由 `OverlayService` 写入）。
  - **可拖动**：手指按住浮窗拖动即可移动位置（`FLAG_NOT_TOUCHABLE` 已去掉，加了拖拽手势）。
  - **附近人数 = "位置在相机范围内"的敌人数**：客户端拿不到迷雾敌人的相机判定，故用**以本机英雄为中心的矩形**近似（`CAM_X`/`CAM_Z` = ±26m，可调），不管可见性；
  - **最近距离 = 所有敌人(camp≠我, 未死亡)中的最小距离**（不管在不在相机/可见）。
    注意：**迷雾里的敌人坐标是"上次已知"、不刷新**（MOBA 迷雾机制），所以最近距离可能是旧坐标；
  - **方向箭头**：**世界/地图绝对方向**（从"我"指向最近敌人的方向，**不随我朝向变化**）；
    映射 `atan2(dz,dx)`：`+x=右, +z=上`（k=0→右, 2→上, 4→左, 6→下），`["→","↗","↑","↖","←","↙","↓","↘"]`。

## 四、对外接口（WebSocket）
- URL：`ws://127.0.0.1:8787/ws`（仅本机）
- 每帧一条**文本 JSON**：
```json
{"seq":678,"n":10,"heroes":[
 {"heroid":106,"camp":1,"objid":8,"me":1,"hp":4033,"hpmax":4225,"lvl":6,
  "x":-389,"y":0,"z":-207,"move":564,"fyaw":2808,"ad":206,"def":222,"res":127,
  "dead":0,"dying":0,"grass":0,"freeze":0,"battle":0,"nomove":0,"inroom":0,
  "fantasy":0,"autoai":0,"lvis":1,"cam":1,"atktarget":0,"eqn":1,
  "eq":[[1424,1]],"skills":[{"s":0,"lvl":2,"cd":0,"cdmax":1,"ready":1,"bean":0,"power":0,"powermax":0,"tgt":0,"hit":0,"lvlup":0}, ...]},
 ...
]}
```
- `seq` 递增（偶=稳定）；`me=1` 本机玩家；`camp` 1/2；坐标 `x/z` 单位厘米。

## 五、读取要点
- 一致性：桥接内部已用 seqlock，App 只需按帧处理；`seq` 变化=新帧。
- 陈旧：桥接无新帧不推；游戏不在对局时 `herobin` 会报"未在对局"。
- 权限：`/data/local/tmp` 仅 root 可读 → 桥接须 root；App 只连本机端口 → 无需 root。
- 隐蔽：无字符设备/netlink/procfs；痕迹仅"文件 + 两个普通 root 进程"。
- ⚠️ 风险：**root + 悬浮窗**对王者荣耀/ACE 是强检测点，技术上跑通但风险在游戏侧。
