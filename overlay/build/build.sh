#!/data/data/com.termux/files/usr/bin/bash
# 在 Termux 上本地构建 HeroOverlay APK (无需 Android Studio)
# 依赖: javac(jdk), d8, aapt2, apksigner, android.jar
set -e
cd "$(dirname "$0")"
AJ=${ANDROID_JAR:-/data/data/com.termux/files/usr/tmp/opencode/p35/android-35/android.jar}
if [ ! -f "$AJ" ]; then
  for c in "$HOME/android.jar" "$HOME/android-sdk/platforms/android-35/android.jar"; do
    [ -f "$c" ] && AJ="$c" && break
  done
fi
if [ ! -f "$AJ" ]; then
  echo "找不到 android.jar；请设置 ANDROID_JAR=/path/to/android.jar" >&2
  exit 1
fi
APP=com.hero.overlay

echo "[1/5] javac"
rm -rf classes dex && mkdir -p classes dex
javac --release 11 -classpath "$AJ" -d classes java/com/hero/overlay/*.java

echo "[2/5] d8 -> classes.dex"
d8 --lib "$AJ" --min-api 26 --output dex classes/com/hero/overlay/*.class

echo "[3/5] aapt2 link"
rm -f base.apk
aapt2 link -o base.apk -I "$AJ" --manifest AndroidManifest.xml

echo "[4/5] 打包 classes.dex"
python3 - <<EOF
import zipfile
with zipfile.ZipFile("base.apk","a",zipfile.ZIP_DEFLATED) as z: z.write("dex/classes.dex","classes.dex")
EOF

echo "[5/5] 签名 (自签名 debug key)"
[ -f ks.jks ] || keytool -genkeypair -keystore ks.jks -alias hero -keyalg RSA -keysize 2048 \
  -validity 10000 -storepass android -keypass android -dname "CN=hero,OU=x,O=x,C=CN"
rm -f hero.apk
apksigner sign --ks ks.jks --ks-pass pass:android --key-pass pass:android --out hero.apk base.apk
echo "OK -> $(pwd)/hero.apk"
