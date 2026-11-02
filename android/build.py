"""Build a signed local-testing APK using JDK 21 and Android SDK 36.1.0."""

import os
import shutil
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SDK = Path(os.environ["ANDROID_HOME"])
JAVA = Path(os.environ["JAVA_HOME"]) / "bin"
TOOLS = SDK / "build-tools/36.1.0"
BUILD = ROOT / "work/android-build/output"
BUILD.mkdir(parents=True, exist_ok=True)
ASSETS = BUILD / "assets/www"
shutil.copytree(ROOT / "src/api_sentry/web/static", ASSETS, dirs_exist_ok=True)
js = ASSETS / "app.js"
js.write_text(
    js.read_text().replace(
        "function download(content, format, type){",
        "function download(content, format, type){if(window.ScanxAndroid){"
        "window.ScanxAndroid.save(`scanx-report.${format}`,content);return;}",
    )
)
bridge = """\ndocument.addEventListener('click', async event => {
 const link=event.target.closest('a[download]');
 if(!link || new URL(link.href).origin!==location.origin)return;
 event.preventDefault();
 try { const r=await fetch(link.href); if(!r.ok)throw Error();
 window.ScanxAndroid.save(new URL(link.href).pathname.split('/').pop(),await r.text());
 } catch(e) { alert('Could not save example file.'); }
});\n"""
for page in ASSETS.glob("*.html"):
    page.write_text(
        page.read_text().replace("</head>", '<script src="./android.js" defer></script></head>')
    )
(ASSETS / "android.js").write_text(bridge)


def run(*args):
    subprocess.run([str(a) for a in args], check=True)


platform = SDK / "platforms/android-36/android.jar"
run(TOOLS / "aapt2", "compile", "--dir", ROOT / "android/res", "-o", BUILD / "resources.zip")
run(
    TOOLS / "aapt2",
    "link",
    "-o",
    BUILD / "base.apk",
    "-I",
    platform,
    "--manifest",
    ROOT / "android/AndroidManifest.xml",
    "-A",
    BUILD / "assets",
    BUILD / "resources.zip",
)
classes = BUILD / "classes"
classes.mkdir(exist_ok=True)
run(
    JAVA / "javac",
    "-source",
    "8",
    "-target",
    "8",
    "-classpath",
    platform,
    "-d",
    classes,
    ROOT / "android/src/com/scanx/app/MainActivity.java",
)
run(
    TOOLS / "d8", "--lib", platform, "--min-api", "30", "--output", BUILD, *classes.rglob("*.class")
)
with zipfile.ZipFile(BUILD / "base.apk", "a") as apk:
    apk.write(BUILD / "classes.dex", "classes.dex")
run(TOOLS / "zipalign", "-f", "4", BUILD / "base.apk", BUILD / "aligned.apk")
key = ROOT / "work/android-build/local-test.keystore"
if not key.exists():
    run(
        JAVA / "keytool",
        "-genkeypair",
        "-keystore",
        key,
        "-storepass",
        "android",
        "-keypass",
        "android",
        "-alias",
        "scanx-local",
        "-dname",
        "CN=Scanx Local Testing",
        "-keyalg",
        "RSA",
        "-keysize",
        "2048",
        "-validity",
        "3650",
    )
output = ROOT / "outputs/scanx-1.0.0.apk"
output.parent.mkdir(exist_ok=True)
run(
    TOOLS / "apksigner",
    "sign",
    "--ks",
    key,
    "--ks-key-alias",
    "scanx-local",
    "--ks-pass",
    "pass:android",
    "--out",
    output,
    BUILD / "aligned.apk",
)
run(TOOLS / "apksigner", "verify", "--verbose", output)
print(output)
