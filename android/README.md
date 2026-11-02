# Scanx for Android

An offline snapshot of the liquid-glass Scanx report explorer, bundled from the same frontend as the website. Requires **Android 11 or newer** and an up-to-date Android System WebView. No sign-in or network permission is required. External HTTPS links open in your browser.

## Install

Download [scanx-1.0.0.apk](downloads/scanx-1.0.0.apk), transfer it to your Android device, and open it. If Android asks, allow installation from the specific app you use to open the APK. This is a locally signed testing build, not a Play Store release.

## Use

Explore the sample assessments, import a Scanx JSON report using the system file picker, filter findings, and export JSON/Markdown/HTML through Android's Save dialog. The beginner guide and copyright page are included offline. Reports are held in the WebView session; export before leaving the app. Live API scanning remains a Python-runner feature on your computer. This APK does not run Python or connect to that runner.

The APK is a snapshot, not an automatic updater. Future website changes require rebuilding and installing a new APK. Glass rendering depends on the installed WebView; opaque fallback styles and reduced-motion preferences are supported.

## Build

Install JDK 21, Python 3.11+, Android SDK Platform 36, and Build Tools 36.1.0. Set `JAVA_HOME` and `ANDROID_HOME`, then from the repository root:

```sh
python3 android/build.py
```

The signed APK is written to `outputs/scanx-1.0.0.apk`. The script generates a local testing key under ignored `work/android-build/`. It uses a conventional non-secret testing password. Do not use this key for production distribution. Keep the same key to update installed test builds; builds signed with another key require uninstalling the previous app first. Production releases should use a separately managed release key and increasing version codes.

## Validation

Java compilation, DEX conversion, resource packaging, ZIP alignment, and APK signature verification passed with SDK 36.1.0 and Temurin JDK 21. Assets are bundled directly from the shared frontend; only Android import/export integration is added during packaging. No physical-device or emulator interaction test has been performed. Test report import/export and visual rendering on a device before distribution.
