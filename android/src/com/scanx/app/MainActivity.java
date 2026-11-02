package com.scanx.app;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.*;
import android.widget.Toast;
import java.io.*;
import java.nio.charset.StandardCharsets;

/** Offline report explorer. Only packaged assets execute inside this WebView. */
public final class MainActivity extends Activity {
    private static final String HOST = "appassets.androidplatform.net";
    private WebView web;
    private ValueCallback<Uri[]> chooser;
    private byte[] pendingExport;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        web = new WebView(this);
        web.setOnApplyWindowInsetsListener((view, insets) -> {
            android.graphics.Insets bars = insets.getInsets(android.view.WindowInsets.Type.systemBars());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return insets;
        });
        setContentView(web);
        WebSettings settings = web.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(true); // System-picker URIs only; never arbitrary file paths.
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        web.addJavascriptInterface(new ExportBridge(), "ScanxAndroid");
        web.setWebViewClient(new WebViewClient() {
            @Override public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                if (isLocal(uri)) {
                    String path = uri.getPath();
                    String name = path.equals("/") ? "index.html" : path.substring(1);
                    if (name.matches("[A-Za-z0-9_-]+\\.(html|js|css|json|yaml|svg)")) {
                        try {
                            String mime = name.endsWith("html") ? "text/html" : name.endsWith("js") ? "text/javascript" : name.endsWith("css") ? "text/css" : name.endsWith("svg") ? "image/svg+xml" : name.endsWith("json") ? "application/json" : "text/plain";
                            return new WebResourceResponse(mime, "UTF-8", getAssets().open("www/" + name));
                        } catch (IOException ignored) { }
                    }
                }
                return new WebResourceResponse("text/plain", "UTF-8", 403, "Blocked", null, new ByteArrayInputStream(new byte[0]));
            }
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                if (isLocal(request.getUrl())) return false;
                if (request.isForMainFrame() && "https".equals(request.getUrl().getScheme())) {
                    try { startActivity(new Intent(Intent.ACTION_VIEW, request.getUrl())); }
                    catch (android.content.ActivityNotFoundException e) { notice("No browser available"); }
                }
                return true;
            }
        });
        web.setWebChromeClient(new WebChromeClient() {
            @Override public boolean onShowFileChooser(WebView v, ValueCallback<Uri[]> callback, FileChooserParams params) {
                if (chooser != null) chooser.onReceiveValue(null);
                chooser = callback;
                Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE);
                try { startActivityForResult(intent, 10); }
                catch (android.content.ActivityNotFoundException e) { chooser.onReceiveValue(null); chooser = null; }
                return true;
            }
        });
        web.loadUrl("https://" + HOST + "/index.html");
    }
    private boolean isLocal(Uri uri) { return "https".equals(uri.getScheme()) && HOST.equals(uri.getHost()) && uri.getPort() == -1; }
    private void notice(String text) { Toast.makeText(this, text, Toast.LENGTH_LONG).show(); }
    private final class ExportBridge {
        @JavascriptInterface public void save(String name, String content) {
            if (content == null || content.length() > 16 * 1024 * 1024 || name == null || !name.matches("[a-zA-Z0-9._-]{1,80}")) return;
            runOnUiThread(() -> {
                if (pendingExport != null) { notice("Finish saving the previous report first"); return; }
                pendingExport = content.getBytes(StandardCharsets.UTF_8);
                Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/octet-stream").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE, name);
                try { startActivityForResult(intent, 11); }
                catch (android.content.ActivityNotFoundException e) { pendingExport = null; notice("No file picker available"); }
            });
        }
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        Uri uri = result == RESULT_OK && data != null ? data.getData() : null;
        if (request == 10 && chooser != null) {
            chooser.onReceiveValue(uri != null && "content".equals(uri.getScheme()) ? new Uri[]{uri} : null);
            chooser = null;
        }
        if (request == 11) {
            byte[] bytes = pendingExport; pendingExport = null;
            if (uri != null && bytes != null && "content".equals(uri.getScheme())) {
                new Thread(() -> {
                    try (OutputStream out = getContentResolver().openOutputStream(uri)) {
                        if (out == null) throw new IOException();
                        out.write(bytes); runOnUiThread(() -> notice("Report saved"));
                    } catch (IOException e) { runOnUiThread(() -> notice("Could not save report")); }
                }).start();
            }
        }
    }
    @Override public void onBackPressed() { if (web.canGoBack()) web.goBack(); else super.onBackPressed(); }
    @Override protected void onDestroy() { if (chooser != null) chooser.onReceiveValue(null); web.removeJavascriptInterface("ScanxAndroid"); web.destroy(); super.onDestroy(); }
}
