package vn.vanthu.app

import android.app.Activity
import android.app.AlertDialog
import android.app.DownloadManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.text.InputType
import android.view.Menu
import android.view.MenuItem
import android.view.WindowManager
import android.webkit.*
import android.widget.EditText
import android.widget.Toast

/** Ứng dụng khách: chỉ là WebView trỏ tới máy chủ Văn thư nội bộ. Dữ liệu nằm trên máy chủ, không lưu trên điện thoại. */
class MainActivity : Activity() {
    private lateinit var web: WebView
    private var chooser: ValueCallback<Array<Uri>>? = null
    private var host = ""
    private fun prefs() = getSharedPreferences("cfg", Context.MODE_PRIVATE)

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        // Chặn chụp màn hình / quay màn hình / xem trước trong danh sách ứng dụng gần đây
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        web = WebView(this).also { setContentView(it) }
        setup()
        val url = prefs().getString("url", null)
        if (url == null) askServer() else load(url)
    }

    private fun load(url: String) { host = Uri.parse(url).host ?: ""; web.loadUrl(url) }

    private fun setup() {
        CookieManager.getInstance().setAcceptCookie(true)
        web.settings.apply {
            javaScriptEnabled = true; domStorageEnabled = true
            allowFileAccess = false; cacheMode = WebSettings.LOAD_NO_CACHE
        }
        web.webViewClient = object : WebViewClient() {
            // Khóa điều hướng: không cho mở trang ngoài máy chủ đã cấu hình
            override fun shouldOverrideUrlLoading(v: WebView, r: WebResourceRequest) = r.url.host != host
            override fun onReceivedError(v: WebView, r: WebResourceRequest, e: WebResourceError) {
                if (r.isForMainFrame) v.loadDataWithBaseURL(null,
                    "<body style='font:16px sans-serif;padding:24px'><h3>Không kết nối được máy chủ</h3>" +
                    "<p>Kiểm tra mạng nội bộ/VPN, rồi chọn <b>Tải lại</b> hoặc <b>Đổi máy chủ</b> trong menu.</p>",
                    "text/html", "utf-8", null)
            }
        }
        web.webChromeClient = object : WebChromeClient() {
            override fun onShowFileChooser(w: WebView, cb: ValueCallback<Array<Uri>>, p: FileChooserParams): Boolean {
                chooser?.onReceiveValue(null); chooser = cb
                return try { startActivityForResult(p.createIntent(), 1); true } catch (e: Exception) { chooser = null; false }
            }
        }
        web.setDownloadListener { url, ua, cd, mime, _ ->
            val name = URLUtil.guessFileName(url, cd, mime)
            val req = DownloadManager.Request(Uri.parse(url))
                .addRequestHeader("Cookie", CookieManager.getInstance().getCookie(url) ?: "")
                .addRequestHeader("User-Agent", ua)
                .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
                .setDestinationInExternalFilesDir(this, Environment.DIRECTORY_DOWNLOADS, name) // thư mục riêng của app
            (getSystemService(DOWNLOAD_SERVICE) as DownloadManager).enqueue(req)
            Toast.makeText(this, "Đang tải: $name", Toast.LENGTH_SHORT).show()
        }
    }

    private fun askServer() {
        val et = EditText(this).apply {
            hint = "http://192.168.1.10:8080"; setText(prefs().getString("url", "")); inputType = InputType.TYPE_TEXT_VARIATION_URI
        }
        AlertDialog.Builder(this).setTitle("Địa chỉ máy chủ Văn thư").setView(et)
            .setCancelable(prefs().contains("url"))
            .setPositiveButton("Lưu") { _, _ ->
                val u = et.text.toString().trim().trimEnd('/')
                if (Regex("https?://[^\\s/]+").matches(u)) {
                    prefs().edit().putString("url", u).apply()
                    CookieManager.getInstance().removeAllCookies(null)
                    load(u)
                } else { Toast.makeText(this, "Địa chỉ không hợp lệ", Toast.LENGTH_LONG).show(); askServer() }
            }.show()
    }

    override fun onCreateOptionsMenu(m: Menu): Boolean { m.add(0, 1, 0, "Tải lại"); m.add(0, 2, 1, "Đổi máy chủ"); return true }
    override fun onOptionsItemSelected(i: MenuItem): Boolean { when (i.itemId) { 1 -> web.reload(); 2 -> askServer() }; return true }
    override fun onActivityResult(rc: Int, res: Int, d: Intent?) {
        if (rc == 1) { chooser?.onReceiveValue(WebChromeClient.FileChooserParams.parseResult(res, d)); chooser = null }
    }
    @Deprecated("Deprecated in Java")
    override fun onBackPressed() { if (web.canGoBack()) web.goBack() else super.onBackPressed() }
    override fun onDestroy() { web.destroy(); super.onDestroy() }
}
