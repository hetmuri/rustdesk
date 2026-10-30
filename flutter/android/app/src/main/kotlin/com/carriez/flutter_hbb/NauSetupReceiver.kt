package com.carriez.flutter_hbb

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import java.security.MessageDigest

/**
 * NAU POS -> RustDesk: set (or clear) the permanent password.
 * Protected by android:permission="com.naupos.kiosk.permission.REMOTE_SETUP" (manifest), so only the NAU POS app
 * can send it. The Rust config can only be changed from Dart, so we keep it as "pending" here; the Dart side
 * (ServerModel.fetchID, every 3 s while RustDesk is open) takes it with "nau_take_pending", applies it, and answers
 * the POS app with "nau_report_pw" (tag = first 12 hex of sha256(password), never the password itself).
 *   extras: "password" (8..64, [A-Za-z0-9]) or "clear" = true
 */
class NauSetupReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION) return
        val prefs = context.getSharedPreferences(KEY_SHARED_PREFERENCES, Context.MODE_PRIVATE)
        val clear = intent.getBooleanExtra("clear", false)
        val pw = intent.getStringExtra("password") ?: ""
        if (clear) {
            prefs.edit().remove(KEY_PW).putBoolean(KEY_CLEAR, true).remove(KEY_TAG).apply()
            Log.i(TAG, "pending: clear")
            return
        }
        if (!Regex("^[A-Za-z0-9]{8,64}$").matches(pw)) {
            Log.w(TAG, "ignored: bad password format")
            return
        }
        prefs.edit().putString(KEY_PW, pw).putString(KEY_TAG, tagOf(pw)).remove(KEY_CLEAR).apply()
        Log.i(TAG, "pending: password")
    }

    companion object {
        const val ACTION = "com.carriez.flutter_hbb.NAU_REMOTE_SETUP"
        const val KEY_PW = "nau_pending_password"
        const val KEY_TAG = "nau_pending_tag"
        const val KEY_CLEAR = "nau_pending_clear"
        private const val TAG = "NauSetupReceiver"

        fun tagOf(pw: String): String {
            val d = MessageDigest.getInstance("SHA-256").digest(pw.toByteArray(Charsets.UTF_8))
            return d.joinToString("") { "%02x".format(it) }.substring(0, 12)
        }
    }
}
