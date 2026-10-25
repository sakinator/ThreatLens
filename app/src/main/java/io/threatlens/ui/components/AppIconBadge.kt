package io.threatlens.ui.components

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material3.Icon
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import io.threatlens.ui.theme.CyberCardBorder
import io.threatlens.ui.theme.CyberDarkSurface
import io.threatlens.ui.theme.NeonCyan
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
fun AppIconBadge(
    packageName: String?,
    apkPath: String?,
    isApk: Boolean = true,
    size: Dp = 44.dp,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var iconBitmap by remember(packageName, apkPath) { mutableStateOf<Bitmap?>(null) }

    LaunchedEffect(packageName, apkPath) {
        withContext(Dispatchers.IO) {
            val pm = context.packageManager
            var drawable: Drawable? = null

            // 1. Try loading directly from installed package
            if (!packageName.isNullOrBlank()) {
                try {
                    drawable = pm.getApplicationIcon(packageName)
                } catch (_: Exception) {}
            }

            // 2. Fallback: parse standalone APK file archive
            if (drawable == null && !apkPath.isNullOrBlank() && apkPath.endsWith(".apk", ignoreCase = true)) {
                try {
                    val pkgInfo = pm.getPackageArchiveInfo(apkPath, 0)
                    pkgInfo?.applicationInfo?.let { appInfo ->
                        appInfo.sourceDir = apkPath
                        appInfo.publicSourceDir = apkPath
                        drawable = appInfo.loadIcon(pm)
                    }
                } catch (_: Exception) {}
            }

            // Convert to Bitmap
            if (drawable != null) {
                try {
                    if (drawable is BitmapDrawable && drawable.bitmap != null) {
                        iconBitmap = drawable.bitmap
                    } else {
                        val w = if (drawable!!.intrinsicWidth > 0) drawable!!.intrinsicWidth else 96
                        val h = if (drawable!!.intrinsicHeight > 0) drawable!!.intrinsicHeight else 96
                        val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
                        val canvas = Canvas(bmp)
                        drawable!!.setBounds(0, 0, canvas.width, canvas.height)
                        drawable!!.draw(canvas)
                        iconBitmap = bmp
                    }
                } catch (_: Exception) {}
            }
        }
    }

    Box(
        modifier = modifier
            .size(size)
            .clip(RoundedCornerShape(10.dp))
            .background(CyberDarkSurface)
            .border(1.dp, CyberCardBorder.copy(alpha = 0.8f), RoundedCornerShape(10.dp)),
        contentAlignment = Alignment.Center
    ) {
        val bmp = iconBitmap
        if (bmp != null) {
            Image(
                bitmap = bmp.asImageBitmap(),
                contentDescription = "App Icon",
                modifier = Modifier
                    .fillMaxSize()
                    .padding(4.dp)
                    .clip(RoundedCornerShape(8.dp))
            )
        } else {
            Icon(
                imageVector = if (isApk) Icons.Default.Android else Icons.Default.InsertDriveFile,
                contentDescription = "File Type",
                tint = NeonCyan,
                modifier = Modifier.size(size * 0.6f)
            )
        }
    }
}
