package com.mann.fakeqrscanner

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.mann.fakeqrscanner.data.ScanEntity
import com.mann.fakeqrscanner.databinding.ActivityResultBinding
import com.mann.fakeqrscanner.logic.SecurityAnalyzer
import com.mann.fakeqrscanner.viewmodel.ScanViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ResultActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_QR_CONTENT = "extra_qr_content"
    }

    private lateinit var binding: ActivityResultBinding
    private val viewModel: ScanViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityResultBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Set support action bar for back button support
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        binding.toolbar.setNavigationOnClickListener {
            onBackPressedDispatcher.onBackPressed()
        }

        val qrContent = intent.getStringExtra(EXTRA_QR_CONTENT) ?: ""
        if (qrContent.isBlank()) {
            finish()
            return
        }

        analyzeAndDisplay(qrContent, savedInstanceState == null)
    }

    private fun analyzeAndDisplay(content: String, saveToDb: Boolean) {
        val result = SecurityAnalyzer.analyze(content)
        val timestamp = System.currentTimeMillis()
        val formattedDate = SimpleDateFormat("MMM dd, yyyy • hh:mm a", Locale.getDefault()).format(Date(timestamp))

        // Display basic fields
        binding.tvQrContent.text = content
        binding.tvScanDate.text = formattedDate
        binding.tvRiskScore.text = result.riskScore.toString()
        binding.tvRiskLevel.text = result.riskLevel
        binding.tvDomain.text = if (result.domain == "N/A") getString(R.string.label_not_a_url) else result.domain

        // Setup HTTPS Status display
        when (result.isHttps) {
            true -> {
                binding.ivHttpsIcon.setImageResource(R.drawable.ic_lock)
                binding.tvHttpsStatus.text = getString(R.string.https_secure)
                binding.tvHttpsStatus.setTextColor(ContextCompat.getColor(this, R.color.https_secure))
            }
            false -> {
                binding.ivHttpsIcon.setImageResource(R.drawable.ic_lock_open)
                binding.tvHttpsStatus.text = getString(R.string.http_insecure)
                binding.tvHttpsStatus.setTextColor(ContextCompat.getColor(this, R.color.http_insecure))
            }
            else -> {
                binding.ivHttpsIcon.setImageResource(R.drawable.ic_warning)
                binding.tvHttpsStatus.text = getString(R.string.label_na)
                binding.tvHttpsStatus.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))
            }
        }

        // Setup Risk Level appearance
        // Support both legacy "DANGEROUS" and new "HIGH RISK" / "LOW RISK"
        applyRiskLevelStyle(result.riskLevel)

        // Populate dynamic list of indicators
        binding.llIndicators.removeAllViews()
        if (result.indicators.isEmpty()) {
            addIndicatorView(getString(R.string.label_na))
        } else {
            for (indicator in result.indicators) {
                addIndicatorView(indicator)
            }
        }

        // Save to Database
        // Store "HIGH RISK" as the risk level for new records
        if (saveToDb) {
            val entity = ScanEntity(
                content = content,
                domain = result.domain,
                riskScore = result.riskScore,
                riskLevel = result.riskLevel,
                timestamp = timestamp
            )
            viewModel.insertScan(entity)
        }

        // Configure Scan Another / Back to Home Button
        binding.btnScanAnother.setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            startActivity(intent)
            finish()
        }

        // Configure Open Link Button — only visible for URL content
        if (result.isUrl) {
            binding.btnOpenLink.visibility = View.VISIBLE
            binding.btnOpenLink.setOnClickListener {
                handleOpenLink(content, result.riskLevel)
            }
        } else {
            binding.btnOpenLink.visibility = View.GONE
        }
    }

    /**
     * Applies the correct colors and badge drawables based on the risk level string.
     * Handles legacy "DANGEROUS" values from older database records as well as new values.
     */
    private fun applyRiskLevelStyle(riskLevel: String) {
        when (riskLevel) {
            "LOW RISK", "SAFE" -> {
                binding.viewScoreCircle.setBackgroundResource(R.drawable.bg_score_safe)
                binding.tvRiskLevel.setTextColor(ContextCompat.getColor(this, R.color.risk_safe))
                binding.tvRiskLevel.setBackgroundResource(R.drawable.bg_badge_safe)
            }
            "SUSPICIOUS" -> {
                binding.viewScoreCircle.setBackgroundResource(R.drawable.bg_score_suspicious)
                binding.tvRiskLevel.setTextColor(ContextCompat.getColor(this, R.color.risk_suspicious))
                binding.tvRiskLevel.setBackgroundResource(R.drawable.bg_badge_suspicious)
            }
            "HIGH RISK", "DANGEROUS" -> {
                binding.viewScoreCircle.setBackgroundResource(R.drawable.bg_score_dangerous)
                binding.tvRiskLevel.setTextColor(ContextCompat.getColor(this, R.color.risk_dangerous))
                binding.tvRiskLevel.setBackgroundResource(R.drawable.bg_badge_dangerous)
            }
        }
    }

    /**
     * Handles the "Open Link" button behavior based on risk level.
     * - HIGH RISK / DANGEROUS: Show a strong warning. Do NOT open automatically.
     * - SUSPICIOUS: Show a warning with the destination URL.
     * - LOW RISK / SAFE: Open in browser directly (user already reviewed the result screen).
     */
    private fun handleOpenLink(url: String, riskLevel: String) {
        val normalizedUrl = if (!url.startsWith("http://", ignoreCase = true) &&
            !url.startsWith("https://", ignoreCase = true)
        ) {
            "http://$url"
        } else {
            url
        }

        when (riskLevel) {
            "HIGH RISK", "DANGEROUS" -> {
                AlertDialog.Builder(this, R.style.Theme_App_MaterialDialog)
                    .setTitle(getString(R.string.warning_high_risk_title))
                    .setMessage(getString(R.string.warning_high_risk_message))
                    .setNegativeButton(getString(R.string.btn_go_back)) { dialog, _ ->
                        dialog.dismiss()
                    }
                    .setPositiveButton(getString(R.string.btn_proceed_anyway)) { dialog, _ ->
                        dialog.dismiss()
                        openUrlInBrowser(normalizedUrl)
                    }
                    .show()
            }
            "SUSPICIOUS" -> {
                AlertDialog.Builder(this, R.style.Theme_App_MaterialDialog)
                    .setTitle(getString(R.string.warning_suspicious_title))
                    .setMessage(getString(R.string.warning_suspicious_message, normalizedUrl))
                    .setNegativeButton(getString(R.string.btn_cancel)) { dialog, _ ->
                        dialog.dismiss()
                    }
                    .setPositiveButton(getString(R.string.btn_proceed)) { dialog, _ ->
                        dialog.dismiss()
                        openUrlInBrowser(normalizedUrl)
                    }
                    .show()
            }
            else -> {
                // LOW RISK / SAFE — open directly
                openUrlInBrowser(normalizedUrl)
            }
        }
    }

    private fun openUrlInBrowser(url: String) {
        try {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
            startActivity(intent)
        } catch (_: Exception) {
            // No browser available or invalid URL — silently ignore
        }
    }

    private fun addIndicatorView(text: String) {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            val params = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            params.setMargins(0, 8, 0, 8)
            layoutParams = params
            gravity = android.view.Gravity.TOP
        }

        // Custom indicator dot or icon
        val bullet = TextView(this).apply {
            this.text = "• "
            setTextColor(ContextCompat.getColor(context, R.color.primary))
            textSize = 18f
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val textView = TextView(this).apply {
            this.text = text
            setTextColor(ContextCompat.getColor(context, R.color.text_secondary))
            textSize = 14f
            setLineSpacing(0f, 1.1f)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        container.addView(bullet)
        container.addView(textView)
        binding.llIndicators.addView(container)
    }
}
