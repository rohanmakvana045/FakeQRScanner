package com.mann.fakeqrscanner

import android.app.Dialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.View
import android.view.Window
import android.widget.LinearLayout
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.google.mlkit.vision.barcode.BarcodeScanner
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import com.mann.fakeqrscanner.databinding.ActivityMainBinding
import com.mann.fakeqrscanner.databinding.DialogLoadingBinding
import com.mann.fakeqrscanner.databinding.DialogManualInputBinding
import com.mann.fakeqrscanner.viewmodel.ScanViewModel

class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "QR_SCAN_DEBUG"
        private const val DASHBOARD_TAG = "DASHBOARD_DEBUG"
    }

    private lateinit var binding: ActivityMainBinding
    private val viewModel: ScanViewModel by viewModels()
    private var loadingDialog: Dialog? = null

    // ── Singleton BarcodeScanner ─────────────────────────────────────
    // Created once, reused for every scan, closed on Activity destroy.
    // This prevents native resource leaks and concurrent-init SIGSEGV.
    private var barcodeScanner: BarcodeScanner? = null

    // ── Concurrency guard ────────────────────────────────────────────
    // Prevents a second scan from starting while one is still processing.
    @Volatile
    private var isScanning = false

    // Register Activity Result API for Gallery image selection
    private val pickImageLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            scanQrFromImageUri(uri)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        initBarcodeScanner()
        setupListeners()
        observeStats()
    }

    private fun observeStats() {
        viewModel.scanStats.observe(this) { stats ->
            Log.d(DASHBOARD_TAG, "total scans: ${stats.totalScans}")
            Log.d(DASHBOARD_TAG, "safe count: ${stats.safeCount}")
            Log.d(DASHBOARD_TAG, "suspicious count: ${stats.suspiciousCount}")
            Log.d(DASHBOARD_TAG, "high risk count: ${stats.highRiskCount}")
            Log.d(DASHBOARD_TAG, "URL count: ${stats.urlCount}")

            binding.tvTotalScans.text = stats.totalScans.toString()
            binding.tvSafeScans.text = stats.safeCount.toString()
            binding.tvSuspiciousScans.text = stats.suspiciousCount.toString()
            binding.tvHighRiskScans.text = stats.highRiskCount.toString()
            binding.tvUrlsAnalyzed.text = stats.urlCount.toString()
            binding.tvThreatsDetected.text = stats.threatsDetected.toString()

            if (stats.totalScans == 0) {
                binding.tvNoScans.visibility = View.VISIBLE
                binding.layoutDistributionChart.visibility = View.GONE
            } else {
                binding.tvNoScans.visibility = View.GONE
                binding.layoutDistributionChart.visibility = View.VISIBLE
                
                // Update bar weights
                updateChartWeights(stats)
            }
        }
    }

    private fun updateChartWeights(stats: ScanViewModel.ScanStats) {
        val total = stats.totalScans.toFloat()
        val safeWeight = (stats.safeCount / total) * 100f
        val suspiciousWeight = (stats.suspiciousCount / total) * 100f
        val highRiskWeight = (stats.highRiskCount / total) * 100f

        binding.viewSafeBar.layoutParams = (binding.viewSafeBar.layoutParams as LinearLayout.LayoutParams).apply {
            weight = if (safeWeight > 0) safeWeight else 0f
        }
        binding.viewSuspiciousBar.layoutParams = (binding.viewSuspiciousBar.layoutParams as LinearLayout.LayoutParams).apply {
            weight = if (suspiciousWeight > 0) suspiciousWeight else 0f
        }
        binding.viewHighRiskBar.layoutParams = (binding.viewHighRiskBar.layoutParams as LinearLayout.LayoutParams).apply {
            weight = if (highRiskWeight > 0) highRiskWeight else 0f
        }
    }

    /**
     * Initializes a single BarcodeScanner instance that will be reused
     * for every scan operation. This avoids creating (and leaking) a new
     * native detector on every gallery pick.
     */
    private fun initBarcodeScanner() {
        Log.d(TAG, "Initializing BarcodeScanner (singleton)")
        val options = BarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_ALL_FORMATS)
            .build()
        barcodeScanner = BarcodeScanning.getClient(options)
        Log.d(TAG, "BarcodeScanner initialized successfully")
    }

    private fun setupListeners() {
        // Card: Scan with Camera
        binding.cardScanCamera.setOnClickListener {
            val intent = Intent(this, CameraActivity::class.java)
            startActivity(intent)
        }

        // Card: Select QR Image
        binding.cardSelectImage.setOnClickListener {
            if (!isScanning) {
                pickImageLauncher.launch("image/*")
            } else {
                Log.d(TAG, "Scan already in progress — ignoring tap")
            }
        }

        // Card: Enter URL Manually
        binding.cardManualInput.setOnClickListener {
            showManualInputDialog()
        }

        // Card: View Scan History
        binding.cardHistory.setOnClickListener {
            val intent = Intent(this, HistoryActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
            startActivity(intent)
        }
    }

    private fun scanQrFromImageUri(uri: Uri) {
        // ── Guard: prevent concurrent scans ──────────────────────────
        if (isScanning) {
            Log.w(TAG, "scanQrFromImageUri called while scan is already in progress — skipping")
            return
        }

        val scanner = barcodeScanner
        if (scanner == null) {
            Log.e(TAG, "BarcodeScanner is null — reinitializing")
            initBarcodeScanner()
            // Try again with the new scanner
            scanQrFromImageUri(uri)
            return
        }

        isScanning = true
        showLoading(getString(R.string.scanning_image))
        Log.d(TAG, "Image received from gallery: $uri")

        try {
            val image = try {
                InputImage.fromFilePath(this, uri)
            } catch (e: java.io.IOException) {
                Log.e(TAG, "Failed to load image from URI", e)
                isScanning = false
                hideLoading()
                showErrorDialog(
                    getString(R.string.scan_error_title),
                    "Could not read image data."
                )
                return
            }
            Log.d(TAG, "InputImage created from file path")

            Log.d(TAG, "QR processing started")
            scanner.process(image)
                .addOnSuccessListener { barcodes ->
                    Log.d(TAG, "QR processing completed — found ${barcodes.size} barcode(s)")
                    isScanning = false
                    hideLoading()

                    if (barcodes.isNotEmpty()) {
                        var qrContent = barcodes[0].rawValue
                        Log.d(TAG, "Decoded QR value length: ${qrContent?.length}")
                        if (!qrContent.isNullOrBlank()) {
                            // Truncate to prevent TransactionTooLargeException (Intent payload limit is ~1MB)
                            if (qrContent.length > 50_000) {
                                qrContent = qrContent.take(50_000) + "\n...[TRUNCATED]"
                            }
                            navigateToResult(qrContent)
                        } else {
                            Log.d(TAG, "QR rawValue is null/blank")
                            showErrorDialog(
                                getString(R.string.no_qr_found_title),
                                getString(R.string.no_qr_found_message)
                            )
                        }
                    } else {
                        Log.d(TAG, "No barcodes detected in image")
                        showErrorDialog(
                            getString(R.string.no_qr_found_title),
                            getString(R.string.no_qr_found_message)
                        )
                    }
                }
                .addOnFailureListener { e ->
                    Log.e(TAG, "QR processing failed: ${e.message}", e)
                    isScanning = false
                    hideLoading()
                    showErrorDialog(
                        getString(R.string.scan_error_title),
                        getString(R.string.scan_error_message) + "\n\nError: " + e.localizedMessage
                    )
                }
        } catch (e: Exception) {
            Log.e(TAG, "Exception creating InputImage: ${e.message}", e)
            isScanning = false
            hideLoading()
            showErrorDialog(
                getString(R.string.scan_error_title),
                getString(R.string.scan_error_message) + "\n\nError: " + e.localizedMessage
            )
        }
    }

    private fun showManualInputDialog() {
        val dialogBinding = DialogManualInputBinding.inflate(layoutInflater)
        val dialog = AlertDialog.Builder(this, R.style.Theme_App_MaterialDialog)
            .setView(dialogBinding.root)
            .create()

        dialog.show()

        dialogBinding.btnAnalyze.setOnClickListener {
            val text = dialogBinding.etInput.text?.toString()?.trim()
            if (!text.isNullOrBlank()) {
                dialog.dismiss()
                navigateToResult(text)
            } else {
                dialogBinding.tilInput.error = getString(R.string.empty_input_error)
            }
        }

        dialogBinding.btnCancel.setOnClickListener {
            dialog.dismiss()
        }
    }

    private fun navigateToResult(content: String) {
        val intent = Intent(this, ResultActivity::class.java)
        intent.putExtra(ResultActivity.EXTRA_QR_CONTENT, content)
        startActivity(intent)
    }

    private fun showLoading(message: String) {
        if (loadingDialog == null) {
            val dialogBinding = DialogLoadingBinding.inflate(layoutInflater)
            dialogBinding.tvLoadingMessage.text = message
            loadingDialog = Dialog(this).apply {
                requestWindowFeature(Window.FEATURE_NO_TITLE)
                setContentView(dialogBinding.root)
                setCancelable(false)
                window?.setBackgroundDrawableResource(android.R.color.transparent)
            }
        } else {
            val tvMsg = loadingDialog?.findViewById<android.widget.TextView>(R.id.tvLoadingMessage)
            tvMsg?.text = message
        }
        loadingDialog?.show()
    }

    private fun hideLoading() {
        loadingDialog?.dismiss()
        loadingDialog = null
    }

    private fun showErrorDialog(title: String, message: String) {
        AlertDialog.Builder(this, R.style.Theme_App_MaterialDialog)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton(R.string.btn_ok) { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }

    override fun onDestroy() {
        // ── Close the native barcode scanner to release native resources ──
        Log.d(TAG, "onDestroy — closing BarcodeScanner")
        barcodeScanner?.close()
        barcodeScanner = null
        Log.d(TAG, "BarcodeScanner closed")

        hideLoading()
        super.onDestroy()
    }
}
