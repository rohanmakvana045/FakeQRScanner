package com.mann.fakeqrscanner.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.asLiveData
import androidx.lifecycle.map
import androidx.lifecycle.viewModelScope
import com.mann.fakeqrscanner.data.ScanDatabase
import com.mann.fakeqrscanner.data.ScanEntity
import com.mann.fakeqrscanner.data.ScanRepository
import kotlinx.coroutines.launch

class ScanViewModel(application: Application) : AndroidViewModel(application) {
    private val repository: ScanRepository
    val allScans: LiveData<List<ScanEntity>>

    data class ScanStats(
        val totalScans: Int = 0,
        val safeCount: Int = 0,
        val suspiciousCount: Int = 0,
        val highRiskCount: Int = 0,
        val urlCount: Int = 0,
        val threatsDetected: Int = 0
    )

    val scanStats: LiveData<ScanStats>

    init {
        val scanDao = ScanDatabase.getDatabase(application).scanDao()
        repository = ScanRepository(scanDao)
        allScans = repository.allScans.asLiveData()

        scanStats = allScans.map { scans ->
            val total = scans.size
            var safe = 0
            var suspicious = 0
            var highRisk = 0
            var urls = 0

            scans.forEach { scan ->
                // Support legacy "DANGEROUS" as HIGH RISK
                when (scan.riskLevel.uppercase()) {
                    "SAFE", "LOW RISK" -> safe++
                    "SUSPICIOUS" -> suspicious++
                    "HIGH RISK", "DANGEROUS" -> highRisk++
                }
                
                // Heuristic for URL detection in history
                if (scan.domain != "N/A") {
                    urls++
                }
            }

            ScanStats(
                totalScans = total,
                safeCount = safe,
                suspiciousCount = suspicious,
                highRiskCount = highRisk,
                urlCount = urls,
                threatsDetected = suspicious + highRisk
            )
        }
    }

    fun insertScan(scan: ScanEntity) = viewModelScope.launch {
        repository.insertScan(scan)
    }

    fun deleteScan(scan: ScanEntity) = viewModelScope.launch {
        repository.deleteScan(scan)
    }

    fun clearHistory() = viewModelScope.launch {
        repository.clearHistory()
    }
}
