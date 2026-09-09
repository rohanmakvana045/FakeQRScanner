package com.mann.fakeqrscanner.data

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "scan_history")
data class ScanEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val content: String,
    val domain: String,
    val riskScore: Int,
    val riskLevel: String,
    val timestamp: Long
)
