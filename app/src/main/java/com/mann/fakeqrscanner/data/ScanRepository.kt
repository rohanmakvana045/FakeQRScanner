package com.mann.fakeqrscanner.data

import kotlinx.coroutines.flow.Flow

class ScanRepository(private val scanDao: ScanDao) {
    val allScans: Flow<List<ScanEntity>> = scanDao.getAllScans()

    suspend fun insertScan(scan: ScanEntity): Long {
        return scanDao.insertScan(scan)
    }

    suspend fun deleteScan(scan: ScanEntity) {
        scanDao.deleteScan(scan)
    }

    suspend fun clearHistory() {
        scanDao.clearHistory()
    }
}
