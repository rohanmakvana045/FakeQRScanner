package com.mann.fakeqrscanner

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.mann.fakeqrscanner.data.ScanEntity
import com.mann.fakeqrscanner.databinding.ActivityHistoryBinding
import com.mann.fakeqrscanner.ui.HistoryAdapter
import com.mann.fakeqrscanner.viewmodel.ScanViewModel

class HistoryActivity : AppCompatActivity() {

    private lateinit var binding: ActivityHistoryBinding
    private val viewModel: ScanViewModel by viewModels()
    private lateinit var adapter: HistoryAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityHistoryBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Set action bar for back button
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        binding.toolbar.setNavigationOnClickListener {
            onBackPressedDispatcher.onBackPressed()
        }

        setupRecyclerView()
        setupObservers()
        setupListeners()
    }

    private fun setupRecyclerView() {
        adapter = HistoryAdapter(
            onItemClick = { item ->
                navigateToResult(item.content)
            },
            onDeleteClick = { item ->
                showDeleteConfirmationDialog(item)
            }
        )

        binding.rvHistory.layoutManager = LinearLayoutManager(this)
        binding.rvHistory.adapter = adapter
    }

    private fun setupObservers() {
        viewModel.allScans.observe(this) { scans ->
            if (scans.isNullOrEmpty()) {
                binding.llEmptyState.visibility = View.VISIBLE
                binding.rvHistory.visibility = View.GONE
                binding.btnClearAll.visibility = View.GONE
            } else {
                binding.llEmptyState.visibility = View.GONE
                binding.rvHistory.visibility = View.VISIBLE
                binding.btnClearAll.visibility = View.VISIBLE
                adapter.submitList(scans)
            }
        }
    }

    private fun setupListeners() {
        binding.btnClearAll.setOnClickListener {
            showClearAllConfirmationDialog()
        }
    }

    private fun navigateToResult(content: String) {
        val intent = Intent(this, ResultActivity::class.java)
        intent.putExtra(ResultActivity.EXTRA_QR_CONTENT, content)
        // Reset flags so it creates or uses a single task structure
        intent.flags = Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
        startActivity(intent)
    }

    private fun showDeleteConfirmationDialog(item: ScanEntity) {
        AlertDialog.Builder(this, R.style.Theme_App_MaterialDialog)
            .setTitle(getString(R.string.delete_item_title))
            .setMessage(getString(R.string.delete_item_message))
            .setPositiveButton(getString(R.string.btn_delete)) { dialog, _ ->
                viewModel.deleteScan(item)
                Toast.makeText(this, getString(R.string.history_deleted), Toast.LENGTH_SHORT).show()
                dialog.dismiss()
            }
            .setNegativeButton(getString(R.string.btn_cancel)) { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }

    private fun showClearAllConfirmationDialog() {
        AlertDialog.Builder(this, R.style.Theme_App_MaterialDialog)
            .setTitle(getString(R.string.clear_history_title))
            .setMessage(getString(R.string.clear_history_message))
            .setPositiveButton(getString(R.string.btn_clear)) { dialog, _ ->
                viewModel.clearHistory()
                Toast.makeText(this, getString(R.string.history_cleared), Toast.LENGTH_SHORT).show()
                dialog.dismiss()
            }
            .setNegativeButton(getString(R.string.btn_cancel)) { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }
}
