package com.mann.fakeqrscanner.ui

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.mann.fakeqrscanner.R
import com.mann.fakeqrscanner.data.ScanEntity
import com.mann.fakeqrscanner.databinding.ItemHistoryBinding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class HistoryAdapter(
    private val onItemClick: (ScanEntity) -> Unit,
    private val onDeleteClick: (ScanEntity) -> Unit
) : ListAdapter<ScanEntity, HistoryAdapter.HistoryViewHolder>(ScanDiffCallback()) {

    private val dateFormat = SimpleDateFormat("MMM dd, yyyy • hh:mm a", Locale.getDefault())

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): HistoryViewHolder {
        val binding = ItemHistoryBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return HistoryViewHolder(binding)
    }

    override fun onBindViewHolder(holder: HistoryViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class HistoryViewHolder(
        private val binding: ItemHistoryBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(item: ScanEntity) {
            binding.tvItemContent.text = item.content
            binding.tvItemDomain.text = if (item.domain == "N/A") {
                itemView.context.getString(R.string.label_not_a_url)
            } else {
                item.domain
            }
            binding.tvItemDate.text = dateFormat.format(Date(item.timestamp))
            binding.tvItemRiskScore.text = itemView.context.getString(
                R.string.label_risk_score
            ) + ": ${item.riskScore}/100"

            binding.tvItemRiskLevel.text = item.riskLevel

            // Configure badge look based on risk level
            val context = itemView.context
            when (item.riskLevel) {
                "SAFE", "LOW RISK" -> {
                    binding.tvItemRiskLevel.setTextColor(ContextCompat.getColor(context, R.color.risk_safe))
                    binding.tvItemRiskLevel.setBackgroundResource(R.drawable.bg_badge_safe)
                }
                "SUSPICIOUS" -> {
                    binding.tvItemRiskLevel.setTextColor(ContextCompat.getColor(context, R.color.risk_suspicious))
                    binding.tvItemRiskLevel.setBackgroundResource(R.drawable.bg_badge_suspicious)
                }
                "DANGEROUS", "HIGH RISK" -> {
                    binding.tvItemRiskLevel.setTextColor(ContextCompat.getColor(context, R.color.risk_dangerous))
                    binding.tvItemRiskLevel.setBackgroundResource(R.drawable.bg_badge_dangerous)
                }
            }

            binding.root.setOnClickListener {
                onItemClick(item)
            }

            binding.btnDelete.setOnClickListener {
                onDeleteClick(item)
            }
        }
    }

    class ScanDiffCallback : DiffUtil.ItemCallback<ScanEntity>() {
        override fun areItemsTheSame(oldItem: ScanEntity, newItem: ScanEntity): Boolean {
            return oldItem.id == newItem.id
        }

        override fun areContentsTheSame(oldItem: ScanEntity, newItem: ScanEntity): Boolean {
            return oldItem == newItem
        }
    }
}
