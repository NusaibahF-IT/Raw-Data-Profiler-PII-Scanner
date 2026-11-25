<template>
  <section class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
    <!-- Readiness Ring Card -->
    <div class="card-bento p-5 flex items-center justify-between gap-3 bg-field/15 border-field/50">
      <div>
        <span class="text-[11px] font-extrabold uppercase tracking-wider text-tx/70">Readiness Score</span>
        <div class="text-2xl font-black text-tx mt-1">{{ overview.data_readiness_score }}<span class="text-sm font-bold opacity-60">/100</span></div>
        <p class="text-[11px] text-tx/75 mt-0.5">Weighted quality index</p>
      </div>
      <div class="relative w-14 h-14 shrink-0">
        <svg class="w-14 h-14 -rotate-90" viewBox="0 0 60 60">
          <circle cx="30" cy="30" r="24" fill="none" stroke="rgba(33,40,27,0.12)" stroke-width="6" />
          <circle
            cx="30"
            cy="30"
            r="24"
            fill="none"
            :stroke="scoreColor"
            stroke-width="6"
            stroke-linecap="round"
            :stroke-dasharray="150.8"
            :stroke-dashoffset="150.8 - (150.8 * overview.data_readiness_score) / 100"
          />
        </svg>
        <span class="absolute inset-0 grid place-items-center text-xs font-extrabold text-tx">
          {{ overview.data_readiness_score }}%
        </span>
      </div>
    </div>

    <!-- Grain / Volume -->
    <div class="card-bento p-5">
      <span class="text-[11px] font-extrabold uppercase tracking-wider text-tx/70">Shape &amp; Duplicates</span>
      <div class="text-2xl font-black text-tx mt-1">
        {{ overview.row_count.toLocaleString() }} <span class="text-sm font-bold opacity-65">× {{ overview.column_count }}</span>
      </div>
      <p class="text-[11px] text-tx/75 mt-1 font-mono">
        {{ overview.memory_kb }} KB · {{ overview.full_row_duplicates }} dup rows
      </p>
    </div>

    <!-- Candidate Keys -->
    <div class="card-bento p-5">
      <span class="text-[11px] font-extrabold uppercase tracking-wider text-tx/70">Candidate Key(s)</span>
      <div class="mt-2 flex flex-wrap gap-1.5">
        <span
          v-for="k in overview.candidate_key_columns"
          :key="k"
          class="chip bg-act/15 border-act/40 font-mono text-tx"
        >
          {{ k }}
        </span>
        <span v-if="!overview.candidate_key_columns.length" class="text-xs font-bold text-mag">
          No unique key column found
        </span>
      </div>
    </div>

    <!-- Findings Breakdown -->
    <div class="card-bento p-5">
      <span class="text-[11px] font-extrabold uppercase tracking-wider text-tx/70">Candidate Findings</span>
      <div class="text-2xl font-black text-tx mt-1">{{ overview.findings_summary.total }}</div>
      <div class="flex items-center gap-2 mt-1.5 text-[11px] font-bold">
        <span class="px-2 py-0.5 rounded-full bg-mag/15 text-mag">H: {{ overview.findings_summary.high }}</span>
        <span class="px-2 py-0.5 rounded-full bg-sun/25 text-tx">M: {{ overview.findings_summary.medium }}</span>
        <span class="px-2 py-0.5 rounded-full bg-line text-tx/80">L: {{ overview.findings_summary.low }}</span>
      </div>
    </div>

    <!-- PII Risk Status -->
    <div
      class="card-bento p-5"
      :class="piiSummary.overall_status === 'ACTION_REQUIRED' ? 'border-mag/50 bg-mag/10' : ''"
    >
      <span class="text-[11px] font-extrabold uppercase tracking-wider text-tx/70">PII Risk Gate</span>
      <div class="mt-1.5">
        <span
          class="inline-block px-2.5 py-1 rounded-md text-xs font-mono font-extrabold border"
          :class="piiBadgeClass"
        >
          {{ piiSummary.overall_status }}
        </span>
      </div>
      <p class="text-[11px] text-tx/75 mt-1.5">
        {{ piiSummary.pii_column_count }} sensitive column(s) flagged
      </p>
    </div>
  </section>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  overview: { type: Object, required: true },
  piiSummary: { type: Object, required: true }
})

const scoreColor = computed(() => {
  const s = props.overview.data_readiness_score
  if (s >= 80) return '#00D26A'
  if (s >= 55) return '#F8C33A'
  return '#F108B0'
})

const piiBadgeClass = computed(() => {
  const st = props.piiSummary.overall_status
  if (st === 'ACTION_REQUIRED') return 'bg-mag text-white border-ink'
  if (st === 'REVIEW_RECOMMENDED') return 'bg-sun text-ink border-ink'
  return 'bg-act text-ink border-ink'
})
</script>
