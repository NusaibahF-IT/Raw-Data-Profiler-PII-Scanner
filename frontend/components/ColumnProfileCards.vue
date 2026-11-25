<template>
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
    <article
      v-for="col in columns"
      :key="col.column"
      class="card-bento p-5 flex flex-col justify-between gap-3"
    >
      <div>
        <div class="flex items-start justify-between gap-2">
          <div>
            <h4 class="font-mono font-bold text-sm text-tx break-all">{{ col.column }}</h4>
            <span class="text-[11px] font-mono text-tx/65">
              {{ col.semantic_type }} · {{ col.pandas_dtype }}
            </span>
          </div>
          <div class="flex flex-wrap gap-1 justify-end">
            <span v-if="col.is_candidate_key" class="px-2 py-0.5 rounded-full text-[10px] font-extrabold bg-act/20 text-tx border border-act/40">
              PK Candidate
            </span>
            <span v-if="col.pii_info" class="px-2 py-0.5 rounded-full text-[10px] font-extrabold bg-mag text-white">
              PII: {{ col.pii_info.pii_type }}
            </span>
          </div>
        </div>

        <!-- Completeness Bar -->
        <div class="mt-3">
          <div class="flex justify-between text-[11px] font-semibold text-tx/75 mb-1">
            <span>Completeness</span>
            <span class="font-mono">{{ (100 - col.missing_pct).toFixed(1) }}% ({{ col.effective_missing }} missing)</span>
          </div>
          <div class="h-2 w-full rounded-full bg-line overflow-hidden">
            <div
              class="h-full rounded-full transition-all"
              :class="col.missing_pct > 10 ? 'bg-mag' : (col.missing_pct > 0 ? 'bg-sun' : 'bg-act')"
              :style="{ width: `${Math.max(2, 100 - col.missing_pct)}%` }"
            />
          </div>
        </div>

        <!-- Key Stats -->
        <div class="grid grid-cols-2 gap-2 mt-3 text-[11px]">
          <div class="p-2 rounded-lg bg-canvas border border-line">
            <span class="text-tx/60 block">Distinct</span>
            <strong class="font-mono text-tx">{{ col.distinct_count }}</strong>
          </div>
          <div class="p-2 rounded-lg bg-canvas border border-line">
            <span class="text-tx/60 block">Duplicates</span>
            <strong class="font-mono text-tx">{{ col.duplicate_count }}</strong>
          </div>
        </div>

        <!-- Numeric Summary -->
        <div v-if="col.numeric_stats" class="mt-3 p-2.5 rounded-lg bg-canvas border border-line text-[11px] font-mono space-y-0.5">
          <div class="flex justify-between">
            <span class="text-tx/60">Min / Med / Max:</span>
            <span>{{ col.numeric_stats.min }} / {{ col.numeric_stats.median }} / {{ col.numeric_stats.max }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-tx/60">Mean / IQR Outliers:</span>
            <span>{{ col.numeric_stats.mean }} / {{ col.numeric_stats.iqr_outlier_count }}</span>
          </div>
        </div>

        <!-- Date Summary -->
        <div v-if="col.date_stats" class="mt-3 p-2.5 rounded-lg bg-canvas border border-line text-[11px] font-mono space-y-0.5">
          <div class="flex justify-between">
            <span class="text-tx/60">Range:</span>
            <span>{{ col.date_stats.min_date?.slice(0, 10) }} → {{ col.date_stats.max_date?.slice(0, 10) }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-tx/60">Unparseable:</span>
            <span :class="col.date_stats.unparseable_count > 0 ? 'text-mag font-bold' : ''">{{ col.date_stats.unparseable_count }}</span>
          </div>
        </div>
      </div>

      <!-- Top Values -->
      <div v-if="col.top_values?.length" class="pt-2 border-t border-line">
        <span class="text-[10px] font-extrabold uppercase tracking-wider text-tx/60">Top Values</span>
        <div class="mt-1.5 space-y-1">
          <div
            v-for="tv in col.top_values.slice(0, 3)"
            :key="tv.value"
            class="flex items-center justify-between text-[11px] font-mono gap-2"
          >
            <span class="truncate text-tx/85">{{ tv.value }}</span>
            <span class="shrink-0 font-bold text-tx/70">{{ tv.count }}</span>
          </div>
        </div>
      </div>
    </article>
  </div>
</template>

<script setup>
defineProps({
  columns: { type: Array, default: () => [] }
})
</script>
