<template>
  <section class="card-bento p-6 md:p-7">
    <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-5">
      <div>
        <span class="sticker mb-2">Step 1 · Load Raw Source</span>
        <h2 class="text-xl md:text-2xl font-extrabold text-tx">
          Upload Dataset or Test with Bootcamp Samples
        </h2>
        <p class="text-xs md:text-sm text-tx/75 mt-1">
          Supports <span class="font-mono">CSV, TSV, TXT, XLSX, JSON (nested), Parquet, SQLite</span> — processed locally via DuckDB + pandas.
        </p>
      </div>

      <label class="inline-flex items-center gap-2.5 px-3.5 py-2 rounded-full border border-line bg-canvas cursor-pointer select-none text-xs font-semibold">
        <input
          type="checkbox"
          :checked="maskPreviewPii"
          @change="$emit('update:maskPreviewPii', $event.target.checked)"
          class="accent-[#00D26A] w-4 h-4"
        />
        <span>Mask PII in Preview (Sesi 4 Safe Mode)</span>
      </label>
    </div>

    <!-- Dropzone -->
    <div
      class="relative border-2 border-dashed rounded-bento p-6 md:p-8 text-center transition-all cursor-pointer"
      :class="isDragging ? 'border-act bg-field/15 scale-[1.01]' : 'border-line hover:border-tx/40 bg-canvas/50'"
      @dragover.prevent="isDragging = true"
      @dragleave.prevent="isDragging = false"
      @drop.prevent="onDrop"
      @click="fileInput?.click()"
    >
      <input
        ref="fileInput"
        type="file"
        class="hidden"
        accept=".csv,.tsv,.txt,.xlsx,.xls,.json,.parquet,.sqlite,.db"
        @change="onFileSelect"
      />

      <div class="flex flex-col items-center gap-2">
        <div class="w-12 h-12 rounded-2xl bg-field text-ink border-[1.5px] border-ink shadow-sticker flex items-center justify-center font-mono font-bold text-lg">
          { }
        </div>
        <p class="font-bold text-base text-tx mt-1">
          {{ selectedFileName ? `Selected: ${selectedFileName}` : 'Drop raw dataset here, or click to browse' }}
        </p>
        <p class="text-xs text-tx/65">
          Zero automatic mutations — profiling strictly follows <strong>Detect → Measure → Verify</strong>.
        </p>
      </div>
    </div>

    <!-- Sheet / Table switcher if multi-sheet or SQLite -->
    <div
      v-if="availableSources && availableSources.length > 1"
      class="mt-4 p-3.5 rounded-xl bg-sun/15 border border-sun/50 flex flex-wrap items-center gap-3"
    >
      <span class="text-xs font-extrabold text-tx">Multiple sheets/tables found:</span>
      <select
        :value="selectedSource"
        @change="$emit('change-source', $event.target.value)"
        class="px-3 py-1.5 rounded-lg border border-ink/30 bg-card text-tx text-xs font-mono font-bold"
      >
        <option v-for="src in availableSources" :key="src" :value="src">
          {{ src }}
        </option>
      </select>
    </div>

    <!-- Sample Datasets -->
    <div v-if="samples.length > 0" class="mt-5 pt-4 border-t border-line">
      <div class="flex items-center justify-between flex-wrap gap-2 mb-2.5">
        <span class="text-xs font-extrabold uppercase tracking-wider text-tx/70">
          Quick-Load Bootcamp Raw Datasets:
        </span>
        <span v-if="loading" class="text-xs font-mono font-bold text-act animate-pulse">
          Running DuckDB + PII scan...
        </span>
      </div>
      <div class="flex flex-wrap gap-2">
        <button
          v-for="s in samples"
          :key="s.id"
          type="button"
          :disabled="loading"
          class="btn text-xs py-1.5 px-3.5"
          :class="activeSampleId === s.id ? 'btn-mint' : 'btn-outline'"
          :title="s.description"
          @click="$emit('load-sample', s.id)"
        >
          <span class="font-mono text-[11px]">{{ s.filename }}</span>
        </button>
      </div>
    </div>
  </section>
</template>

<script setup>
import { ref } from 'vue'

defineProps({
  samples: { type: Array, default: () => [] },
  activeSampleId: { type: String, default: null },
  selectedFileName: { type: String, default: '' },
  maskPreviewPii: { type: Boolean, default: true },
  loading: { type: Boolean, default: false },
  availableSources: { type: Array, default: () => [] },
  selectedSource: { type: String, default: null }
})

const emit = defineEmits(['upload-file', 'load-sample', 'update:maskPreviewPii', 'change-source'])

const isDragging = ref(false)
const fileInput = ref(null)

function onDrop(e) {
  isDragging.value = false
  const file = e.dataTransfer?.files?.[0]
  if (file) emit('upload-file', file)
}

function onFileSelect(e) {
  const file = e.target?.files?.[0]
  if (file) emit('upload-file', file)
}
</script>
