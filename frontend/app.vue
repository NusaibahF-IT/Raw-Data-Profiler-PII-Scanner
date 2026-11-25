<template>
  <div class="min-h-screen bg-canvas text-tx pb-16">
    <!-- Top Bar -->
    <header class="sticky top-0 z-30 border-b border-line bg-canvas/90 backdrop-blur-md">
      <div class="wrap h-16 flex items-center justify-between gap-4">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-xl bg-field border-[1.5px] border-ink shadow-sticker grid place-items-center font-mono font-black text-ink text-sm">
            DP
          </div>
          <div>
            <h1 class="text-base md:text-lg font-extrabold tracking-tight text-tx leading-none">
              Raw Data Profiler &amp; PII Scanner
            </h1>
            <p class="text-[11px] font-mono text-tx/65 mt-0.5">
              FastAPI + DuckDB + Nuxt 3 · Detect → Measure → Verify
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2.5">
          <span
            class="hidden sm:inline-flex items-center gap-1.5 chip font-mono"
            :class="apiHealthy ? 'bg-act/15 border-act/50 text-tx' : 'bg-mag/15 border-mag/50 text-mag'"
          >
            <span class="w-2 h-2 rounded-full" :class="apiHealthy ? 'bg-act' : 'bg-mag'" />
            {{ apiHealthy ? 'API Connected' : 'API Offline' }}
          </span>
          <button type="button" class="btn btn-outline text-xs py-1.5 px-3" @click="toggleTheme">
            {{ isDark ? '☀ Light' : '☾ Dark' }}
          </button>
        </div>
      </div>
    </header>

    <main class="wrap pt-8 space-y-6">
      <UploadDropzone
        :samples="samples"
        :active-sample-id="activeSampleId"
        :selected-file-name="selectedFile?.name || ''"
        v-model:mask-preview-pii="maskPreviewPii"
        :loading="loading"
        :available-sources="profileResult?.source?.available_sheets_or_tables || []"
        :selected-source="profileResult?.source?.selected_source || null"
        @upload-file="handleFileUpload"
        @load-sample="handleSampleLoad"
        @change-source="handleSourceChange"
      />

      <div v-if="errorMsg" class="p-4 rounded-xl bg-mag/15 border border-mag/50 text-sm font-semibold text-mag">
        {{ errorMsg }}
      </div>

      <template v-if="profileResult">
        <KpiOverviewStrip
          :overview="profileResult.overview"
          :pii-summary="profileResult.pii_summary"
        />

        <!-- Workspace Tabs -->
        <div class="flex flex-wrap items-center justify-between gap-3 pt-2">
          <div class="flex flex-wrap gap-2">
            <button
              v-for="tab in tabs"
              :key="tab.id"
              type="button"
              class="btn text-xs py-2 px-4"
              :class="activeTab === tab.id ? 'btn-primary' : 'btn-outline'"
              @click="activeTab = tab.id"
            >
              {{ tab.label }}
            </button>
          </div>
          <span class="text-xs font-mono text-tx/65">
            Source: <strong>{{ profileResult.source.filename }}</strong>
            <template v-if="profileResult.source.selected_source">
              ({{ profileResult.source.selected_source }})
            </template>
          </span>
        </div>

        <CandidateFindingsTable
          v-if="activeTab === 'findings'"
          :findings="profileResult.candidate_findings"
          @export-md="downloadMarkdownReport"
        />

        <PiiAuditPanel
          v-else-if="activeTab === 'pii'"
          :pii-summary="profileResult.pii_summary"
          :anonymizing="anonymizing"
          :anonymize-result="anonymizeResult"
          @run-anonymize="handleAnonymize"
        />

        <ColumnProfileCards
          v-else-if="activeTab === 'columns'"
          :columns="profileResult.columns"
        />

        <div v-else-if="activeTab === 'preview'" class="card-bento p-6 overflow-x-auto">
          <div class="flex items-center justify-between mb-4">
            <div>
              <h3 class="text-lg font-extrabold text-tx">Sample Rows Preview (First 8 Rows)</h3>
              <p class="text-xs text-tx/70">
                {{ maskPreviewPii ? 'PII columns are automatically masked in preview.' : 'Raw unmasked preview mode active.' }}
              </p>
            </div>
          </div>
          <table class="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr class="border-b border-line text-tx/70">
                <th v-for="col in profileResult.columns" :key="col.column" class="py-2 pr-4 whitespace-nowrap">
                  {{ col.column }}
                </th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(row, idx) in profileResult.preview_rows" :key="idx" class="border-b border-line/60">
                <td v-for="col in profileResult.columns" :key="col.column" class="py-2 pr-4 whitespace-nowrap">
                  {{ row[col.column] ?? 'NULL' }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>
    </main>
  </div>
</template>

<script setup>
import { onMounted, ref, watch } from 'vue'

const config = useRuntimeConfig()
const apiBase = config.public.apiBase

const isDark = ref(false)
const apiHealthy = ref(false)
const samples = ref([])
const activeSampleId = ref(null)
const selectedFile = ref(null)
const maskPreviewPii = ref(true)
const loading = ref(false)
const anonymizing = ref(false)
const errorMsg = ref('')
const profileResult = ref(null)
const anonymizeResult = ref(null)
const activeTab = ref('findings')

const tabs = [
  { id: 'findings', label: 'Candidate Findings' },
  { id: 'pii', label: 'PII Scanner & Masking' },
  { id: 'columns', label: 'Column Profiles' },
  { id: 'preview', label: 'Safe Data Preview' }
]

function toggleTheme() {
  isDark.value = !isDark.value
  document.documentElement.setAttribute('data-theme', isDark.value ? 'dark' : 'light')
}

async function fetchHealthAndSamples() {
  try {
    const h = await fetch(`${apiBase}/api/health`)
    apiHealthy.value = h.ok
    const s = await fetch(`${apiBase}/api/samples`)
    if (s.ok) {
      const data = await s.json()
      samples.value = data.samples || []
    }
  } catch {
    apiHealthy.value = false
  }
}

async function handleFileUpload(file, sourceOverride = null) {
  selectedFile.value = file
  activeSampleId.value = null
  anonymizeResult.value = null
  errorMsg.value = ''
  loading.value = true

  try {
    const form = new FormData()
    form.append('file', file)
    form.append('mask_preview_pii', String(maskPreviewPii.value))
    if (sourceOverride) {
      const ext = file.name.toLowerCase()
      if (ext.endsWith('.xlsx') || ext.endsWith('.xls')) form.append('sheet_name', sourceOverride)
      if (ext.endsWith('.sqlite') || ext.endsWith('.db')) form.append('table_name', sourceOverride)
    }
    const resp = await fetch(`${apiBase}/api/profile/upload`, { method: 'POST', body: form })
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}))
      throw new Error(err.detail || `Failed to profile file (${resp.status})`)
    }
    profileResult.value = await resp.json()
  } catch (err) {
    errorMsg.value = err.message || 'Error connecting to FastAPI backend.'
  } finally {
    loading.value = false
  }
}

async function handleSampleLoad(sampleId, sourceOverride = null) {
  activeSampleId.value = sampleId
  selectedFile.value = null
  anonymizeResult.value = null
  errorMsg.value = ''
  loading.value = true

  try {
    const params = new URLSearchParams({ mask_preview_pii: String(maskPreviewPii.value) })
    if (sourceOverride) params.set('sheet_name', sourceOverride)
    const resp = await fetch(`${apiBase}/api/profile/sample/${sampleId}?${params.toString()}`, {
      method: 'POST'
    })
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}))
      throw new Error(err.detail || `Failed to load sample (${resp.status})`)
    }
    profileResult.value = await resp.json()
  } catch (err) {
    errorMsg.value = err.message || 'Error connecting to FastAPI backend.'
  } finally {
    loading.value = false
  }
}

function handleSourceChange(sourceName) {
  if (selectedFile.value) {
    handleFileUpload(selectedFile.value, sourceName)
  } else if (activeSampleId.value) {
    handleSampleLoad(activeSampleId.value, sourceName)
  }
}

async function handleAnonymize({ strategies, piiTypes }) {
  anonymizing.value = true
  errorMsg.value = ''
  try {
    const form = new FormData()
    form.append('strategies_json', JSON.stringify(strategies))
    form.append('pii_types_json', JSON.stringify(piiTypes))

    let url = ''
    if (selectedFile.value) {
      form.append('file', selectedFile.value)
      url = `${apiBase}/api/anonymize/upload`
    } else if (activeSampleId.value) {
      url = `${apiBase}/api/anonymize/sample/${activeSampleId.value}`
    } else {
      throw new Error('No dataset loaded.')
    }

    const resp = await fetch(url, { method: 'POST', body: form })
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}))
      throw new Error(err.detail || 'Anonymization failed.')
    }
    anonymizeResult.value = await resp.json()
  } catch (err) {
    errorMsg.value = err.message || 'Failed to anonymize dataset.'
  } finally {
    anonymizing.value = false
  }
}

async function downloadMarkdownReport() {
  try {
    const form = new FormData()
    if (selectedFile.value) {
      form.append('file', selectedFile.value)
    } else if (activeSampleId.value) {
      form.append('sample_id', activeSampleId.value)
    } else {
      return
    }
    const resp = await fetch(`${apiBase}/api/report/markdown`, { method: 'POST', body: form })
    if (!resp.ok) throw new Error('Failed to export markdown report.')
    const text = await resp.text()
    const blob = new Blob([text], { type: 'text/markdown;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${profileResult.value?.source?.filename || 'dataset'}_audit_report.md`
    a.click()
    URL.revokeObjectURL(url)
  } catch (err) {
    errorMsg.value = err.message
  }
}

watch(maskPreviewPii, () => {
  if (selectedFile.value) handleFileUpload(selectedFile.value)
  else if (activeSampleId.value) handleSampleLoad(activeSampleId.value)
})

onMounted(() => {
  fetchHealthAndSamples()
})
</script>
