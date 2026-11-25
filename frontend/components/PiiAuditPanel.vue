<template>
  <div class="card-bento p-6 space-y-6">
    <div class="flex flex-col md:flex-row md:items-center justify-between gap-4">
      <div>
        <h3 class="text-lg font-extrabold text-tx">PII Scanner &amp; Safe Anonymizer (Sesi 4 Governance)</h3>
        <p class="text-xs text-tx/70 mt-0.5">
          Choose a masking strategy per detected PII column, then generate a verified safe CSV for downstream analysis.
        </p>
      </div>
      <button
        v-if="piiSummary.findings.length > 0"
        type="button"
        :disabled="anonymizing"
        class="btn btn-mint text-xs py-2 px-4"
        @click="triggerAnonymize"
      >
        {{ anonymizing ? 'Applying & Verifying...' : 'Apply Masking & Run VT-01..VT-03 ✓' }}
      </button>
    </div>

    <div v-if="piiSummary.findings.length === 0" class="p-6 rounded-xl bg-act/10 border border-act/40 text-sm font-semibold text-tx">
      SAFE_NO_PII_DETECTED — No email, phone, NIK, NPWP, name, or address patterns were flagged in this dataset.
    </div>

    <div v-else class="overflow-x-auto">
      <table class="w-full text-left border-collapse text-xs">
        <thead>
          <tr class="border-b border-line text-tx/70 uppercase text-[11px]">
            <th class="py-2.5 pr-3">Column</th>
            <th class="py-2.5 pr-3">PII Type</th>
            <th class="py-2.5 pr-3">Risk</th>
            <th class="py-2.5 pr-3">Detection Source</th>
            <th class="py-2.5 pr-3">Masked Samples</th>
            <th class="py-2.5">Protection Strategy</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="item in piiSummary.findings"
            :key="item.column"
            class="border-b border-line/70 align-middle"
          >
            <td class="py-3 pr-3 font-mono font-bold text-tx">{{ item.column }}</td>
            <td class="py-3 pr-3 font-mono font-bold">{{ item.pii_type }}</td>
            <td class="py-3 pr-3">
              <span
                class="px-2 py-0.5 rounded-full text-[11px] font-extrabold"
                :class="item.risk_level === 'High' ? 'bg-mag/15 text-mag' : 'bg-sun/30 text-ink'"
              >
                {{ item.risk_level }}
              </span>
            </td>
            <td class="py-3 pr-3 font-mono text-[11px] text-tx/75">{{ item.detection_source }}</td>
            <td class="py-3 pr-3 font-mono text-[11px] text-tx/80">
              {{ item.masked_examples?.join(', ') || '-' }}
            </td>
            <td class="py-3">
              <select
                v-model="strategies[item.column]"
                class="px-2.5 py-1.5 rounded-lg border border-line bg-canvas text-tx text-xs font-mono font-semibold"
              >
                <option value="sha256">sha256 (Joinable Hash)</option>
                <option value="partial">partial (e.g. wa***@)</option>
                <option value="redact">redact ([REDACTED])</option>
                <option value="keep">keep (Unmasked)</option>
              </select>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Verification Gate Output -->
    <div
      v-if="anonymizeResult"
      class="p-5 rounded-xl border"
      :class="anonymizeResult.verification_evidence.overall_gate === 'PASS' ? 'bg-act/10 border-act/50' : 'bg-mag/10 border-mag/50'"
    >
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <span class="text-xs font-mono font-extrabold uppercase">
            VERIFICATION GATE: {{ anonymizeResult.verification_evidence.overall_gate }}
          </span>
          <p class="text-xs text-tx/80 mt-1">
            VT-01 No Raw PII Leak: <strong>{{ anonymizeResult.verification_evidence['VT-01_no_raw_pii_leak'].status }}</strong> ·
            VT-02 Row Count Preserved: <strong>{{ anonymizeResult.verification_evidence['VT-02_row_count_preserved'].status }}</strong>
            ({{ anonymizeResult.verification_evidence['VT-02_row_count_preserved'].after_rows }} rows) ·
            VT-03 Schema Preserved: <strong>{{ anonymizeResult.verification_evidence['VT-03_schema_preserved'].status }}</strong>
          </p>
        </div>

        <div class="flex flex-wrap gap-2">
          <button type="button" class="btn btn-primary text-xs py-1.5 px-3.5" @click="downloadMaskedCsv">
            Download Safe CSV ↓
          </button>
          <button type="button" class="btn btn-outline text-xs py-1.5 px-3.5" @click="downloadEvidenceJson">
            Download Evidence JSON ↓
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { reactive, watch } from 'vue'

const props = defineProps({
  piiSummary: { type: Object, required: true },
  anonymizing: { type: Boolean, default: false },
  anonymizeResult: { type: Object, default: null }
})

const emit = defineEmits(['run-anonymize'])

const strategies = reactive({})

watch(
  () => props.piiSummary,
  (val) => {
    for (const k of Object.keys(strategies)) delete strategies[k]
    for (const item of val?.findings || []) {
      strategies[item.column] = item.recommended_strategy || 'sha256'
    }
  },
  { immediate: true }
)

function triggerAnonymize() {
  const piiTypes = {}
  for (const item of props.piiSummary.findings || []) {
    piiTypes[item.column] = item.pii_type
  }
  emit('run-anonymize', { strategies: { ...strategies }, piiTypes })
}

function downloadBlob(content, filename, mime) {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function downloadMaskedCsv() {
  if (!props.anonymizeResult) return
  downloadBlob(props.anonymizeResult.csv_content, props.anonymizeResult.filename, 'text/csv;charset=utf-8;')
}

function downloadEvidenceJson() {
  if (!props.anonymizeResult) return
  downloadBlob(
    JSON.stringify(props.anonymizeResult.verification_evidence, null, 2),
    props.anonymizeResult.filename.replace('.csv', '_verification_evidence.json'),
    'application/json'
  )
}
</script>
