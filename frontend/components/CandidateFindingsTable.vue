<template>
  <div class="card-bento p-6">
    <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-5">
      <div>
        <h3 class="text-lg font-extrabold text-tx">Candidate Findings (Detect → Measure → Verify)</h3>
        <p class="text-xs text-tx/70 mt-0.5">
          All findings include affected counts and sample record keys for manual verification before cleaning.
        </p>
      </div>

      <div class="flex flex-wrap items-center gap-2">
        <button
          v-for="sev in ['ALL', 'High', 'Medium', 'Low']"
          :key="sev"
          type="button"
          class="btn text-xs py-1 px-3"
          :class="severityFilter === sev ? 'btn-primary' : 'btn-outline'"
          @click="severityFilter = sev"
        >
          {{ sev }}
        </button>
        <input
          v-model="query"
          type="search"
          placeholder="Filter field or area..."
          class="px-3 py-1.5 rounded-full border border-line bg-canvas text-xs text-tx focus:outline-none focus:border-ink"
        />
        <button type="button" class="btn btn-mint text-xs py-1.5 px-3.5" @click="$emit('export-md')">
          Export Report (.md) ↓
        </button>
      </div>
    </div>

    <div v-if="filteredFindings.length === 0" class="py-10 text-center text-sm text-tx/65">
      No candidate findings match the current filter.
    </div>

    <div v-else class="overflow-x-auto">
      <table class="w-full text-left border-collapse text-xs">
        <thead>
          <tr class="border-b border-line text-tx/70 uppercase text-[11px]">
            <th class="py-2.5 pr-3">ID</th>
            <th class="py-2.5 pr-3">Severity</th>
            <th class="py-2.5 pr-3">Area</th>
            <th class="py-2.5 pr-3">Field</th>
            <th class="py-2.5 pr-3">Affected</th>
            <th class="py-2.5 pr-3">Sample Keys</th>
            <th class="py-2.5">Description &amp; Evidence</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="item in filteredFindings"
            :key="item.finding_id"
            class="border-b border-line/70 hover:bg-canvas/70 align-top"
          >
            <td class="py-3 pr-3 font-mono font-bold whitespace-nowrap">{{ item.finding_id }}</td>
            <td class="py-3 pr-3 whitespace-nowrap">
              <span
                class="px-2 py-0.5 rounded-full text-[11px] font-extrabold"
                :class="severityClass(item.severity)"
              >
                {{ item.severity }}
              </span>
            </td>
            <td class="py-3 pr-3 font-semibold whitespace-nowrap">{{ item.area }}</td>
            <td class="py-3 pr-3 font-mono font-bold text-tx whitespace-nowrap">{{ item.field }}</td>
            <td class="py-3 pr-3 font-mono whitespace-nowrap">
              {{ item.count_affected }} ({{ item.pct_affected }}%)
            </td>
            <td class="py-3 pr-3 font-mono text-[11px] text-tx/80">
              {{ item.sample_record_keys?.length ? item.sample_record_keys.join(', ') : '-' }}
            </td>
            <td class="py-3">
              <p class="font-medium text-tx">{{ item.description }}</p>
              <p class="font-mono text-[11px] text-tx/60 mt-1">{{ item.evidence }}</p>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'

const props = defineProps({
  findings: { type: Array, default: () => [] }
})

defineEmits(['export-md'])

const severityFilter = ref('ALL')
const query = ref('')

const filteredFindings = computed(() => {
  return props.findings.filter((f) => {
    const matchSev = severityFilter.value === 'ALL' || f.severity === severityFilter.value
    const q = query.value.trim().toLowerCase()
    const matchQ =
      !q ||
      f.field.toLowerCase().includes(q) ||
      f.area.toLowerCase().includes(q) ||
      f.description.toLowerCase().includes(q)
    return matchSev && matchQ
  })
})

function severityClass(sev) {
  if (sev === 'High') return 'bg-mag/15 text-mag'
  if (sev === 'Medium') return 'bg-sun/30 text-ink'
  return 'bg-line text-tx/80'
}
</script>
