<template>
  <el-card>
    <template #header>
      <div style="display:flex; justify-content:space-between; align-items:center">
        <span>漏洞知识图谱</span>
        <el-button-group>
          <el-button @click="loadGraph" size="small">刷新</el-button>
          <el-button @click="exportD3" size="small">导出 D3.js</el-button>
        </el-button-group>
      </div>
    </template>
    <div ref="graphRef" class="graph-container"></div>
  </el-card>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import * as d3 from 'd3'
import { getKnowledgeGraph } from '@/api'
import type { KnowledgeGraphData } from '@/types'

const graphRef = ref<HTMLDivElement | null>(null)
const graphData = ref<KnowledgeGraphData>({ nodes: [], links: [] })

const loadGraph = async () => {
  const r = await getKnowledgeGraph({})
  if (r.success && r.data) {
    graphData.value = r.data as KnowledgeGraphData
    renderGraph()
  } else {
    // 演示数据
    graphData.value = {
      nodes: [
        { id: 'cve-1', name: 'CVE-2024-0001', type: 'cve' },
        { id: 'func-1', name: 'vuln_func', type: 'function' },
        { id: 'bin-1', name: 'libvuln.so', type: 'binary' }
      ],
      links: [
        { source: 'cve-1', target: 'func-1', type: 'affects' },
        { source: 'func-1', target: 'bin-1', type: 'part_of' }
      ]
    }
    renderGraph()
  }
}

const renderGraph = () => {
  if (!graphRef.value) return
  graphRef.value.innerHTML = ''
  const width = graphRef.value.clientWidth
  const height = 500
  const svg = d3.select(graphRef.value)
    .append('svg')
    .attr('width', width)
    .attr('height', height)
  const link = svg.selectAll('line')
    .data(graphData.value.links)
    .enter().append('line')
    .attr('stroke', '#999')
    .attr('stroke-width', 1.5)
  const node = svg.selectAll('circle')
    .data(graphData.value.nodes)
    .enter().append('circle')
    .attr('r', 12)
    .attr('fill', (d: any) => d.type === 'cve' ? '#f56c6c' : d.type === 'function' ? '#409eff' : '#67c23a')
  const label = svg.selectAll('text')
    .data(graphData.value.nodes)
    .enter().append('text')
    .text((d: any) => d.name)
    .attr('font-size', 11)
    .attr('dx', 16)
  const sim = d3.forceSimulation(graphData.value.nodes as any)
    .force('link', d3.forceLink(graphData.value.links as any).id((d: any) => d.id).distance(120))
    .force('charge', d3.forceManyBody().strength(-300))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y)
      node.attr('cx', (d: any) => d.x).attr('cy', (d: any) => d.y)
      label.attr('x', (d: any) => d.x).attr('y', (d: any) => d.y)
    })
}

const exportD3 = () => {
  const blob = new Blob([JSON.stringify(graphData.value, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'knowledge_graph_d3.json'
  a.click()
  URL.revokeObjectURL(url)
}

onMounted(loadGraph)
</script>

<style scoped>
.graph-container {
  width: 100%;
  height: 500px;
  background: #fafafa;
  border-radius: 6px;
}
</style>
