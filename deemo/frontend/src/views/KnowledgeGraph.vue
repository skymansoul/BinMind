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
import { ref, onMounted, onUnmounted } from 'vue'
import * as d3 from 'd3'
import { getKnowledgeGraph } from '@/api'
import type { KnowledgeGraphData } from '@/types'

const graphRef = ref<HTMLDivElement | null>(null)
const graphData = ref<KnowledgeGraphData>({ nodes: [], links: [] })

let currentSimulation: d3.Simulation<any, any> | null = null

const loadGraph = async () => {
  const r = await getKnowledgeGraph({})

  if (r?.success && r.data != null) {
    graphData.value = r.data as KnowledgeGraphData
    renderGraph()
  } else {
    const demo_nodes = [
      { id: 'cve-1', name: 'CVE-2024-0001', type: 'cve' },
      { id: 'func-1', name: 'vuln_func', type: 'function' },
      { id: 'bin-1', name: 'libvuln.so', type: 'binary' }
    ]

    const demo_links = [
      { source: 'cve-1', target: 'func-1', type: 'affects' },
      { source: 'func-1', target: 'bin-1', type: 'part_of' }
    ]

    graphData.value = { nodes: demo_nodes, links: demo_links }
    renderGraph()
  }
}

const getNodeColor = (node_type: any): string => {
  if (node_type == null || node_type === '') {
    return '#999999'
  }

  if (node_type === 'cve') return '#f56c6c'
  if (node_type === 'function') return '#409eff'
  if (node_type === 'binary') return '#67c23a'

  return '#909399'
}

// build D3 force-directed graph from current data
const renderGraph = () => {
  if (!graphRef.value) return

  if (currentSimulation != null) {
    currentSimulation.stop()
    currentSimulation = null
  }

  graphRef.value.innerHTML = ''

  const width = graphRef.value.clientWidth || 600
  const height = 500

  const svg = d3.select(graphRef.value)
    .append('svg')
    .attr('width', width)
    .attr('height', height)

  const links_data = graphData.value.links
  const nodes_data = graphData.value.nodes

  const link_elements = svg.append('g')
    .selectAll('line')
    .data(links_data)
    .enter()
    .append('line')
    .attr('stroke', '#999')
    .attr('stroke-width', 1.5)

  const node_elements = svg.append('g')
    .selectAll('circle')
    .data(nodes_data)
    .enter()
    .append('circle')
    .attr('r', 12)
    .attr('fill', (d: any) => getNodeColor(d.type))

  const label_elements = svg.append('g')
    .selectAll('text')
    .data(nodes_data)
    .enter()
    .append('text')
    .text((d: any) => d.name)
    .attr('font-size', 11)
    .attr('dx', 16)

  const sim = d3.forceSimulation(nodes_data as any)
    .force('link', d3.forceLink(links_data as any).id((d: any) => d.id).distance(120))
    .force('charge', d3.forceManyBody().strength(-300))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .on('tick', () => {
      link_elements
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y)

      node_elements
        .attr('cx', (d: any) => d.x)
        .attr('cy', (d: any) => d.y)

      label_elements
        .attr('x', (d: any) => d.x)
        .attr('y', (d: any) => d.y)
    })

  currentSimulation = sim
}

const exportD3 = () => {
  // 序列化当前图数据为 D3.js 标准 nodes/links JSON, 触发浏览器下载
  const graph_state = {
    nodes: graphData.value.nodes.map(function(n: any) {
      return { id: n.id, name: n.name, type: n.type }
    }),
    links: graphData.value.links.map(function(l: any) {
      const src = typeof l.source === 'object' && l.source != null ? l.source.id : l.source
      const tgt = typeof l.target === 'object' && l.target != null ? l.target.id : l.target
      return { source: src, target: tgt, type: l.type }
    })
  }
  const blob = new Blob([JSON.stringify(graph_state, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a_link = document.createElement('a')
  a_link.href = url
  a_link.download = 'knowledge_graph_d3.json'
  document.body.appendChild(a_link)
  a_link.click()
  document.body.removeChild(a_link)
  URL.revokeObjectURL(url)
}

onUnmounted(() => {
  if (currentSimulation != null) {
    currentSimulation.stop()
    currentSimulation = null
  }
})

onMounted(() => {
  loadGraph()
})
</script>

<style scoped>
.graph-container {
  width: 100%;
  min-height: 500px;
  border: 1px solid #e6e6e6;
  border-radius: 4px;
  background: #fafafa;
}
</style>
