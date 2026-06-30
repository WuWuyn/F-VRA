import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  ReactFlowProvider,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react'
import type { Finding, Project, Reachability } from '../types'

type ProjectGraphProps = {
  mode: 'project'
  project: Project
  findings: Finding[]
  selectedId?: string
  onSelect?: (finding: Finding) => void
}

type CveGraphProps = {
  mode: 'cve'
  finding: Finding
  affectedFindings: Finding[]
  projects: Project[]
  onSelectProject?: (projectId: string) => void
}

type MiniGraphNodeData = {
  label: string
  meta: string
  kind: 'project' | 'package' | 'cve'
}

const nodeTypes = {
  miniImpact: MiniImpactNode,
}

export function ImpactGraph(props: ProjectGraphProps | CveGraphProps) {
  const graph = props.mode === 'project' ? buildProjectGraph(props) : buildCveGraph(props)
  return (
    <ReactFlowProvider>
      <div className="impact-flow-shell">
        <ReactFlow
          nodes={graph.nodes}
          edges={graph.edges}
          nodeTypes={nodeTypes}
          onNodeClick={(_, node) => graph.onNodeClick?.(node.id)}
          fitView
          fitViewOptions={{ padding: .22 }}
          minZoom={.35}
          maxZoom={2}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#d8e3ec" gap={24} />
          <Controls showInteractive={false} position="bottom-left" />
        </ReactFlow>
      </div>
    </ReactFlowProvider>
  )
}

function MiniImpactNode({ data, selected }: NodeProps<Node<MiniGraphNodeData>>) {
  return (
    <div className={`mini-impact-node ${data.kind} ${selected ? 'selected' : ''}`}>
      <Handle className="graph-handle graph-handle-left" type="target" position={Position.Left} />
      <Handle className="graph-handle graph-handle-right" type="source" position={Position.Right} />
      <span>{data.kind === 'project' ? 'P' : data.kind === 'package' ? 'ƒ' : '!'}</span>
      <div><strong>{data.label}</strong><small>{data.meta}</small></div>
    </div>
  )
}

function buildProjectGraph(props: ProjectGraphProps) {
  const uniqueFindings = Array.from(new Map(props.findings.map((item) => [item.id, item])).values())
  const packageNames = Array.from(new Set(uniqueFindings.map((item) => item.package)))
  const nodes: Node<MiniGraphNodeData>[] = [
    {
      id: `project:${props.project.id}`,
      type: 'miniImpact',
      position: { x: 0, y: 120 },
      data: { label: props.project.name, meta: props.project.repository, kind: 'project' },
    },
    ...packageNames.map((name, index) => ({
      id: `package:${name}`,
      type: 'miniImpact',
      position: { x: 360, y: 45 + index * 125 },
      data: { label: name, meta: 'Vulnerable dependency', kind: 'package' as const },
    })),
    ...uniqueFindings.map((finding, index) => ({
      id: `cve:${finding.id}`,
      type: 'miniImpact',
      position: { x: 720, y: 20 + index * 105 },
      data: { label: finding.id, meta: `${finding.severity} · ${finding.reachability}`, kind: 'cve' as const },
      selected: props.selectedId === finding.id,
    })),
  ]
  const edges: Edge[] = [
    ...packageNames.map((name) => edge(`project:${props.project.id}`, `package:${name}`, 'Reachable')),
    ...uniqueFindings.map((finding) => edge(`package:${finding.package}`, `cve:${finding.id}`, finding.reachability)),
  ]
  return {
    nodes,
    edges,
    onNodeClick: (id: string) => {
      const finding = uniqueFindings.find((item) => `cve:${item.id}` === id)
      if (finding) props.onSelect?.(finding)
    },
  }
}

function buildCveGraph(props: CveGraphProps) {
  const projectKey = (finding: Finding) => finding.projectId || finding.project
  const nodes: Node<MiniGraphNodeData>[] = [
    {
      id: `cve:${props.finding.id}`,
      type: 'miniImpact',
      position: { x: 0, y: 130 },
      data: { label: props.finding.id, meta: `${props.finding.severity} · CVSS ${props.finding.score}`, kind: 'cve' },
    },
    {
      id: `package:${props.finding.package}`,
      type: 'miniImpact',
      position: { x: 360, y: 130 },
      data: { label: props.finding.package, meta: shortFunction(props.finding.functionName), kind: 'package' },
    },
    ...props.affectedFindings.map((finding, index) => ({
      id: `project:${projectKey(finding)}`,
      type: 'miniImpact',
      position: { x: 720, y: 20 + index * 112 },
      data: { label: finding.project, meta: `${finding.pathCount} call path${finding.pathCount === 1 ? '' : 's'} · ${finding.reachability}`, kind: 'project' as const },
    })),
  ]
  const edges: Edge[] = [
    edge(`cve:${props.finding.id}`, `package:${props.finding.package}`, 'Reachable'),
    ...props.affectedFindings.map((finding) => edge(`package:${props.finding.package}`, `project:${projectKey(finding)}`, finding.reachability)),
  ]
  return {
    nodes,
    edges,
    onNodeClick: (id: string) => {
      if (id.startsWith('project:')) props.onSelectProject?.(id.replace('project:', ''))
    },
  }
}

function edge(source: string, target: string, reachability: Reachability): Edge {
  return {
    id: `${source}-${target}`,
    source,
    target,
    type: 'smoothstep',
    animated: reachability === 'Reachable',
    className: `rf-edge-${reachability.toLowerCase().replaceAll(' ', '-')}`,
    markerEnd: { type: MarkerType.ArrowClosed },
  }
}

function shortFunction(value: string) {
  return value.split('.').at(-1) ?? value
}
