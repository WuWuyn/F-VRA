import { useCallback, useMemo, useState } from 'react'
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import type { Finding, Project, Reachability } from '../types'

type NodeKind = 'project' | 'package' | 'cve'
type GraphNodeData = {
  label: string
  meta: string
  kind: NodeKind
  risk?: number
}

const nodeTypes = {
  portfolio: PortfolioNode,
}

export function PortfolioGraph({ findings, projects }: { findings: Finding[]; projects: Project[] }) {
  return (
    <ReactFlowProvider>
      <PortfolioGraphInner findings={findings} projects={projects} />
    </ReactFlowProvider>
  )
}

function PortfolioGraphInner({ findings, projects }: { findings: Finding[]; projects: Project[] }) {
  const { fitView, zoomIn, zoomOut } = useReactFlow()
  const graph = useMemo(() => buildReactFlowGraph(findings, projects), [findings, projects])
  const [nodes, , onNodesChange] = useNodesState(graph.nodes)
  const [edges, , onEdgesChange] = useEdgesState(graph.edges)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [visibleKinds, setVisibleKinds] = useState<Record<NodeKind, boolean>>({ project: true, package: true, cve: true })
  const selectedNode = nodes.find((node) => node.id === selectedId)

  const relatedIds = useMemo(() => {
    if (!selectedId) return new Set<string>()
    const ids = new Set<string>([selectedId])
    edges.forEach((edge) => {
      if (edge.source === selectedId) ids.add(edge.target)
      if (edge.target === selectedId) ids.add(edge.source)
    })
    return ids
  }, [edges, selectedId])

  const displayNodes = useMemo(() => nodes.map((node) => {
    const kind = node.data.kind
    const hidden = !visibleKinds[kind]
    const dimmed = selectedId !== null && !relatedIds.has(node.id)
    return {
      ...node,
      hidden,
      className: `${node.className ?? ''} ${dimmed ? 'dimmed' : ''}`,
      selected: selectedId === node.id,
    }
  }), [nodes, relatedIds, selectedId, visibleKinds])

  const displayEdges = useMemo(() => edges.map((edge) => {
    const source = nodes.find((node) => node.id === edge.source)
    const target = nodes.find((node) => node.id === edge.target)
    const hidden = !source || !target || !visibleKinds[source.data.kind] || !visibleKinds[target.data.kind]
    const dimmed = selectedId !== null && !(relatedIds.has(edge.source) && relatedIds.has(edge.target))
    return { ...edge, hidden, className: `${edge.className ?? ''} ${dimmed ? 'dimmed' : ''}` }
  }), [edges, nodes, relatedIds, selectedId, visibleKinds])

  const toggleKind = (kind: NodeKind) => {
    setVisibleKinds((current) => ({ ...current, [kind]: !current[kind] }))
  }

  const focusNode = useCallback((_: unknown, node: Node<GraphNodeData>) => {
    setSelectedId((current) => current === node.id ? null : node.id)
  }, [])

  const openProject = useCallback((_: unknown, node: Node<GraphNodeData>) => {
    if (node.data.kind === 'project') window.location.assign(`#/project/${node.id.replace('project:', '')}`)
  }, [])

  return (
    <div className="portfolio-graph-shell react-flow-shell">
      <div className="graph-canvas-toolbar">
        <div className="graph-filters">
          {(['project', 'package', 'cve'] as NodeKind[]).map((kind) => (
            <button className={visibleKinds[kind] ? 'active' : ''} key={kind} onClick={() => toggleKind(kind)}>
              <i className={`${kind}-key`} />{kind === 'cve' ? 'CVEs' : `${kind[0].toUpperCase()}${kind.slice(1)}s`}
            </button>
          ))}
        </div>
        <div className="graph-zoom-controls">
          <button onClick={() => zoomOut()} aria-label="Zoom out">−</button>
          <button onClick={() => zoomIn()} aria-label="Zoom in">+</button>
          <button className="fit-button" onClick={() => fitView({ padding: .18, duration: 350 })}>Fit graph</button>
        </div>
      </div>

      <div className="portfolio-graph-stage">
        <ReactFlow
          className="portfolio-graph-flow"
          nodes={displayNodes}
          edges={displayEdges}
          nodeTypes={nodeTypes}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={focusNode}
          onNodeDoubleClick={openProject}
          onInit={(instance) => {
            window.requestAnimationFrame(() => {
              instance.fitView({ padding: .18, duration: 250 })
            })
          }}
          onPaneClick={() => setSelectedId(null)}
          fitView
          fitViewOptions={{ padding: .18 }}
          defaultViewport={{ x: 80, y: 50, zoom: .75 }}
          minZoom={.2}
          maxZoom={2.4}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#c9d6e0" gap={26} />
          <Controls position="bottom-left" />
          <MiniMap
            position="bottom-right"
            pannable
            zoomable
            nodeColor={(node) => nodeColor(node.data.kind as NodeKind)}
            maskColor="rgba(3, 32, 73, .08)"
          />
        </ReactFlow>
        <div className="graph-help">Scroll to zoom · Drag canvas to pan · Drag nodes to rearrange · Double-click a project to open</div>
        {selectedNode && <NodeInspector node={selectedNode} edges={edges} onClose={() => setSelectedId(null)} />}
      </div>
    </div>
  )
}

function PortfolioNode({ data, selected }: NodeProps<Node<GraphNodeData>>) {
  return (
    <div className={`rf-portfolio-node ${data.kind} ${selected ? 'selected' : ''}`}>
      <Handle className="graph-handle graph-handle-left" type="target" position={Position.Left} />
      <Handle className="graph-handle graph-handle-right" type="source" position={Position.Right} />
      <div className="rf-node-symbol">{data.kind === 'project' ? 'P' : data.kind === 'package' ? 'ƒ' : '!'}</div>
      <div className="rf-node-copy">
        <strong>{data.label}</strong>
        <span>{data.meta}</span>
      </div>
      {data.risk !== undefined && <b>{data.risk}</b>}
    </div>
  )
}

function NodeInspector({ node, edges, onClose }: { node: Node<GraphNodeData>; edges: Edge[]; onClose: () => void }) {
  const related = edges.filter((edge) => edge.source === node.id || edge.target === node.id)
  return (
    <aside className="graph-inspector">
      <button className="inspector-close" onClick={onClose}>×</button>
      <span className="page-eyebrow">{node.data.kind}</span>
      <h3>{node.data.label}</h3>
      <p>{node.data.meta}</p>
      <div className="inspector-stat"><span>Connected nodes</span><strong>{related.length}</strong></div>
      <div className="inspector-stat"><span>Reachable edges</span><strong>{related.filter((edge) => edge.data?.reachability === 'Reachable').length}</strong></div>
      {node.data.kind === 'project' && <button className="primary-button" onClick={() => window.location.assign(`#/project/${node.id.replace('project:', '')}`)}>Open project</button>}
    </aside>
  )
}

function buildReactFlowGraph(findings: Finding[], projects: Project[]) {
  const nodes: Node<GraphNodeData>[] = []
  const edges: Edge[] = []
  const centerX = 720
  const centerY = 360

  projects.forEach((project, index) => {
    nodes.push({
      id: `project:${project.id}`,
      type: 'portfolio',
      position: { x: 40, y: 70 + index * 145 },
      data: {
        label: project.name,
        meta: `${project.reachable} reachable · risk ${project.riskScore}`,
        kind: 'project',
        risk: project.riskScore,
      },
    })
  })

  const packageNames = Array.from(new Set(findings.map((finding) => finding.package)))
  packageNames.forEach((name, index) => {
    const angle = (index * 360 / packageNames.length - 90) * Math.PI / 180
    nodes.push({
      id: `package:${name}`,
      type: 'portfolio',
      position: {
        x: centerX + Math.cos(angle) * 135,
        y: centerY + Math.sin(angle) * 165,
      },
      data: {
        label: name,
        meta: `${findings.filter((finding) => finding.package === name).length} affected instances`,
        kind: 'package',
      },
    })
  })

  const uniqueCves = Array.from(new Map(findings.map((finding) => [finding.id, finding])).values())
  uniqueCves.forEach((finding, index) => {
    nodes.push({
      id: `cve:${finding.id}`,
      type: 'portfolio',
      position: { x: 1150, y: 85 + index * 150 },
      data: {
        label: finding.id,
        meta: `${finding.severity} · ${finding.package}`,
        kind: 'cve',
      },
    })
    edges.push(makeEdge(`package:${finding.package}`, `cve:${finding.id}`, strongestReachability(findings.filter((item) => item.id === finding.id).map((item) => item.reachability))))
  })

  findings.forEach((finding, index) => {
    edges.push(makeEdge(`project:${finding.projectId || finding.project}`, `package:${finding.package}`, finding.reachability, index))
  })

  return { nodes, edges }
}

function makeEdge(source: string, target: string, reachability: Reachability, index = 0): Edge {
  return {
    id: `${source}-${target}-${index}`,
    source,
    target,
    type: 'smoothstep',
    animated: reachability === 'Reachable',
    className: `rf-edge-${statusClass(reachability)}`,
    markerEnd: { type: MarkerType.ArrowClosed },
    data: { reachability },
  }
}

function strongestReachability(values: Reachability[]): Reachability {
  if (values.includes('Reachable')) return 'Reachable'
  if (values.includes('Potentially reachable')) return 'Potentially reachable'
  return 'Not reachable'
}

function statusClass(status: Reachability) {
  return status.toLowerCase().replaceAll(' ', '-')
}

function nodeColor(kind: NodeKind) {
  if (kind === 'project') return '#547494'
  if (kind === 'package') return '#63819d'
  return '#d95b56'
}
