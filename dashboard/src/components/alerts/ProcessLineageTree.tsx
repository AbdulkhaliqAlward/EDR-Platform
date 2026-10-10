import { useState } from 'react';
import { Cpu, ChevronDown, ChevronUp } from 'lucide-react';
import type { ContextSnapshot, AncestorEntry } from '../../api/client';

interface ProcessNodeProps {
    name: string;
    path?: string;
    integrity?: string;
    isElevated?: boolean;
    sigStatus?: string;
    isTarget?: boolean;
    isSuspicious?: boolean;
}

function ProcessNode({ name, path, integrity, isElevated, sigStatus, isTarget = false, isSuspicious = false }: ProcessNodeProps) {
    const [expanded, setExpanded] = useState(false);
    const hasDetails = !!(path || integrity || isElevated || sigStatus);

    return (
        <div className={`rounded-lg border px-3 py-2 text-sm transition-all ${isTarget
                ? 'border-red-400 bg-red-50 dark:bg-red-950/40 dark:border-red-700'
                : isSuspicious
                    ? 'border-orange-400 bg-orange-50 dark:bg-orange-950/40 dark:border-orange-700'
                    : 'border-slate-200 bg-slate-50 dark:bg-slate-700/40 dark:border-slate-600'
            }`}>
            <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                    <Cpu className={`w-3.5 h-3.5 shrink-0 ${isTarget ? 'text-red-500' : isSuspicious ? 'text-orange-500' : 'text-slate-400'}`} />
                    <span className={`font-mono font-semibold truncate ${isTarget ? 'text-red-700 dark:text-red-300' : 'text-slate-800 dark:text-slate-200'}`}>
                        {name}
                    </span>
                    {isElevated && (
                        <span className="badge bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-200 text-xs shrink-0">
                            ELEVATED
                        </span>
                    )}
                    {sigStatus === 'microsoft' && (
                        <span className="badge bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-200 text-xs shrink-0">
                            MS-SIGNED
                        </span>
                    )}
                </div>
                {hasDetails && (
                    <button
                        onClick={() => setExpanded(!expanded)}
                        className="text-slate-400 hover:text-slate-600 shrink-0"
                    >
                        {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    </button>
                )}
            </div>
            {expanded && hasDetails && (
                <div className="mt-2 space-y-1 text-xs text-slate-500 dark:text-slate-400">
                    {path && <p className="font-mono truncate" title={path}>{path}</p>}
                    {integrity && <p>Integrity: <span className="font-medium">{integrity}</span></p>}
                    {sigStatus && <p>Signature: <span className="font-medium">{sigStatus}</span></p>}
                </div>
            )}
        </div>
    );
}

interface LineageTreeProps {
    snapshot: ContextSnapshot;
}

export function LineageTree({ snapshot }: LineageTreeProps) {
    const hasLineage = !!(snapshot.ancestor_chain?.length || snapshot.process_name || snapshot.process_path || snapshot.parent_name || snapshot.grandparent_name);
    const suspicionLevel = hasLineage ? snapshot.lineage_suspicion : 'unknown';
    const isSuspicious = suspicionLevel === 'critical' || suspicionLevel === 'high';

    const suspicionBadge: Record<string, string> = {
        critical: 'badge bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-200',
        high: 'badge bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-200',
        medium: 'badge bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-200',
        low: 'badge badge-info',
        none: 'badge badge-success',
    };

    const suspicionLabel: Record<string, string> = {
        critical: '🔴 Highly suspicious process chain',
        high: '🟠 Suspicious parent process',
        medium: '⚠️ Unusual parent process',
        low: '✅ Low suspicion',
        none: 'No suspicious lineage identified',
        unknown: 'Lineage unavailable',
    };

    // Build the chain from ancestor_chain if available, else fallback to flat fields
    const chain: AncestorEntry[] = snapshot.ancestor_chain || [];

    return (
        <div className="space-y-3">
            {/* Suspicion level header */}
            <div className="flex items-center justify-between">
                <span className="text-xs text-slate-500 uppercase tracking-wider">Process Lineage</span>
                <span className={suspicionBadge[suspicionLevel] || 'badge badge-info'}>
                    {suspicionLabel[suspicionLevel] || suspicionLevel}
                </span>
            </div>

            {/* Ancestor chain as visual tree */}
            {chain.length > 0 ? (
                <div className="space-y-1">
                    {chain.map((node, idx) => (
                        <div key={idx} className="flex items-start gap-2">
                            {idx > 0 && (
                                <div className="flex flex-col items-center ml-3 mr-1">
                                    <div className="w-px h-3 bg-slate-300 dark:bg-slate-600" />
                                    <div className="w-3 h-px bg-slate-300 dark:bg-slate-600" />
                                </div>
                            )}
                            <div className={`flex-1 ${idx > 0 ? '' : ''}`}>
                                <ProcessNode
                                    name={node.name}
                                    path={node.path}
                                    integrity={node.integrity}
                                    isElevated={node.is_elevated}
                                    sigStatus={node.sig_status}
                                    isTarget={idx === 0}
                                    isSuspicious={isSuspicious && idx > 0}
                                />
                            </div>
                        </div>
                    ))}
                </div>
            ) : (
                /* Fallback: use flat fields from ContextSnapshot */
                <div className="space-y-1">
                    {snapshot.grandparent_name && (
                        <div>
                            <ProcessNode
                                name={snapshot.grandparent_name}
                                path={snapshot.grandparent_path}
                                isSuspicious={isSuspicious}
                            />
                            <div className="ml-6 my-1 flex items-center gap-1 text-slate-400">
                                <div className="w-px h-4 bg-slate-300 dark:bg-slate-600 ml-1" />
                                <span className="text-xs">spawned</span>
                            </div>
                        </div>
                    )}
                    {snapshot.parent_name && (
                        <div>
                            <ProcessNode
                                name={snapshot.parent_name}
                                path={snapshot.parent_path}
                                isSuspicious={isSuspicious}
                            />
                            <div className="ml-6 my-1 flex items-center gap-1 text-slate-400">
                                <div className="w-px h-4 bg-slate-300 dark:bg-slate-600 ml-1" />
                                <span className="text-xs">spawned</span>
                            </div>
                        </div>
                    )}
                    {(snapshot.process_name || snapshot.process_path) && (
                        <ProcessNode
                            name={snapshot.process_name || 'Process name unavailable'}
                            path={snapshot.process_path}
                            integrity={snapshot.integrity_level}
                            isElevated={snapshot.is_elevated}
                            sigStatus={snapshot.signature_status}
                            isTarget={true}
                        />
                    )}
                    {!hasLineage && (
                        <p className="text-sm text-slate-400 italic">No lineage data captured for this alert.</p>
                    )}
                </div>
            )}
        </div>
    );
}

export default LineageTree;
