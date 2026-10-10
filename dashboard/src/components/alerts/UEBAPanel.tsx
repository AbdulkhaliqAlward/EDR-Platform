import { Activity } from 'lucide-react';
import { UEBASignalBadge } from './UEBASignalBadge';
import type { ContextSnapshot } from '../../api/client';

interface UEBAPanelProps {
    snapshot: ContextSnapshot;
}

export function UEBAPanel({ snapshot }: UEBAPanelProps) {
    const bd = snapshot.score_breakdown;
    return (
        <div className="space-y-4 animate-slide-up-fade">
            {/* UEBA Signal */}
            <div>
                <span className="text-xs text-slate-500 uppercase tracking-wider block mb-2">Behavioral Signal</span>
                <div className="flex flex-wrap gap-2">
                    <UEBASignalBadge signal={bd?.ueba_signal || 'unknown'} />
                    {bd?.ueba_signal === 'anomaly' && (
                        <span className="inline-flex items-center gap-1 text-xs text-red-600 dark:text-red-400 font-medium">
                            +{bd.ueba_bonus} pts added to risk score
                        </span>
                    )}
                    {bd?.ueba_signal === 'normal' && (
                        <span className="inline-flex items-center gap-1 text-xs text-green-600 dark:text-green-400 font-medium">
                            −{bd.ueba_discount} pts subtracted (FP discount)
                        </span>
                    )}
                </div>
                {bd?.ueba_reason && <p className="text-xs text-slate-600 dark:text-slate-400 mt-2">{bd.ueba_reason}</p>}
            </div>

            {/* Temporal Burst — distinct detections on this host */}
            <div>
                <span className="text-xs text-slate-500 uppercase tracking-wider block mb-2">Distinct detections on this host</span>
                <div className="flex items-center gap-3">
                    {Number.isFinite(snapshot.burst_count) && Number.isFinite(snapshot.burst_window_sec) ? <div className="flex flex-wrap items-center gap-1.5">
                        <Activity className={`w-4 h-4 ${snapshot.burst_count > 3 ? 'text-orange-500' : 'text-slate-400'}`} />
                        <span className={`font-semibold text-sm ${snapshot.burst_count > 3 ? 'text-orange-600 dark:text-orange-400' : 'text-slate-700 dark:text-slate-300'}`}>
                            {snapshot.burst_count} rule{snapshot.burst_count !== 1 ? 's' : ''}
                        </span>
                        <span className="text-xs text-slate-500">in {Math.round(snapshot.burst_window_sec / 60)} min window</span>
                    </div> : <span className="text-xs text-slate-400">Burst data unavailable.</span>}
                    {bd && bd.burst_bonus > 0 && (
                        <span className="badge bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-200">
                            +{bd.burst_bonus} Burst Bonus
                        </span>
                    )}
                </div>
            </div>

            {/* Privilege Info */}
            <div>
                <span className="text-xs text-slate-500 uppercase tracking-wider block mb-2">Privilege Context</span>
                <div className="flex flex-wrap gap-2 text-sm">
                    {snapshot.integrity_level && (
                        <span className={`badge ${snapshot.integrity_level === 'System' || snapshot.integrity_level === 'High'
                                ? 'badge-danger'
                                : 'badge-info'
                            }`}>
                            {snapshot.integrity_level} Integrity
                        </span>
                    )}
                    {snapshot.is_elevated && (
                        <span className="badge badge-danger">Elevated Process</span>
                    )}
                    {snapshot.user_name && (
                        <span className="badge badge-info font-mono">{snapshot.user_name}</span>
                    )}
                    {snapshot.user_sid && !snapshot.user_name && (
                        <span className="badge badge-info font-mono" title="User SID is used for privilege scoring">{snapshot.user_sid}</span>
                    )}
                    {snapshot.signature_status && (
                        <span className={`badge ${snapshot.signature_status === 'microsoft' ? 'badge-success' : snapshot.signature_status === 'unsigned' ? 'badge-danger' : 'badge-warning'}`}>
                            {snapshot.signature_status === 'microsoft' ? '✓ Microsoft' : snapshot.signature_status}
                        </span>
                    )}
                    {!snapshot.integrity_level && !snapshot.is_elevated && !snapshot.user_name && !snapshot.user_sid && (
                        <span className="text-xs text-slate-400 italic">No privilege data captured.</span>
                    )}
                </div>
            </div>


            {/* Warnings */}
            {snapshot.warnings && snapshot.warnings.length > 0 && (
                <div className="rounded-md border border-yellow-200 dark:border-yellow-800 bg-yellow-50 dark:bg-yellow-900/20 p-3">
                    <span className="text-xs font-semibold text-yellow-700 dark:text-yellow-400 uppercase tracking-wider">
                        Partial Context (Degraded Signals)
                    </span>
                    <ul className="mt-1 space-y-1">
                        {snapshot.warnings.map((w, i) => (
                            <li key={i} className="text-xs text-yellow-600 dark:text-yellow-400 font-mono">{w}</li>
                        ))}
                    </ul>
                </div>
            )}
        </div>
    );
}

export default UEBAPanel;
