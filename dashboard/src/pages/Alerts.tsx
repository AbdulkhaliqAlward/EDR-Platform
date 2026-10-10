import { AlertTriangle, TrendingUp, X } from 'lucide-react';
import { useAlerts } from '../hooks/useAlerts';
import {
    AlertsFiltersBar,
    AlertsTable,
    BulkActionsToolbar,
    Pagination,
    AlertDetailPanel,
} from '../components/alerts';
import type { SortField } from '../hooks/useAlerts';

export default function Alerts() {
    const {
        // Data
        alerts,
        total,
        totalPages,
        agentHostnameMap,

        // Loading states
        isLoading,
        isError,

        // Pagination
        page,
        pageSize,
        setPage,
        setPageSize,

        // Sorting
        sortBy,
        sortOrder,
        toggleSort,

        // Filters
        filters,
        dateRange,
        setFilters,
        setDateRange,

        // Selection
        selectedIds,
        selectedAlert,
        toggleSelectAll,
        toggleSelect,
        setSelectedAlert,
        clearSelection,

        // Actions
        handleStatusChange,
        handleBulkAction,
        newAlertIds,
    } = useAlerts();

    if (isError) {
        return (
            <div className="card text-center py-12">
                <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">Failed to Load Alerts</h3>
                <p className="text-slate-500">Please try again later.</p>
            </div>
        );
    }

    const hasActiveFilters = filters.search.length > 0 || filters.severities.length > 0 || filters.statuses.length > 0;

    return (
        <>
            <div className="relative flex flex-col min-h-[calc(100vh-2rem)] lg:min-h-[calc(100vh-1rem)] h-full -mx-4 sm:-mx-6 lg:-mx-8 -my-4 sm:-my-6 lg:-my-8 p-4 sm:p-6 lg:p-8 bg-slate-200 dark:bg-gradient-to-br dark:from-slate-900 dark:via-[#0b1120] dark:to-slate-900 transition-colors overflow-hidden">
                {/* Background ambient glow */}
                <div className="absolute top-0 left-1/4 w-[800px] h-[500px] pointer-events-none -translate-y-1/2" style={{ background: 'radial-gradient(circle, rgba(6,182,212,0.08) 0%, transparent 70%)' }} />

                <div className="relative flex-1 flex flex-col min-h-0 space-y-4 lg:space-y-6 w-full">
                    {/* Header */}
                    <div className="flex items-center justify-between shrink-0">
                        <div>
                            <h2 className="text-xl font-bold text-slate-900 dark:text-white tracking-tight">Alerts (Triage)</h2>
                            <p className="text-sm text-slate-500 mt-1">Analyst triage queue.</p>
                        </div>
                        <div className="flex items-center gap-2 text-sm text-slate-500 bg-white/50 dark:bg-slate-800/50 px-3 py-1.5 rounded-full border border-slate-200 dark:border-slate-700/50 backdrop-blur-sm shadow-sm">
                            <TrendingUp className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                            <span>Sorted by <span className="font-semibold text-slate-800 dark:text-cyan-300">Risk Score</span></span>
                        </div>
                    </div>

                    {/* Filters */}
                    <AlertsFiltersBar
                        filters={filters}
                        dateRange={dateRange}
                        onFiltersChange={setFilters}
                        onDateRangeChange={setDateRange}
                    />

                    {/* Bulk Actions */}
                    <BulkActionsToolbar
                        selectedCount={selectedIds.size}
                        onAction={handleBulkAction}
                        onClear={clearSelection}
                    />

                    {/* Alert table */}
                    <div className="relative z-10 flex-1 flex flex-col min-h-0 overflow-hidden bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700/50 rounded-2xl shadow-lg">
                        <AlertsTable
                            alerts={alerts}
                            isLoading={isLoading}
                            selectedIds={selectedIds}
                            selectedAlert={selectedAlert}
                            agentHostnameMap={agentHostnameMap}
                            sortBy={sortBy}
                            sortOrder={sortOrder}
                            hasFilters={hasActiveFilters}
                            onToggleSelectAll={toggleSelectAll}
                            onToggleSelect={toggleSelect}
                            onSelectAlert={setSelectedAlert}
                            onStatusChange={handleStatusChange}
                            onToggleSort={toggleSort as (field: SortField) => void}
                            newAlertIds={newAlertIds}
                        />

                        {/* Pagination */}
                        <div className="shrink-0 z-20">
                            <Pagination
                                page={page}
                                totalPages={totalPages}
                                pageSize={pageSize}
                                total={total}
                                onPageChange={setPage}
                                onPageSizeChange={setPageSize}
                            />
                        </div>
                    </div>
                </div>
            </div>

            {/* Fixed Right-Side Drawer */}
            {selectedAlert && (
                <>
                    {/* Dim backdrop */}
                    <div
                        className="fixed inset-0 z-40 bg-black/30 backdrop-blur-[2px]"
                        onClick={() => setSelectedAlert(null)}
                        style={{ animation: 'fadeIn 0.15s ease-out' }}
                    />

                    {/* Drawer panel */}
                    <div
                        className="fixed right-0 top-0 bottom-0 z-50 w-full max-w-3xl flex flex-col bg-white dark:bg-slate-900 shadow-2xl border-l border-slate-200 dark:border-slate-700"
                        style={{ animation: 'slideInRight 0.2s ease-out' }}
                    >
                        {/* Header */}
                        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-700 shrink-0 bg-slate-50 dark:bg-slate-800/80">
                            <div className="flex items-center gap-3 min-w-0">
                                <span className={`w-3 h-3 rounded-full shrink-0 ${
                                    selectedAlert.severity === 'critical' ? 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.6)]' :
                                    selectedAlert.severity === 'high' ? 'bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.6)]' :
                                    selectedAlert.severity === 'medium' ? 'bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.6)]' :
                                    'bg-slate-400'
                                }`} />
                                <div className="min-w-0">
                                    <p className="text-sm font-bold text-slate-900 dark:text-white truncate">{selectedAlert.rule_title}</p>
                                    <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono truncate mt-0.5">{selectedAlert.id}</p>
                                </div>
                            </div>
                            <button
                                onClick={() => setSelectedAlert(null)}
                                className="shrink-0 ml-4 p-2 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition-colors"
                                title="Close (Esc)"
                            >
                                <X className="w-5 h-5" />
                            </button>
                        </div>

                        {/* Body */}
                        <div className="flex-1 overflow-y-auto" style={{ WebkitOverflowScrolling: 'touch' }}>
                            <AlertDetailPanel
                                alert={selectedAlert}
                                isOpen={false}
                                onClose={() => setSelectedAlert(null)}
                                onStatusChange={handleStatusChange}
                                inlineMode
                            />
                        </div>
                    </div>
                </>
            )}

        </>
    );
}
