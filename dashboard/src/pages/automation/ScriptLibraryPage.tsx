import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { FileCode, Plus, Pencil, Trash2, X, Shield, Clock, AlertTriangle } from 'lucide-react';
import { agentsApi, responseScriptsApi, type ResponseScript, type ResponseScriptInput } from '../../api/client';
import { useToast } from '../../components';

const EMPTY_FORM: ResponseScriptInput = { name: '', description: '', cmd: '', timeout_seconds: 300, enabled: true };

/** Extracts the server's error message from an API error. */
function apiErrorMessage(e: unknown, fallback: string): string {
  const err = e as { response?: { data?: { message?: string } }; message?: string };
  return err?.response?.data?.message || err?.message || fallback;
}

/** Client-side checks; the server re-validates everything. */
function validateForm(f: ResponseScriptInput): string | null {
  if (!f.name.trim()) return 'Name is required.';
  if (!f.cmd.trim()) return 'Command is required.';
  if (/[\r\n\t]/.test(f.cmd)) return 'The command must be a single line (no line breaks or tabs).';
  if (!Number.isInteger(f.timeout_seconds) || f.timeout_seconds < 30 || f.timeout_seconds > 3600) {
    return 'Timeout must be a whole number between 30 and 3600 seconds.';
  }
  return null;
}

export function ScriptLibraryPage() {
  const { showToast } = useToast();
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<ResponseScript | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [form, setForm] = useState<ResponseScriptInput>(EMPTY_FORM);
  const [formError, setFormError] = useState<string | null>(null);

  const { data: caps } = useQuery({
    queryKey: ['command-capabilities'],
    queryFn: () => agentsApi.commandCapabilities(),
    staleTime: 5 * 60 * 1000,
  });
  const canManage = !!caps?.script_library_manage;

  const { data: scripts = [], isLoading, error } = useQuery({
    queryKey: ['response-scripts'],
    queryFn: () => responseScriptsApi.list(),
  });

  const saveMutation = useMutation({
    mutationFn: (input: ResponseScriptInput) =>
      editing ? responseScriptsApi.update(editing.id, input) : responseScriptsApi.create(input),
    onSuccess: (s) => {
      showToast(`Script "${s.name}" ${editing ? 'updated' : 'created'}`, 'success');
      queryClient.invalidateQueries({ queryKey: ['response-scripts'] });
      setFormOpen(false);
    },
    onError: (e) => setFormError(apiErrorMessage(e, 'Failed to save script')),
  });

  const deleteMutation = useMutation({
    mutationFn: (s: ResponseScript) => responseScriptsApi.delete(s.id),
    onSuccess: (_, s) => {
      showToast(`Script "${s.name}" deleted`, 'success');
      queryClient.invalidateQueries({ queryKey: ['response-scripts'] });
    },
    onError: (e) => showToast(apiErrorMessage(e, 'Failed to delete script'), 'error'),
  });

  const openCreate = () => {
    setEditing(null);
    setForm(EMPTY_FORM);
    setFormError(null);
    setFormOpen(true);
  };

  const openEdit = (s: ResponseScript) => {
    setEditing(s);
    setForm({ name: s.name, description: s.description, cmd: s.cmd, timeout_seconds: s.timeout_seconds, enabled: s.enabled });
    setFormError(null);
    setFormOpen(true);
  };

  const submit = () => {
    const input: ResponseScriptInput = {
      ...form,
      name: form.name.trim(),
      description: form.description.trim(),
      cmd: form.cmd.trim(),
    };
    const problem = validateForm(input);
    if (problem) {
      setFormError(problem);
      return;
    }
    setFormError(null);
    saveMutation.mutate(input);
  };

  const confirmDelete = (s: ResponseScript) => {
    if (!window.confirm(`Delete script "${s.name}"? Endpoints will no longer be able to run it.`)) return;
    deleteMutation.mutate(s);
  };

  const executables = caps?.script_library_executables || [];

  return (
    <div className="space-y-6 relative">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-teal-100 dark:bg-teal-900/30 rounded-lg">
            <FileCode className="w-6 h-6 text-teal-600 dark:text-teal-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Response Script Library</h1>
            <p className="text-sm text-slate-500 mt-1">
              Server-stored response commands that analysts can run on endpoints — no agent rebuild needed.
            </p>
          </div>
        </div>
        {canManage && (
          <button onClick={openCreate} className="btn btn-primary flex items-center gap-2">
            <Plus className="w-4 h-4" />
            New Script
          </button>
        )}
      </div>

      {/* How it works */}
      <div className="rounded-xl border border-teal-200 dark:border-teal-800/50 bg-teal-50 dark:bg-teal-900/10 p-4 text-sm text-teal-900 dark:text-teal-200 flex gap-3">
        <Shield className="w-5 h-5 shrink-0 mt-0.5 text-teal-600 dark:text-teal-400" />
        <div className="space-y-1">
          <p>
            Scripts run on the endpoint as SYSTEM, without a shell, under the agent&apos;s approved command list
            (PowerShell is limited to <code className="font-mono">-Command</code>). Run a script from an endpoint&apos;s
            <span className="font-semibold"> Response</span> tab → <span className="font-semibold">Run library script</span>.
          </p>
          <p>
            {canManage
              ? 'Only administrators can add or change scripts; every change is approved (when OTP is configured) and audited.'
              : 'Only administrators can add or change scripts.'}
          </p>
          {executables.length > 0 && (
            <p className="text-xs">
              Allowed programs: <span className="font-mono">{executables.join(', ')}</span>
            </p>
          )}
        </div>
      </div>

      {/* List */}
      <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden">
        {isLoading ? (
          <div className="p-12 text-center">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-teal-600"></div>
            <p className="text-sm font-medium text-slate-500 mt-4">Loading scripts...</p>
          </div>
        ) : error ? (
          <div className="p-8 text-center text-sm text-rose-600 dark:text-rose-400 flex items-center justify-center gap-2">
            <AlertTriangle className="w-4 h-4" />
            {apiErrorMessage(error, 'Failed to load scripts')}
          </div>
        ) : scripts.length === 0 ? (
          <div className="p-12 text-center text-sm text-slate-500">
            No scripts yet.{canManage ? ' Click "New Script" to add the first one.' : ''}
          </div>
        ) : (
          <div className="divide-y divide-slate-200 dark:divide-slate-700/80">
            {scripts.map((s) => (
              <div key={s.id} className={`p-5 flex flex-col lg:flex-row lg:items-start gap-4 ${s.enabled ? '' : 'opacity-70'}`}>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="font-bold text-slate-900 dark:text-white truncate">{s.name}</h3>
                    <span
                      className={`px-2 py-0.5 text-[10px] uppercase tracking-wider font-bold rounded-md border ${
                        s.enabled
                          ? 'bg-emerald-50 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800/50'
                          : 'bg-slate-100 dark:bg-slate-800 text-slate-500 border-slate-200 dark:border-slate-700'
                      }`}
                    >
                      {s.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </div>
                  {s.description && <p className="text-sm text-slate-600 dark:text-slate-400 mb-2">{s.description}</p>}
                  <pre className="text-xs font-mono bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-lg p-2.5 whitespace-pre-wrap break-all text-slate-700 dark:text-slate-300">
                    {s.cmd}
                  </pre>
                  <div className="flex flex-wrap items-center gap-4 mt-2 text-xs text-slate-500">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5" /> Timeout {s.timeout_seconds}s
                    </span>
                    <span>
                      Updated {new Date(s.updated_at).toLocaleString()} by {s.updated_by || s.created_by || 'unknown'}
                    </span>
                  </div>
                </div>
                {canManage && (
                  <div className="flex lg:flex-col gap-2 shrink-0">
                    <button
                      onClick={() => openEdit(s)}
                      className="px-3 py-2 text-sm font-medium rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 flex items-center gap-1.5"
                    >
                      <Pencil className="w-4 h-4" /> Edit
                    </button>
                    <button
                      onClick={() => confirmDelete(s)}
                      disabled={deleteMutation.isPending}
                      className="px-3 py-2 text-sm font-medium rounded-lg border border-slate-300 dark:border-slate-600 text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-900/20 flex items-center gap-1.5 disabled:opacity-50"
                    >
                      <Trash2 className="w-4 h-4" /> Delete
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Create / edit modal */}
      {formOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl w-full max-w-2xl flex flex-col border border-slate-200 dark:border-slate-800" style={{ maxHeight: '92vh' }}>
            <div className="flex items-center justify-between p-6 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/30 shrink-0">
              <h2 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <FileCode className="w-5 h-5 text-teal-500" />
                {editing ? 'Edit Script' : 'New Script'}
              </h2>
              <button
                onClick={() => setFormOpen(false)}
                className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4 overflow-y-auto flex-1">
              <div>
                <label className="block text-sm font-bold text-slate-700 dark:text-slate-300 mb-1.5">
                  Name <span className="text-rose-500">*</span>
                </label>
                <input
                  type="text"
                  maxLength={128}
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="e.g., List scheduled tasks"
                  className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-2.5 text-slate-900 dark:text-white focus:ring-2 focus:ring-teal-500 outline-none"
                />
              </div>
              <div>
                <label className="block text-sm font-bold text-slate-700 dark:text-slate-300 mb-1.5">Description</label>
                <input
                  type="text"
                  maxLength={1000}
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  placeholder="What this script does and when to use it"
                  className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-2.5 text-slate-900 dark:text-white focus:ring-2 focus:ring-teal-500 outline-none"
                />
              </div>
              <div>
                <label className="block text-sm font-bold text-slate-700 dark:text-slate-300 mb-1.5">
                  Command <span className="text-rose-500">*</span>
                </label>
                <textarea
                  value={form.cmd}
                  onChange={(e) => setForm({ ...form, cmd: e.target.value })}
                  placeholder={'powershell -Command "Get-ScheduledTask | Where-Object State -eq Ready | Select-Object TaskName,TaskPath"'}
                  className="w-full h-28 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-2.5 text-slate-900 dark:text-white focus:ring-2 focus:ring-teal-500 outline-none font-mono text-sm"
                />
                <p className="text-xs text-slate-500 mt-1">
                  One line. Start with the program name only (e.g. <code className="font-mono">powershell</code>, not a full path).
                  Put PowerShell code in quotes after <code className="font-mono">-Command</code>.
                </p>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-bold text-slate-700 dark:text-slate-300 mb-1.5">Timeout (seconds)</label>
                  <input
                    type="number"
                    min={30}
                    max={3600}
                    value={form.timeout_seconds}
                    onChange={(e) => setForm({ ...form, timeout_seconds: Number(e.target.value) })}
                    className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-2.5 text-slate-900 dark:text-white focus:ring-2 focus:ring-teal-500 outline-none"
                  />
                  <p className="text-xs text-slate-500 mt-1">How long the command stays deliverable. The agent stops the program itself after 120 seconds.</p>
                </div>
                <label className="flex items-center gap-2 text-sm font-medium text-slate-700 dark:text-slate-300 sm:mt-8">
                  <input
                    type="checkbox"
                    checked={form.enabled}
                    onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                    className="w-4 h-4 rounded"
                  />
                  Enabled (can be run from endpoints)
                </label>
              </div>

              {formError && (
                <div className="p-3 rounded-lg border border-rose-200 dark:border-rose-800/50 bg-rose-50 dark:bg-rose-900/20 text-sm text-rose-700 dark:text-rose-400 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                  <span>{formError}</span>
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-3 p-6 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/30 shrink-0">
              <button
                onClick={() => setFormOpen(false)}
                disabled={saveMutation.isPending}
                className="px-5 py-2.5 font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-lg"
              >
                Cancel
              </button>
              <button
                onClick={submit}
                disabled={saveMutation.isPending}
                className="px-6 py-2.5 font-bold text-white bg-teal-600 hover:bg-teal-700 rounded-lg shadow-md disabled:opacity-70 disabled:cursor-not-allowed"
              >
                {saveMutation.isPending ? 'Saving...' : editing ? 'Save Changes' : 'Create Script'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
