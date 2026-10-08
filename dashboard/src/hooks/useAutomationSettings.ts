import { useQuery, useQueryClient } from '@tanstack/react-query';
import { automationApi, type AutomationSettings } from '../api/client';

export const AUTOMATION_SETTINGS_KEY = ['automation-settings'];

/**
 * Platform-wide automated-response switch. Cached for 30 s; components that
 * change it call `refresh()` so every view updates at once.
 */
export function useAutomationSettings() {
    const qc = useQueryClient();
    const q = useQuery<AutomationSettings>({
        queryKey: AUTOMATION_SETTINGS_KEY,
        queryFn: automationApi.getSettings,
        staleTime: 30_000,
        refetchInterval: 60_000,
        retry: 1,
    });
    return {
        settings: q.data,
        loading: q.isLoading,
        error: q.isError,
        refresh: () => qc.invalidateQueries({ queryKey: AUTOMATION_SETTINGS_KEY }),
        setCached: (s: AutomationSettings) => qc.setQueryData(AUTOMATION_SETTINGS_KEY, s),
    };
}
