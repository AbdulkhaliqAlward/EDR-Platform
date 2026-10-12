/** Server error message (connection-manager ErrorResponse.message, sigma-engine `error`) or a fallback. */
export function apiErrorMessage(err: unknown, fallback = 'Request failed'): string {
    const e = err as { response?: { data?: { message?: string; error?: string } }; message?: string };
    return e?.response?.data?.message || e?.response?.data?.error || e?.message || fallback;
}
