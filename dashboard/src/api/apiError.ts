/** Server error message (connection-manager ErrorResponse.message) or a fallback. */
export function apiErrorMessage(err: unknown, fallback = 'Request failed'): string {
    const e = err as { response?: { data?: { message?: string } }; message?: string };
    return e?.response?.data?.message || e?.message || fallback;
}
