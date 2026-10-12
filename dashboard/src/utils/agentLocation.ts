import type { AgentNetworkContext } from '../api/client';

/**
 * Where an agent connects from, as the server sees it (geolocated server-side
 * from the connection address): "Riyadh, Riyadh Region, Saudi Arabia (SA) · 198.51.100.23".
 */
export function formatAgentLocation(ctx?: Pick<AgentNetworkContext, 'network_scope' | 'public_ip' | 'city' | 'region' | 'country' | 'country_code'> | null): string {
    if (!ctx) return '';
    const ip = ctx.public_ip ? ` · ${ctx.public_ip}` : '';
    if (ctx.network_scope === 'private') return `Private network${ip}`;
    const country = ctx.country ? `${ctx.country}${ctx.country_code ? ` (${ctx.country_code})` : ''}` : ctx.country_code || '';
    const place = [ctx.city, ctx.region !== ctx.city ? ctx.region : '', country].filter(Boolean).join(', ');
    return place ? `${place}${ip}` : `Location unknown${ip}`;
}
