import { useQuery } from '@tanstack/react-query';
import { agentBuildApi } from '../api/client';

/** Where agents reach the server: prefilled into every build / upgrade form. */
export interface AgentServerSettings {
    serverIP: string;
    serverDomain: string;
    serverPort: string;
}

/** Used when the deployment has no DNS name; the installer writes it to the hosts file. */
export const DEFAULT_AGENT_DOMAIN = 'edr.local';
export const DEFAULT_AGENT_PORT = '47051';

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

/** The address the dashboard was opened on, when it is a usable IPv4 literal. */
export function browserHostIP(hostname: string = typeof window !== 'undefined' ? window.location.hostname : ''): string {
    return IPV4.test(hostname) && !hostname.startsWith('127.') && hostname !== '0.0.0.0' ? hostname : '';
}

/**
 * Server-resolved defaults (GET /api/v1/agent/build-defaults: deployment env,
 * C2_GRPC_ADDRESS, the host the dashboard is served from, DNS), falling back
 * to the browser's host IP and the default domain/port.
 */
export function useAgentBuildDefaults(enabled = true) {
    const q = useQuery({
        queryKey: ['agent-build-defaults'],
        queryFn: agentBuildApi.defaults,
        enabled,
        staleTime: 5 * 60_000,
        retry: 1,
    });
    const settings: AgentServerSettings = {
        serverIP: q.data?.server_ip || browserHostIP(),
        serverDomain: q.data?.server_domain || DEFAULT_AGENT_DOMAIN,
        serverPort: q.data?.server_port || DEFAULT_AGENT_PORT,
    };
    return { settings, isLoading: q.isLoading, isResolved: q.isSuccess || q.isError };
}

/**
 * The ready-to-run install command. Server flags are always explicit, so the
 * same command works for builds with embedded settings and for "skip config"
 * builds, and never relies on the agent's container-internal default port.
 */
export function agentInstallCommand(token: string, s: AgentServerSettings): string {
    const ip = s.serverIP.trim() || '<SERVER_IP>';
    const domain = s.serverDomain.trim() || DEFAULT_AGENT_DOMAIN;
    const port = s.serverPort.trim() || DEFAULT_AGENT_PORT;
    return `echo '${token}' | .\\edr-agent.exe -install -token-stdin -server-ip ${ip} -server-domain ${domain} -server-port ${port}`;
}
