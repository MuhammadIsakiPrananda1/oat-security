import os from 'os';

/**
 * Returns formatted network interfaces and their IPv4 addresses for this server,
 * e.g. "eth0: 192.168.1.10, eth1: 10.0.0.5".
 *
 * Explicitly excludes:
 * - Loopback (127.0.0.1, ::1, lo)
 * - Docker interfaces (docker0, docker_gwbridge, etc.)
 * - Podman interfaces (podman0, podman1, etc.)
 * - Container virtual bridges and veth devices (br-*, veth*, cni*, flannel*)
 */
export function getServerNetworkAddresses(): string {
  try {
    const interfaces = os.networkInterfaces();
    const results: string[] = [];

    for (const [name, addrs] of Object.entries(interfaces)) {
      if (!addrs) continue;
      const lower = name.toLowerCase();

      // Exclude loopback, docker, podman, and virtual bridges/veth interfaces
      if (
        lower === 'lo' ||
        lower.includes('docker') ||
        lower.includes('podman') ||
        lower.startsWith('br-') ||
        lower.startsWith('veth') ||
        lower.startsWith('cni') ||
        lower.startsWith('flannel')
      ) {
        continue;
      }

      for (const addr of addrs) {
        if (addr.internal) continue;
        if (addr.family !== 'IPv4') continue;
        if (!addr.address || addr.address.startsWith('127.')) continue;

        results.push(`${name}: ${addr.address}`);
      }
    }

    if (results.length > 0) {
      return results.join(', ');
    }
  } catch (err) {
    console.warn('[NetworkUtils] Failed to inspect network interfaces:', err);
  }

  return '127.0.0.1';
}

