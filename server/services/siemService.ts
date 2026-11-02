import { db } from '../database/db';

export type SIEMProviderType = 'splunk' | 'elastic' | 'syslog' | 'webhook';
export type SIEMStatus = 'CONNECTED' | 'DISCONNECTED' | 'NOT CONFIGURED' | 'ERROR';

export interface SIEMConfig {
  id: string;
  provider: SIEMProviderType;
  endpoint?: string;
  indexOrChannel?: string;
  authToken?: string;
  status: SIEMStatus;
  lastSync?: string;
}

export class SIEMManager {
  public static getConfigs(organizationId: string): SIEMConfig[] {
    const rows = db.prepare(`
      SELECT * FROM integration_configs WHERE organization_id = ?
    `).all(organizationId) as Array<{
      id: string;
      provider: SIEMProviderType;
      config_json: string;
      status: SIEMStatus;
      updated_at: string;
    }>;

    const defaultProviders: SIEMProviderType[] = ['splunk', 'elastic', 'syslog', 'webhook'];
    const results: SIEMConfig[] = [];

    for (const p of defaultProviders) {
      const match = rows.find(r => r.provider === p);
      if (match) {
        let parsed: any = {};
        try {
          parsed = JSON.parse(match.config_json);
        } catch {
          parsed = {};
        }
        results.push({
          id: match.id,
          provider: p,
          endpoint: parsed.endpoint,
          indexOrChannel: parsed.indexOrChannel,
          status: match.status,
          lastSync: match.updated_at
        });
      } else {
        results.push({
          id: `cfg_${p}`,
          provider: p,
          status: 'NOT CONFIGURED'
        });
      }
    }

    return results;
  }

  public static saveConfig(
    organizationId: string,
    provider: SIEMProviderType,
    config: { endpoint?: string; indexOrChannel?: string; authToken?: string; enabled?: boolean }
  ): SIEMConfig {
    const status: SIEMStatus = config.endpoint ? 'CONNECTED' : 'NOT CONFIGURED';
    const id = `siem_${provider}_${organizationId}`;
    const json = JSON.stringify(config);

    db.prepare(`
      INSERT INTO integration_configs (id, organization_id, provider, config_json, status, updated_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
      ON DUPLICATE KEY UPDATE
        config_json = VALUES(config_json),
        status = VALUES(status),
        updated_at = VALUES(updated_at)
    `).run(id, organizationId, provider, json, status);

    return {
      id,
      provider,
      endpoint: config.endpoint,
      indexOrChannel: config.indexOrChannel,
      status,
      lastSync: new Date().toISOString()
    };
  }
}
