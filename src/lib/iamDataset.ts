export interface IAMActionInfo {
  description: string;
  access_level: string;
  service_name: string;
}

export type IAMDatasetMap = Record<string, IAMActionInfo>;

let cached: IAMDatasetMap | null = null;

export async function loadIAMDataset(): Promise<IAMDatasetMap> {
  if (cached) return cached;

  const base = import.meta.env.BASE_URL ?? "/";
  const url = `${base}iam_definition.json`.replace(/\/+/g, "/");

  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to load IAM dataset: ${res.status}`);

  const raw: Array<{
    prefix: string;
    service_name: string;
    privileges: Array<{
      privilege: string;
      description: string;
      access_level: string;
    }>;
  }> = await res.json();

  const map: IAMDatasetMap = {};
  for (const service of raw) {
    for (const priv of service.privileges) {
      const key = `${service.prefix}:${priv.privilege}`;
      map[key] = {
        description: priv.description,
        access_level: priv.access_level,
        service_name: service.service_name,
      };
    }
  }

  cached = map;
  return map;
}
