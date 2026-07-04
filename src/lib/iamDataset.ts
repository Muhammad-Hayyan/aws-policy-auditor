export interface IAMActionInfo {
  description: string;
  access_level: string;
  service_name: string;
}

export type IAMDatasetMap = Record<string, IAMActionInfo>;

// Bump this string whenever iam_definition.json is updated to invalidate the cache.....
const CACHE_KEY = 'iam_map_v1';
const DB_NAME = 'iam-auditor';
const STORE_NAME = 'dataset';

let memoryCache: IAMDatasetMap | null = null;

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE_NAME);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function readFromDB(): Promise<IAMDatasetMap | null> {
  try {
    const db = await openDB();
    return await new Promise((resolve, reject) => {
      const req = db.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).get(CACHE_KEY);
      req.onsuccess = () => { resolve(req.result ?? null); db.close(); };
      req.onerror = () => { reject(req.error); db.close(); };
    });
  } catch {
    return null;
  }
}

async function writeToDB(data: IAMDatasetMap): Promise<void> {
  try {
    const db = await openDB();
    await new Promise<void>((resolve, reject) => {
      const req = db.transaction(STORE_NAME, 'readwrite').objectStore(STORE_NAME).put(data, CACHE_KEY);
      req.onsuccess = () => { resolve(); db.close(); };
      req.onerror = () => { reject(req.error); db.close(); };
    });
  } catch {
    // IndexedDB unavailable (e.g. private browsing) — silently skip
  }
}

function buildMap(raw: Array<{
  prefix: string;
  service_name: string;
  privileges: Array<{ privilege: string; description: string; access_level: string }>;
}>): IAMDatasetMap {
  const map: IAMDatasetMap = {};
  for (const service of raw) {
    for (const priv of service.privileges) {
      map[`${service.prefix}:${priv.privilege}`] = {
        description: priv.description,
        access_level: priv.access_level,
        service_name: service.service_name,
      };
    }
  }
  return map;
}

export async function loadIAMDataset(): Promise<IAMDatasetMap> {
  if (memoryCache) return memoryCache;

  const persisted = await readFromDB();
  if (persisted) {
    memoryCache = persisted;
    return memoryCache;
  }

  const base = import.meta.env.BASE_URL ?? "/";
  const url = `${base}iam_definition.json`.replace(/\/+/g, "/");

  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to load IAM dataset: ${res.status}`);

  const raw = await res.json();
  const map = buildMap(raw);

  memoryCache = map;
  writeToDB(map); // fire-and-forget, don't block the UI
  return map;
}
