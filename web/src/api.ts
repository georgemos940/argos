export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

// the crowdsec this browser looks at, when argos has more than one
const KEY = 'argos.instance';
export const selectedInstance = () => { try { return localStorage.getItem(KEY) ?? ''; } catch { return ''; } };
export function selectInstance(id: string) {
  try { if (id === 'main') localStorage.removeItem(KEY); else localStorage.setItem(KEY, id); } catch { /* private mode */ }
}

export async function api<T = any>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const { json, ...rest } = init;
  const res = await fetch(`/api${path}`, {
    credentials: 'same-origin',
    ...rest,
    headers: {
      'X-Argos': '1', ...(selectedInstance() ? { 'X-Argos-Instance': selectedInstance() } : {}),
      ...(json !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(rest.headers ?? {}),
    },
    body: json !== undefined ? JSON.stringify(json) : rest.body,
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith('/auth/')) window.dispatchEvent(new Event('argos:signed-out'));
    throw new ApiError(res.status, data?.error ?? res.statusText);
  }
  return data as T;
}

export interface Me {
  setup: boolean;
  user: { username: string; role: 'admin' | 'operator' | 'viewer'; totp: boolean } | null;
  needsTotp: boolean;
  mustEnroll?: boolean;
  passkeys?: boolean;
  ssoLinked?: boolean;
  sso?: { label: string } | null;
  instance: string;
  instanceId?: string;
  instances?: { id: string; name: string }[];
  home?: [number, number];
  demo?: boolean;
}

export interface SlimAlert {
  id: number; scenario: string; message: string; events_count: number; start_at: string; stop_at: string;
  target?: string;
  source: { scope: string; value: string; ip?: string; range?: string; cn?: string; as_name?: string; as_number?: string; latitude?: number; longitude?: number };
  decisions: { id: number; type: string; value: string; duration: string; origin: string }[];
}
