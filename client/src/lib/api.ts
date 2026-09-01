import type { CaptureSummary, HealthResponse, IncidentRecord, IncidentStatus, JobResponse, UploadResponse } from "./flowcrypid";

const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL?.trim();
export const API_BASE_URL = configuredBaseUrl ? configuredBaseUrl.replace(/\/$/, "") : "";

export interface AuthUser {
  id: number;
  email: string;
  role: "admin" | "analyst" | string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: AuthUser;
}

function apiUrl(path: string): string {
  return `${API_BASE_URL}${path.startsWith("/") ? path : `/${path}`}`;
}

async function parseError(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json();
    if (typeof body === "object" && body !== null && "detail" in body) {
      const detail = (body as { detail?: unknown }).detail;
      if (typeof detail === "string") return detail;
    }
  } catch {
    // Fall through to status text when the backend returns non-JSON content.
  }
  return response.statusText || `Request failed with status ${response.status}`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(apiUrl(path), init);
  if (!response.ok) throw new Error(await parseError(response));
  return (await response.json()) as T;
}

export async function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return request<HealthResponse>("/api/health", { signal });
}

export async function login(email: string, password: string, signal?: AbortSignal): Promise<LoginResponse> {
  return request<LoginResponse>("/api/auth/login", {
    method: "POST",
    signal,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
}

export async function getCurrentUser(token: string, signal?: AbortSignal): Promise<AuthUser> {
  return request<AuthUser>("/api/auth/me", { signal, headers: { Authorization: `Bearer ${token}` } });
}

export async function logout(token: string): Promise<void> {
  await request<{ status: string }>("/api/auth/logout", { method: "POST", headers: { Authorization: `Bearer ${token}` } });
}

export async function uploadPcap(file: File, token: string, signal?: AbortSignal): Promise<JobResponse> {
  const body = new FormData();
  body.append("file", file);
  return request<JobResponse>("/api/upload", { method: "POST", body, signal, headers: { Authorization: `Bearer ${token}` } });
}

export async function getAnalysisJob(jobId: string, token: string, signal?: AbortSignal): Promise<JobResponse> {
  return request<JobResponse>(`/api/jobs/${encodeURIComponent(jobId)}`, { signal, headers: { Authorization: `Bearer ${token}` } });
}

export async function getCaptures(token: string, signal?: AbortSignal): Promise<CaptureSummary[]> {
  return request<CaptureSummary[]>("/api/captures", { signal, headers: { Authorization: `Bearer ${token}` } });
}

export async function getIncidents(token: string, status?: IncidentStatus, signal?: AbortSignal): Promise<IncidentRecord[]> {
  const suffix = status ? `?status=${encodeURIComponent(status)}` : "";
  return request<IncidentRecord[]>(`/api/incidents${suffix}`, { signal, headers: { Authorization: `Bearer ${token}` } });
}

export async function updateIncident(token: string, incidentId: string, update: Partial<Pick<IncidentRecord, "status" | "assignee" | "notes">>): Promise<IncidentRecord> {
  return request<IncidentRecord>(`/api/incidents/${encodeURIComponent(incidentId)}`, { method: "PATCH", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify(update) });
}
