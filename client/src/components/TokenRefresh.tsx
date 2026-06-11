import { useState, useEffect, useCallback, useRef } from "react";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  RefreshCw,
  Eye,
  EyeOff,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import { CustomHeaders as CustomHeadersType } from "@/lib/types/customHeaders";
import { toast } from "@/lib/hooks/useToast";
import { ConnectionStatus } from "@/lib/constants";

interface TokenRefreshProps {
  customHeaders: CustomHeadersType;
  setCustomHeaders: (headers: CustomHeadersType) => void;
  connectionStatus: ConnectionStatus;
  onConnect: () => void;
  onDisconnect: () => void;
}

interface JwtClaims {
  iss?: string;
  azp?: string;
  exp?: number;
}

const parseJwt = (token: string): JwtClaims | null => {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    // atob requires padded base64; JWT payloads are unpadded base64url
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
};

const getBearerToken = (headers: CustomHeadersType): string | null => {
  const h = headers.find(
    (h) => h.enabled && h.name.toLowerCase() === "authorization",
  );
  if (!h) return null;
  const m = h.value.trim().match(/^Bearer\s+(\S+)/i);
  return m ? m[1] : null;
};

const resolveTokenEndpoint = async (issuer: string): Promise<string> => {
  try {
    const resp = await fetch(
      `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`,
    );
    if (resp.ok) {
      const cfg = await resp.json();
      if (typeof cfg.token_endpoint === "string") return cfg.token_endpoint;
    }
  } catch {
    // fall through to convention
  }
  return `${issuer.replace(/\/$/, "")}/protocol/openid-connect/token`;
};

const TokenRefresh = ({
  customHeaders,
  setCustomHeaders,
  connectionStatus,
  onConnect,
  onDisconnect,
}: TokenRefreshProps) => {
  const [enabled, setEnabled] = useState(false);
  const [refreshToken, setRefreshToken] = useState("");
  const [showRefreshToken, setShowRefreshToken] = useState(false);
  const [clientSecret, setClientSecret] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showSecret, setShowSecret] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [statusText, setStatusText] = useState<string | null>(null);

  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const customHeadersRef = useRef(customHeaders);
  const setCustomHeadersRef = useRef(setCustomHeaders);
  const refreshTokenRef = useRef(refreshToken);
  const clientSecretRef = useRef(clientSecret);
  const enabledRef = useRef(enabled);
  const connectionStatusRef = useRef(connectionStatus);
  const onConnectRef = useRef(onConnect);
  const onDisconnectRef = useRef(onDisconnect);

  customHeadersRef.current = customHeaders;
  setCustomHeadersRef.current = setCustomHeaders;
  refreshTokenRef.current = refreshToken;
  clientSecretRef.current = clientSecret;
  enabledRef.current = enabled;
  connectionStatusRef.current = connectionStatus;
  onConnectRef.current = onConnect;
  onDisconnectRef.current = onDisconnect;

  const currentToken = getBearerToken(customHeaders);
  const claims = currentToken ? parseJwt(currentToken) : null;

  const doFetch = useCallback(async (): Promise<number | null> => {
    const token = getBearerToken(customHeadersRef.current);
    if (!token) {
      toast({
        title: "Token refresh failed",
        description: "No Bearer token found in Authorization headers.",
        variant: "destructive",
      });
      return null;
    }
    const claims = parseJwt(token);
    if (!claims?.iss) {
      toast({
        title: "Token refresh failed",
        description: "JWT is missing the 'iss' claim.",
        variant: "destructive",
      });
      return null;
    }
    if (!claims.azp) {
      toast({
        title: "Token refresh failed",
        description: "JWT is missing the 'azp' (client ID) claim.",
        variant: "destructive",
      });
      return null;
    }

    const rt = refreshTokenRef.current;
    const secret = clientSecretRef.current;

    if (!rt && !secret) {
      toast({
        title: "Token refresh failed",
        description:
          "Provide a refresh token (public clients) or a client secret (confidential clients).",
        variant: "destructive",
      });
      return null;
    }

    setIsRefreshing(true);
    try {
      const tokenEndpoint = await resolveTokenEndpoint(claims.iss);

      // Prefer refresh_token grant; fall back to client_credentials for service accounts.
      const body = rt
        ? new URLSearchParams({
            grant_type: "refresh_token",
            client_id: claims.azp,
            refresh_token: rt,
            ...(secret ? { client_secret: secret } : {}),
          })
        : new URLSearchParams({
            grant_type: "client_credentials",
            client_id: claims.azp,
            client_secret: secret,
          });

      const response = await fetch(tokenEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });

      if (!response.ok) {
        const text = await response.text().catch(() => "");
        throw new Error(
          `${response.status} ${response.statusText}${text ? `: ${text}` : ""}`,
        );
      }

      const data = await response.json();
      const newToken: string = data.access_token;
      if (!newToken) throw new Error("No access_token in response");

      // Rotate the stored refresh token if the server issued a new one.
      if (data.refresh_token && data.refresh_token !== rt) {
        setRefreshToken(data.refresh_token);
      }

      // Update Authorization header in-place.
      const current = customHeadersRef.current;
      const authIdx = current.findIndex(
        (h) => h.name.toLowerCase() === "authorization",
      );
      const next = [...current];
      if (authIdx >= 0) {
        next[authIdx] = {
          ...next[authIdx],
          value: `Bearer ${newToken}`,
          enabled: true,
        };
      } else {
        next.push({
          name: "Authorization",
          value: `Bearer ${newToken}`,
          enabled: true,
        });
      }
      setCustomHeadersRef.current(next);

      // If currently connected, reconnect so the new token is used.
      // The setTimeout gives React one tick to re-render with the updated
      // headers before connect() reads them.
      if (connectionStatusRef.current === "connected") {
        onDisconnectRef.current();
        setTimeout(() => onConnectRef.current(), 100);
      }

      const newClaims = parseJwt(newToken);
      const expiresInMs =
        typeof data.expires_in === "number" ? data.expires_in * 1000 : 60_000;
      const refreshInMs = newClaims?.exp
        ? Math.max(newClaims.exp * 1000 - Date.now() - 30_000, 10_000)
        : Math.max(expiresInMs - 30_000, 10_000);

      const refreshedAt = new Date().toLocaleTimeString();
      const nextAt = new Date(Date.now() + refreshInMs).toLocaleTimeString();
      setStatusText(`Refreshed at ${refreshedAt} · next ~${nextAt}`);

      return refreshInMs;
    } catch (err) {
      toast({
        title: "Token refresh failed",
        description: err instanceof Error ? err.message : String(err),
        variant: "destructive",
      });
      setStatusText("Last refresh failed");
      return null;
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  const loop = useCallback(() => {
    doFetch().then((delay) => {
      if (delay !== null && enabledRef.current) {
        refreshTimerRef.current = setTimeout(loop, delay);
      }
    });
  }, [doFetch]);

  useEffect(() => {
    if (!enabled) return;
    loop();
    return () => {
      if (refreshTimerRef.current) {
        clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = null;
      }
    };
  }, [enabled, loop]);

  const handleToggle = (checked: boolean) => {
    if (!checked) {
      if (refreshTimerRef.current) {
        clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = null;
      }
      setStatusText(null);
    }
    setEnabled(checked);
  };

  const handleManualRefresh = () => {
    if (refreshTimerRef.current) {
      clearTimeout(refreshTimerRef.current);
      refreshTimerRef.current = null;
    }
    loop();
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Switch
            id="token-refresh-toggle"
            checked={enabled}
            onCheckedChange={handleToggle}
          />
          <label
            htmlFor="token-refresh-toggle"
            className="text-sm font-medium cursor-pointer select-none"
          >
            Auto-refresh token
          </label>
        </div>
        {enabled && (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={handleManualRefresh}
            disabled={isRefreshing}
            className="h-7 px-2"
            title="Refresh now"
          >
            <RefreshCw
              className={`w-3 h-3 ${isRefreshing ? "animate-spin" : ""}`}
            />
          </Button>
        )}
      </div>

      {enabled && (
        <div className="border rounded-md p-3 space-y-3">
          {/* Detected JWT info */}
          {claims?.iss ? (
            <div className="space-y-0.5">
              <p className="text-xs text-muted-foreground">
                <span className="font-medium">Issuer:</span> {claims.iss}
              </p>
              {claims.azp && (
                <p className="text-xs text-muted-foreground">
                  <span className="font-medium">Client:</span> {claims.azp}
                </p>
              )}
            </div>
          ) : (
            <p className="text-xs text-amber-600">
              No Bearer token with an <code>iss</code> claim detected yet.
            </p>
          )}

          {/* Refresh token (primary path for public clients) */}
          <div>
            <label className="text-xs text-muted-foreground">
              Refresh token
            </label>
            <div className="relative mt-1">
              <Input
                placeholder="Paste your refresh token here"
                value={refreshToken}
                onChange={(e) => setRefreshToken(e.target.value)}
                type={showRefreshToken ? "text" : "password"}
                className="font-mono text-xs pr-8"
              />
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setShowRefreshToken((s) => !s)}
                className="absolute right-1 top-1/2 -translate-y-1/2 h-6 w-6 p-0"
                aria-label={showRefreshToken ? "Hide token" : "Show token"}
              >
                {showRefreshToken ? (
                  <EyeOff className="w-3 h-3" />
                ) : (
                  <Eye className="w-3 h-3" />
                )}
              </Button>
            </div>
          </div>

          {statusText && (
            <p className="text-xs text-muted-foreground">{statusText}</p>
          )}

          {/* Advanced: client secret for confidential service accounts */}
          <button
            type="button"
            onClick={() => setShowAdvanced((s) => !s)}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
          >
            {showAdvanced ? (
              <ChevronDown className="w-3 h-3" />
            ) : (
              <ChevronRight className="w-3 h-3" />
            )}
            Service account (client secret)
          </button>
          {showAdvanced && (
            <div className="relative">
              <Input
                placeholder="client-secret — uses client_credentials grant instead"
                value={clientSecret}
                onChange={(e) => setClientSecret(e.target.value)}
                type={showSecret ? "text" : "password"}
                className="font-mono text-xs pr-8"
              />
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setShowSecret((s) => !s)}
                className="absolute right-1 top-1/2 -translate-y-1/2 h-6 w-6 p-0"
                aria-label={showSecret ? "Hide secret" : "Show secret"}
              >
                {showSecret ? (
                  <EyeOff className="w-3 h-3" />
                ) : (
                  <Eye className="w-3 h-3" />
                )}
              </Button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default TokenRefresh;
