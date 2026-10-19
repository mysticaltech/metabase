(ns metabase.mcp.core
  "Public API for the MCP module. External consumers should use this namespace
   rather than reaching into internal namespaces like [[metabase.mcp.settings]]."
  (:require
   [clojure.string :as str]
   [metabase.api.macros :as api.macros]
   [metabase.mcp.pilot-auth :as pilot.auth]
   [metabase.mcp.pilot-config :as pilot.config]
   [metabase.mcp.resources :as mcp.resources]
   [metabase.mcp.session :as mcp.session]
   [metabase.mcp.settings :as mcp.settings]))

(set! *warn-on-reflection* true)

(defn pilot-configuration
  "Current bounded MCP pilot deployment state."
  []
  (pilot.config/current))

(defn validate-pilot-grant!
  "Apply the configured pilot ceiling to a stored or proposed native OAuth grant."
  [grant]
  (pilot.auth/validate-grant! grant))

(defn validate-pilot-token-client!
  "Refuse OAuth redemption/refresh when pilot configuration cannot classify the client."
  [client-id]
  (pilot.auth/validate-token-client! client-id))

(defn pilot-bearer-request-error
  "Return a pre-authentication rejection when a supplied Bearer cannot safely reach this route."
  [config client-id path mixed-auth?]
  (pilot.auth/bearer-request-error config client-id path mixed-auth?))

(defn cors-origins
  "Returns space-separated CORS origins from both common and custom MCP client settings."
  []
  (mcp.settings/mcp-apps-cors-origins))

(defn mcp-enabled?
  "Whether the MCP server is enabled (composes [[metabase.llm.settings/ai-features-enabled?]])."
  []
  (mcp.settings/mcp-enabled?))

(defn resolve-ui-credential
  "Resolves a credential issued for an MCP UI resource."
  [credential]
  (mcp.session/resolve-ui-credential credential))

(defn vscode-webview-enabled?
  "Returns true if vscode/cursor is enabled in common MCP apps."
  []
  (some #{"cursor-vscode"} (mcp.settings/mcp-apps-cors-enabled-clients)))

(defn sandbox-origin?
  "Returns true if the origin matches an enabled MCP client's non-standard sandbox pattern.
   Currently handles vscode-webview:// origins used by VS Code and Cursor."
  [raw-origin]
  (when raw-origin
    (condp #(str/starts-with? %2 %1) raw-origin
      "vscode-webview://" (vscode-webview-enabled?)
      false)))

(defn all-scopes
  "All supported OAuth scopes: those declared on agent-api endpoints via
   defendpoint metadata, plus scopes from MCP UI resources (e.g. visualize_query)."
  []
  (into (mcp.resources/resource-scopes)
        (comp (keep #(get-in % [:form :metadata :scope]))
              (filter string?))
        (vals (api.macros/ns-routes 'metabase.agent-api.api))))
