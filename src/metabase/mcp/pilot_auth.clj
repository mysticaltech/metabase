(ns metabase.mcp.pilot-auth
  "Native OAuth grant checks and request-local authority for the bounded MCP pilot."
  (:require
   [metabase.api.common :as api]
   [metabase.mcp.pilot-config :as config]
   [metabase.mcp.pilot-policy :as policy]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

(def ^:dynamic *authorization*
  "Server-established request authority. Never populated from request body or headers."
  nil)

(defn restricted-request?
  "Keep captured pilot requests restricted even if a configuration changes during dispatch."
  []
  (or (some? *authorization*) (config/configured? (config/current))))

(defn- current-client [client-id]
  (some-> (t2/select-one :model/OAuthClient :client_id client-id)
          (select-keys [:client_id :client_type :registration_type :application_type
                        :token_endpoint_auth_method :redirect_uris :response_types :grant_types :scopes])
          (update-keys #(keyword (.replace ^String (name %) "_" "-")))))

(defn- active-user? [user-id]
  (and (pos-int? user-id) (t2/exists? :model/User :id user-id :is_active true)))

(defn validate-grant!
  "Validate current policy/client/user for a stored or proposed pilot grant. Other clients retain native behavior."
  [grant]
  (let [c (config/current)]
    (case (config/client-mode c (:client-id grant))
      :baseline true
      :unavailable (config/unavailable!)
      :pilot (let [user-id (:user-id (:policy c))]
               (when-not (policy/grant-valid? (:policy c) grant (current-client (:client-id grant))
                                              (active-user? user-id))
                 (throw (ex-info "MCP pilot authorization unavailable."
                                 {:status-code 403 :type ::denied})))
               true))))

(defn validate-token-client!
  "Refuse issuance when deployment configuration cannot safely classify this client."
  [client-id]
  (when (= :unavailable (config/client-mode (config/current) client-id))
    (config/unavailable!)))

(defn authorize-mcp!
  "Validate an OAuth grant for an MCP request against the captured, active deployment policy."
  [captured-config grant]
  (when-not (= :active (:mode captured-config))
    (config/unavailable!))
  (when-not (and (= captured-config (config/current))
                 (= :pilot (config/client-mode captured-config (:client-id grant))))
    (policy/unavailable!))
  (validate-grant! grant)
  grant)

(defn ensure-authorized!
  "Recheck token validity and policy immediately before and after native execution."
  []
  (let [{:keys [config resolve-grant]} *authorization*]
    (when-not (and config resolve-grant)
      (policy/unavailable!))
    (let [grant (resolve-grant)]
      (when-not (and grant (= (str api/*current-user-id*) (str (:user-id grant))))
        (policy/unavailable!))
      (authorize-mcp! config grant))
    (:policy config)))

(defn bearer-request-error
  "Return a safe pre-fallback rejection for an unclassifiable or out-of-surface Bearer request.
   `client-id` is looked up from the stored token, including expired/revoked records."
  [c client-id path mixed-auth?]
  (when (config/configured? c)
    (cond
      (= :invalid-registry (:mode c))
      {:status 503 :message "MCP pilot configuration unavailable."}

      (nil? client-id)
      {:status 401 :message "Bearer authentication unavailable."}

      (= :unavailable (config/client-mode c client-id))
      {:status 503 :message "MCP pilot configuration unavailable."}

      (and (= :pilot (config/client-mode c client-id))
           (or mixed-auth? (not (policy/mcp-path? path))))
      {:status 403 :message "MCP pilot authorization unavailable."})))
