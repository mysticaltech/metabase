(ns metabase.mcp.native-access
  "Account admission only. Native MCP tools and Metabase role checks remain unchanged."
  (:require
   ^{:clj-kondo/ignore [:discouraged-namespace]} [cheshire.core :as json]
   [metabase.mcp.pilot-config :as pilot.config]
   [metabase.system.core :as system]
   [toucan2.core :as t2])
  (:import (java.io StringReader)))

(defn inputs
  "Deployment inputs. Both genuinely absent retain the existing deployment behavior."
  []
  {:mode (System/getenv "MB_MCP_ACCESS_MODE")
   :users (System/getenv "MB_MCP_ALLOWED_USER_IDS")})

(defn- parse-users [text]
  (when (and (string? text) (<= 1 (count text) 128))
    (with-open [reader (StringReader. text)]
      (let [values (vec (take 2 (json/parsed-seq reader true)))
            users (first values)]
        (when (and (= 1 (count values)) (vector? users) (= 2 (count users))
                   (every? #(and (integer? %) (<= 1 % Integer/MAX_VALUE)) users)
                   (= 2 (count (set users))))
          (set users))))))

(defn current
  "Return off, invalid or active. Malformed or competing modes never fall back."
  []
  (let [{:keys [mode users]} (inputs)]
    (if (and (nil? mode) (nil? users))
      {:mode :off}
      (try
        (let [ids (parse-users users)]
          (if (and (= mode "two-accounts") ids
                   (every? nil? (vals (pilot.config/inputs))))
            {:mode :active :user-ids ids}
            {:mode :invalid}))
        (catch Exception _ {:mode :invalid})))))

(defn configured? [c] (not= :off (:mode c)))

(defn- unavailable! []
  (throw (ex-info "Metabase MCP access configuration unavailable." {:status-code 503 :type ::unavailable})))

(defn- denied! []
  (throw (ex-info "Metabase MCP access unavailable." {:status-code 403 :type ::denied})))

(defn- canonical-user-id [id]
  (cond
    (and (integer? id) (<= 1 id Integer/MAX_VALUE)) id
    (and (string? id) (re-matches #"[1-9][0-9]{0,9}" id))
    (let [number (parse-long id)]
      (when (and number (<= number Integer/MAX_VALUE)) number))))

(defn- active-allowed-user? [c id]
  (when-let [id (canonical-user-id id)]
    (and (contains? (:user-ids c) id)
         (t2/exists? :model/User :id id :is_active true))))

(defn authorize!
  "Check current account admission and the native MCP resource, without filtering tools or scopes."
  [captured grant]
  (when-not (= :active (:mode captured)) (unavailable!))
  (when-not (= captured (current)) (unavailable!))
  (let [resource (str (system/site-url) "/api/metabase-mcp")
        resources (:resource grant)]
    (when-not (and (or (= resource resources) (= [resource] resources))
                   (active-allowed-user? captured (:user-id grant)))
      (denied!)))
  (when-not (= captured (current)) (unavailable!))
  true)

(defn validate-grant!
  "Guard native authorization, token issuance, refresh and resolution through existing provider hooks."
  [grant]
  (let [c (current)]
    (if (configured? c) (authorize! c grant) true)))

(defn ui-user-allowed?
  "Check native MCP App credentials too. No alternate account admission path."
  [id]
  (try
    (let [c (current)]
      (or (= :off (:mode c))
          (and (= :active (:mode c)) (active-allowed-user? c id) (= c (current)))))
    (catch Exception _ false)))
