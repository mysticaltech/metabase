(ns metabase.mcp.pilot-policy
  "Pure validation for the bounded native MCP report pilot."
  (:require
   [clojure.string :as str]
   [metabase.util.json :as json])
  (:import
   (java.net URI)
   (java.nio.charset StandardCharsets)
   (java.security MessageDigest)
   (java.time LocalDate OffsetDateTime ZoneOffset)))

(set! *warn-on-reflection* true)

(def execute-scope "The unchanged native execute_question scope." "agent:question:execute")

(defn unavailable!
  "Throw a safe error without policy, query, identity, or result details."
  []
  (throw (ex-info "Approved report unavailable." {:type ::unavailable})))

(defn- exact-keys? [m ks]
  (and (map? m) (= (set (keys m)) (set ks))))

(defn- bounded-vector? [v n]
  (and (vector? v) (<= 1 (count v) n) (= (count v) (count (distinct v)))))

(defn mcp-path?
  "Whether a path is one of the exact native MCP endpoints."
  [path]
  (contains? #{"/api/metabase-mcp" "/api/metabase-mcp/" "/api/mcp" "/api/mcp/"} path))

(defn- url? [s resource?]
  (boolean
   (and (string? s) (<= 1 (count s) 2048) (not (re-find #"[\s*\\%]" s))
        (try
          (let [uri (URI. ^String s)
                scheme (.getScheme uri)
                host (.getHost uri)]
            (and host (nil? (.getRawUserInfo uri)) (nil? (.getRawQuery uri))
                 (nil? (.getRawFragment uri))
                 (or (= scheme "https")
                     (and (not resource?) (= scheme "http")
                          (= host "127.0.0.1") (pos? (.getPort uri))))
                 (if resource? (mcp-path? (.getRawPath uri)) (seq (.getRawPath uri)))))
          (catch Exception _ false)))))

(defn- identifier? [s]
  (and (string? s) (boolean (re-matches #"[A-Za-z0-9._-]{1,128}" s))))

(defn- digest? [s]
  (and (string? s) (boolean (re-matches #"[0-9a-f]{64}" s))))

(defn- column? [{:keys [name base-type kind] :as column}]
  (and (exact-keys? column [:name :base-type :kind])
       (string? name) (boolean (re-matches #"[A-Za-z][A-Za-z0-9_ ]{0,95}" name))
       (contains? (get {"integer" #{"type/Integer" "type/BigInteger"}
                        "number" #{"type/Float" "type/Decimal" "type/Number"}
                        "boolean" #{"type/Boolean"}
                        "date" #{"type/Date"}
                        "datetime" #{"type/DateTime" "type/DateTimeWithTZ" "type/DateTimeWithLocalTZ"}}
                       kind #{})
                  base-type)))

(defn- client-policy? [{:keys [id redirect-uris] :as client}]
  (and (exact-keys? client [:id :redirect-uris]) (identifier? id)
       (bounded-vector? redirect-uris 4) (every? #(url? % false) redirect-uris)))

(defn- dependency? [{:keys [kind id sha256] :as dependency}]
  (and (exact-keys? dependency [:kind :id :sha256])
       (contains? #{"card" "snippet"} kind) (pos-int? id) (digest? sha256)))

(defn- report? [{:keys [id title collection-id database-id sha256 dependencies columns max-rows max-bytes]
                 :as report}]
  (and (exact-keys? report [:id :title :collection-id :database-id :sha256 :dependencies
                            :columns :max-rows :max-bytes])
       (pos-int? id) (pos-int? collection-id) (pos-int? database-id) (digest? sha256)
       (string? title) (boolean (re-matches #"[A-Za-z0-9 _(),.-]{1,96}" title))
       (vector? dependencies) (<= (count dependencies) 64) (every? dependency? dependencies)
       (= (count dependencies) (count (distinct (map (juxt :kind :id) dependencies))))
       (not-any? #(= ["card" id] [(:kind %) (:id %)]) dependencies)
       (bounded-vector? columns 32) (every? column? columns)
       (= (count columns) (count (distinct (map :name columns))))
       (pos-int? max-rows) (<= max-rows 1000)
       (pos-int? max-bytes) (<= max-bytes (* 4 1024 1024))))

(defn valid-policy?
  "Whether a parsed policy has the supported exact shape."
  [{:keys [version user-id resource clients reports] :as policy}]
  (boolean
   (and (exact-keys? policy [:version :user-id :resource :clients :reports])
        (= version 1) (pos-int? user-id) (url? resource true)
        (bounded-vector? clients 4) (every? client-policy? clients)
        (= (count clients) (count (distinct (map :id clients))))
        (bounded-vector? reports 20) (every? report? reports)
        (= (count reports) (count (distinct (map :id reports)))))))

(defn client-valid?
  "Whether the current registered client still has its exact reviewed public-client configuration."
  [policy {:keys [client-id client-type application-type token-endpoint-auth-method
                  redirect-uris response-types grant-types scopes] :as client}]
  (boolean
   (when-let [approved (some #(when (= (:id %) client-id) %) (:clients policy))]
     (and client (= client-type "public")
          (= application-type "native") (= token-endpoint-auth-method "none")
          (= (vec redirect-uris) (:redirect-uris approved))
          (= (vec response-types) ["code"])
          (= (set grant-types) #{"authorization_code" "refresh_token"})
          (= (count grant-types) 2) (= (vec scopes) [execute-scope])))))

(defn grant-valid?
  "Whether a stored grant and current client satisfy the pilot policy."
  [policy {:keys [user-id client-id scope resource]} client active-user?]
  (boolean
   (and (valid-policy? policy) active-user? (= (str (:user-id policy)) (str user-id))
        (= client-id (:client-id client)) (client-valid? policy client)
        (= (vec scope) [execute-scope]) (= (vec resource) [(:resource policy)]))))

(defn validate-arguments!
  "Return the approved report for the exact execute_question argument shape."
  [policy tool arguments]
  (or (when (and (valid-policy? policy) (= tool "execute_question")
                 (exact-keys? arguments [:id]) (pos-int? (:id arguments)))
        (some #(when (= (:id %) (:id arguments)) %) (:reports policy)))
      (unavailable!)))

(defn- canonical-date [value]
  (when (and (string? value) (<= (count value) 35))
    (try
      (if-let [[_ day offset] (re-matches #"([0-9]{4}-[0-9]{2}-[0-9]{2})T00:00:00(?:\.0{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})?" value)]
        (let [date (LocalDate/parse day)]
          ;; DATE values name a reporting day; validate the offset without applying it.
          (when offset (ZoneOffset/of offset))
          (when (= day (str date)) day))
        (when (= value (str (LocalDate/parse value))) value))
      (catch Exception _ nil))))

(defn- value-valid? [kind value]
  (case kind
    "integer" (and (integer? value) (Double/isFinite (double value)))
    "number" (and (number? value) (Double/isFinite (double value)))
    "boolean" (boolean? value)
    "date" (some? (canonical-date value))
    "datetime" (and (string? value) (<= (count value) 40)
                    (try (some? (OffsetDateTime/parse value)) (catch Exception _ false)))
    false))

(defn encoded-size
  "UTF-8 bytes in a JSON value, including its metadata and text representation."
  [value]
  (alength (.getBytes ^String (json/encode value) StandardCharsets/UTF_8)))

(defn safe-result!
  "Validate the complete native result and return only the approved output."
  [{:keys [columns max-rows max-bytes] :as report} result]
  (let [cols (get-in result [:data :cols])
        rows (get-in result [:data :rows])
        safe-cols (mapv (fn [{:keys [name base-type]}] {:name name :base_type base-type}) columns)]
    (when-not (and (report? report) (contains? #{:completed "completed"} (:status result))
                   (nil? (:continuation_token result))
                   (nil? (get-in result [:data :rows_truncated]))
                   (nil? (get-in result [:data :pivot_rows_truncated]))
                   (sequential? cols) (= (count cols) (count columns))
                   (= safe-cols (mapv #(select-keys % [:name :base_type]) cols))
                   (sequential? rows) (<= (count rows) max-rows)
                   (integer? (:row_count result)) (= (:row_count result) (count rows))
                   (every? (fn [row]
                             (and (sequential? row) (= (count row) (count columns))
                                  (every? true? (map #(boolean (value-valid? (:kind %1) %2)) columns row))))
                           rows))
      (unavailable!))
    (let [safe-rows (mapv (fn [row]
                            (mapv (fn [{:keys [kind base-type]} value]
                                    (if (and (= kind "date") (= base-type "type/Date"))
                                      (canonical-date value)
                                      value))
                                  columns row))
                          rows)
          safe {:status "completed" :data {:cols safe-cols :rows safe-rows} :row_count (count rows)}]
      (when (> (encoded-size safe) max-bytes)
        (unavailable!))
      safe)))

(defn fingerprint
  "SHA-256 of a deterministic EDN representation of an in-process query snapshot."
  [snapshot]
  (letfn [(canonical [x]
            (cond
              (map? x) (into (sorted-map-by #(compare (pr-str %1) (pr-str %2)))
                             (map (fn [[k v]] [k (canonical v)])) x)
              (set? x) (sort-by pr-str (map canonical x))
              (sequential? x) (mapv canonical x)
              (or (nil? x) (boolean? x) (string? x) (keyword? x) (number? x)) x
              :else (unavailable!)))]
    (let [bytes (.digest (MessageDigest/getInstance "SHA-256")
                         (.getBytes (pr-str (canonical snapshot)) StandardCharsets/UTF_8))]
      (str/join (map #(format "%02x" (bit-and 0xff %)) bytes)))))
