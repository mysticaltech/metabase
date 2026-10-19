(ns metabase.mcp.pilot-config
  "Read the independent deployment registry and atomic report policy without a last-good fallback."
  (:require
   ;; parsed-seq is required to reject trailing JSON values; util.json/decode only decodes the first.
   ^{:clj-kondo/ignore [:discouraged-namespace]} [cheshire.core :as json]
   [metabase.mcp.pilot-policy :as policy])
  (:import
   (java.io StringReader)
   (java.nio.charset StandardCharsets)
   (java.nio.file Files LinkOption OpenOption Path)))

(set! *warn-on-reflection* true)

(defn inputs
  "Return deployment input strings; nil alone means absent."
  []
  {:registry (System/getenv "MB_MCP_PILOT_CLIENT_IDS")
   :path (System/getenv "MB_MCP_PILOT_POLICY_PATH")})

(defn- parse-one [text]
  (when (and (string? text) (<= 1 (count text) 65536))
    (with-open [reader (StringReader. text)]
      (let [values (vec (take 2 (json/parsed-seq reader true)))]
        (when (= 1 (count values))
          (first values))))))

(defn- parse-registry [text]
  (let [ids (parse-one text)]
    (when (and (vector? ids) (<= 1 (count ids) 4)
               (= (count ids) (count (distinct ids)))
               (every? #(and (string? %) (re-matches #"[A-Za-z0-9._-]{1,128}" %)) ids))
      (set ids))))

(defn- read-policy [path]
  (when (and (string? path) (<= 1 (count path) 4096))
    (let [file (Path/of path (make-array String 0))]
      (when (and (.isAbsolute file) (Files/isRegularFile file (make-array LinkOption 0))
                 (<= (Files/size file) 65536))
        (with-open [stream (Files/newInputStream file (make-array OpenOption 0))]
          (let [bytes (.readNBytes stream 65537)]
            (when (<= (alength bytes) 65536)
              (parse-one (String. bytes StandardCharsets/UTF_8)))))))))

(defn current
  "Return :off, :invalid-registry, :invalid-policy, or :active and the safe classification data.
   Both inputs must be genuinely absent for :off. No error details or file contents escape."
  []
  (let [{:keys [registry path]} (inputs)]
    (if (and (nil? registry) (nil? path))
      {:mode :off}
      (let [ids (try (parse-registry registry) (catch Exception _ nil))]
        (if-not ids
          {:mode :invalid-registry}
          (let [p (try (read-policy path) (catch Exception _ nil))]
            (if (and (policy/valid-policy? p) (= ids (set (map :id (:clients p)))))
              {:mode :active :client-ids ids :policy p}
              {:mode :invalid-policy :client-ids ids})))))))

(defn configured?
  "Whether either deployment input was supplied, including invalid input."
  [config]
  (not= :off (:mode config)))

(defn client-mode
  "Classify a client without losing the pilot boundary when the report policy is unavailable."
  [config client-id]
  (cond
    (= :off (:mode config)) :baseline
    (= :invalid-registry (:mode config)) :unavailable
    (not (contains? (:client-ids config) client-id)) :baseline
    (= :active (:mode config)) :pilot
    :else :unavailable))

(defn unavailable!
  "Signal a finite configuration failure without disclosing policy or identities."
  []
  (throw (ex-info "MCP pilot configuration unavailable." {:status-code 503 :type ::unavailable})))
