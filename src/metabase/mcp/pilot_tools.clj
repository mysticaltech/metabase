(ns metabase.mcp.pilot-tools
  "Constrain the existing native execute_question tool and validate its fully buffered result."
  (:require
   [clojure.string :as str]
   [metabase.mcp.pilot-auth :as auth]
   [metabase.mcp.pilot-policy :as policy]
   [metabase.mcp.pilot-snapshot :as snapshot]
   [metabase.util.json :as json])
  (:import
   (java.io ByteArrayOutputStream)))

(set! *warn-on-reflection* true)

(def raw-response-limit "Hard bound on the native response before metadata projection." (* 8 1024 1024))

(defn limited-buffer
  "A buffer that refuses to retain more than `limit` bytes from a native response."
  [limit]
  (proxy [ByteArrayOutputStream] []
    (write
      ([value]
       (when (>= (.size ^ByteArrayOutputStream this) limit) (policy/unavailable!))
       (proxy-super write value))
      ([bytes offset length]
       (when (> (+ (.size ^ByteArrayOutputStream this) length) limit) (policy/unavailable!))
       (proxy-super write bytes offset length)))))

(defn- authorized-policy! [token-scopes]
  (when-not (= token-scopes #{policy/execute-scope})
    (policy/unavailable!))
  (auth/ensure-authorized!))

(defn list-tools
  "Project the native manifest to its approved saved-question tool. Denial exposes no catalog."
  [token-scopes native-tools]
  (try
    (let [p (authorized-policy! token-scopes)
          tool (some #(when (= "execute_question" (:name %)) %) (native-tools))]
      (if (and tool (= p (authorized-policy! token-scopes)))
        [(-> tool
             (dissoc :_meta :outputSchema)
             (assoc :description (str "Run one approved aggregate saved question. Approved reports: "
                                      (str/join "; " (map #(str (:id %) " " (:title %)) (:reports p))) ".")
                    :inputSchema {:type "object" :additionalProperties false :required ["id"]
                                  :properties {:id {:type "integer" :enum (mapv :id (:reports p))}}}))]
        []))
    (catch Exception _ [])))

(defn call-tool
  "Call native execution only after every policy/pin check; release no result until postchecks pass."
  [token-scopes tool arguments invoke-native]
  (try
    (let [p (authorized-policy! token-scopes)
          report (policy/validate-arguments! p tool arguments)
          before (snapshot/validate! report)
          result (invoke-native)]
      (when (:isError result) (policy/unavailable!))
      (when-not (and (= p (authorized-policy! token-scopes))
                     (= before (snapshot/validate! report)))
        (policy/unavailable!))
      (let [safe (policy/safe-result! report (:structuredContent result))
            response {:content [{:type "text" :text (json/encode safe)}] :structuredContent safe}]
        (when (> (policy/encoded-size response) (:max-bytes report)) (policy/unavailable!))
        response))
    (catch Throwable _
      {:content [{:type "text" :text "Approved report unavailable."}] :isError true})))
