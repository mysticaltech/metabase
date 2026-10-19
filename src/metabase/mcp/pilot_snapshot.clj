(ns metabase.mcp.pilot-snapshot
  "Capture and pin the saved-question dependency graph under the caller's existing permissions."
  (:require
   [metabase.api.common :as api]
   [metabase.lib.core :as lib]
   [metabase.mcp.pilot-policy :as policy]
   [metabase.util.log :as log]
   [toucan2.core :as t2]))

(def ^:private card-keys
  [:id :dataset_query :collection_id :database_id :type :display :parameters :result_metadata :archived])

(def ^:private snippet-keys [:id :name :content :template_tags :collection_id :archived])

(def ^:private collection-keys [:id :location :namespace :archived])

(defn- at-substage! [substage f]
  (try
    (f)
    (catch Throwable e
      (log/warnf "MCP pilot snapshot failure substage=%s" (name substage))
      (throw e))))

(defn- unavailable-at! [substage]
  (at-substage! substage policy/unavailable!))

(defn- complete? [entity fields]
  (and (map? entity) (every? #(contains? entity %) fields)))

(defn- collection-binding [collection-id collection]
  (when collection-id
    (when-not (and (complete? collection collection-keys)
                   (= collection-id (:id collection)) (false? (:archived collection)))
      (unavailable-at! :collection-shape))
    (-> (select-keys collection collection-keys)
        (update :namespace #(some-> % keyword)))))

(defn- definition [[kind id] entity collection]
  (let [fields (case kind "card" card-keys "snippet" snippet-keys)]
    (when-not (and (complete? entity fields) (= id (:id entity)) (false? (:archived entity)))
      (unavailable-at! :required-shape))
    (let [binding (collection-binding (:collection_id entity) collection)]
      (at-substage!
       :normalization
       (fn []
         (cond-> (assoc (select-keys entity fields) :collection-binding binding)
           (= kind "card")
           (-> (update :dataset_query #(->> (lib/->mbql5 %)
                                            (lib/normalize :metabase.lib.schema/query)
                                            lib/prepare-for-serialization))
               (update :type #(some-> % keyword))
               (update :display #(some-> % keyword))
               (update :result_metadata #(not-empty (mapv lib/normalize-result-metadata-column %))))
           (= kind "snippet")
           (update :template_tags #(lib/normalize :metabase.lib.schema.template-tag/template-tag-map %))))))))

(defn- fetch-node [[kind id :as key]]
  (let [model (case kind "card" :model/Card "snippet" :model/NativeQuerySnippet)
        entity (at-substage! :entity #(t2/select-one model id))]
    (when (or (nil? entity) (:archived entity))
      (unavailable-at! :entity))
    (at-substage! :read-authority #(api/read-check entity))
    ;; Hash the same definition native persistence writes, never request-local metadata providers or caches.
    (definition key entity (when-let [collection-id (:collection_id entity)]
                             (at-substage! :collection-read
                                           #(t2/select-one (into [:model/Collection] collection-keys) collection-id))))))

(defn- references [[kind _id] node]
  (at-substage!
   :references
   (fn []
     (let [query (when (= kind "card")
                   (lib/normalize :metabase.lib.schema/query (lib/->mbql5 (:dataset_query node))))
           tags (if query
                  (vec (lib/all-template-tags query))
                  (lib/normalize :metabase.lib.schema.template-tag/template-tags (:template_tags node)))
           cards (if query (lib/all-source-card-ids query) (lib/template-tags->card-ids tags))
           snippets (lib/template-tags->snippet-ids tags)]
       (when (or (seq (:parameters node))
                 (some (fn [{:keys [type card-id snippet-id]}]
                         (case type
                           :card (not (pos-int? card-id))
                           :snippet (not (pos-int? snippet-id))
                           true))
                       tags))
         (policy/unavailable!))
       (set (concat (map #(vector "card" %) cards) (map #(vector "snippet" %) snippets)))))))

(defn- capture-with! [report fetch]
  (let [root ["card" (:id report)]
        nodes (atom {})]
    (letfn [(visit! [key ancestors]
              (when (contains? ancestors key)
                (unavailable-at! :cycle))
              (when-not (contains? @nodes key)
                (when (>= (count @nodes) 65)
                  (unavailable-at! :graph-limit))
                (let [node (fetch key)]
                  (when (and (= "card" (first key))
                             (or (not= (:database-id report) (:database_id node))
                                 (not= (:database-id report) (get-in node [:dataset_query :database]))))
                    (unavailable-at! :database-binding))
                  (swap! nodes assoc key node)
                  (doseq [dependency (references key node)]
                    (visit! dependency (conj ancestors key))))))]
      (visit! root #{})
      (when-not (= (:collection-id report) (get-in @nodes [root :collection_id]))
        (unavailable-at! :collection-binding))
      {:root (get @nodes root)
       :dependencies (dissoc @nodes root)})))

(defn capture!
  "Read the current root and transitive cards/snippets under current permissions, refusing incomplete graphs.
   Captured definitions remain in process; only their fingerprints belong in a reviewed policy."
  [report]
  (capture-with! report fetch-node))

(defn- snapshot-pins [{:keys [root dependencies]}]
  {:sha256 (policy/fingerprint root)
   :dependencies (mapv (fn [[[kind id] node]] {:kind kind :id id :sha256 (policy/fingerprint node)})
                       (sort-by key dependencies))})

(defn pins!
  "Return only root/dependency hashes and dependency IDs for an already reviewed report under current permissions."
  [report]
  (try
    (snapshot-pins (capture! report))
    (catch Exception _ (policy/unavailable!))))

(defn pins-from-api
  "Return only pins from complete, authenticated native API metadata kept in memory.
   `cards`, `snippets`, and `collections` are maps of integer ID to decoded JSON response body.
   Missing entities, required fields, bindings, or transitive dependencies are unavailable."
  [report {:keys [cards snippets collections]}]
  (try
    (snapshot-pins
     (capture-with! report (fn [[kind id :as key]]
                             (let [entity (get (case kind "card" cards "snippet" snippets) id)]
                               (definition key entity (get collections (:collection_id entity)))))))
    (catch Exception _ (policy/unavailable!))))

(defn validate!
  "Return the captured graph only when every configured query/dependency pin still matches."
  [report]
  (let [{:keys [root dependencies] :as snapshot} (capture! report)
        pins (into {} (map (fn [{:keys [kind id sha256]}] [[kind id] sha256])) (:dependencies report))]
    (when-not (= (:sha256 report) (at-substage! :root-fingerprint #(policy/fingerprint root)))
      (unavailable-at! :root-pin))
    (when-not (= (set (keys dependencies)) (set (keys pins)))
      (unavailable-at! :dependency-set))
    (when-not (every? (fn [[key node]]
                        (= (get pins key) (at-substage! :dependency-fingerprint #(policy/fingerprint node))))
                      dependencies)
      (unavailable-at! :dependency-pin))
    snapshot))
