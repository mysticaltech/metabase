(ns metabase.mcp.pilot-snapshot-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [metabase.api.common :as api]
   [metabase.lib-be.metadata.jvm :as lib.metadata.jvm]
   [metabase.lib.core :as lib]
   [metabase.mcp.pilot-policy :as policy]
   [metabase.mcp.pilot-policy-test :as fixtures]
   [metabase.mcp.pilot-snapshot :as snapshot]
   [metabase.test :as mt]
   [metabase.util.json :as json]
   [metabase.util.log.capture :as log.capture]
   [toucan2.core :as t2]))

(def card
  {:id 17 :database_id 7 :collection_id 4 :archived false :parameters []
   :dataset_query {:database 7 :type :native :native {:query "SELECT 41 AS visits" :template-tags {}}}})

(defn- pinned [root dependencies]
  (assoc fixtures/report :sha256 (policy/fingerprint root)
         :dependencies (mapv (fn [[[kind id] node]] {:kind kind :id id :sha256 (policy/fingerprint node)})
                             dependencies)))

(deftest exact-graph-pins-test
  (with-redefs-fn {#'snapshot/fetch-node (constantly card)}
    (fn []
      (is (= {:root card :dependencies {}} (snapshot/validate! (pinned card {}))))
      (doseq [report [(assoc (pinned card {}) :collection-id 5)
                      (assoc (pinned card {}) :database-id 8)
                      (assoc (pinned card {}) :sha256 (apply str (repeat 64 "0")))]]
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"unavailable" (snapshot/validate! report)))))))

(deftest complete-transitive-dependencies-test
  (let [root (assoc-in card [:dataset_query :native]
                       {:query "SELECT * FROM {{#18}} WHERE {{snippet: condition}}"
                        :template-tags {"#18" {:name "#18" :display-name "Invented card" :type :card :card-id 18}
                                        "snippet: condition" {:name "snippet: condition" :display-name "Invented condition"
                                                              :type :snippet :snippet-id 19 :snippet-name "condition"}}})
        child (assoc card :id 18)
        snippet {:id 19 :content "true" :template_tags {}}
        nodes {["card" 17] root ["card" 18] child ["snippet" 19] snippet}
        report (pinned root (dissoc nodes ["card" 17]))]
    (with-redefs-fn {#'snapshot/fetch-node nodes}
      (fn []
        (is (= {:root root :dependencies (dissoc nodes ["card" 17])} (snapshot/validate! report)))
        (is (thrown? clojure.lang.ExceptionInfo (snapshot/validate! (assoc report :dependencies []))))))
    (testing "One-way concurrent changes to a referenced query or snippet invalidate its pin"
      (doseq [changed [(assoc-in nodes [["card" 18] :dataset_query :native :query] "SELECT 99")
                       (assoc-in nodes [["snippet" 19] :content] "false")]]
        (with-redefs-fn {#'snapshot/fetch-node changed}
          #(is (thrown? clojure.lang.ExceptionInfo (snapshot/validate! report))))))))

(deftest cyclic-and-parameterized-graphs-denied-test
  (doseq [root [(assoc card :parameters [{:id "invented-parameter"}])
                (assoc-in card [:dataset_query :native :template-tags]
                          {"#17" {:name "#17" :display-name "Invented cycle" :type :card :card-id 17}})
                (assoc-in card [:dataset_query :native :template-tags]
                          {"variable" {:name "variable" :display-name "Invented variable" :type :text}})]]
    (with-redefs-fn {#'snapshot/fetch-node (constantly root)}
      #(is (thrown? clojure.lang.ExceptionInfo (snapshot/capture! fixtures/report))))))

(def api-card
  (assoc card :type "question" :display "table" :result_metadata nil
         :dataset_query {:database 7 :lib/type "mbql/query"
                         :stages [{:lib/type "mbql.stage/native" :native "SELECT 41 AS visits"}]}))

(def api-collection {:id 4 :location "/" :namespace nil :archived false})

(deftest portable-pins-require-complete-metadata-test
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"unavailable" (policy/fingerprint (Object.))))
  (let [metadata {:cards {17 api-card} :collections {4 api-collection} :snippets {}}
        pins (snapshot/pins-from-api fixtures/report metadata)]
    (is (= #{:sha256 :dependencies} (set (keys pins))))
    (is (= [] (:dependencies pins)))
    (doseq [bad [(dissoc metadata :cards)
                 (dissoc metadata :collections)
                 (update-in metadata [:cards 17] dissoc :result_metadata)
                 (update-in metadata [:collections 4] dissoc :namespace)
                 (assoc-in metadata [:cards 17 :archived] true)
                 (assoc-in metadata [:cards 17 :database_id] 8)
                 (assoc-in metadata [:collections 4 :id] 5)]]
      (is (thrown? clojure.lang.ExceptionInfo (snapshot/pins-from-api fixtures/report bad))))
    (testing "Real definition changes remain in the pin after stripping runtime-only state"
      (doseq [changed [(assoc-in metadata [:cards 17 :dataset_query :stages 0 :native] "SELECT 99 AS visits")
                       (assoc-in metadata [:cards 17 :result_metadata] [{:name "visits" :base_type "type/Float"}])
                       (assoc-in metadata [:collections 4 :location] "/9/")]]
        (is (not= pins (snapshot/pins-from-api fixtures/report changed)))))))

(deftest fixed-definition-survives-fresh-provider-and-json-reconstruction-test
  (let [metadata {:cards {17 api-card} :collections {4 api-collection} :snippets {}}
        pins (snapshot/pins-from-api fixtures/report metadata)]
    (dotimes [_ 3]
      (let [query (assoc (:dataset_query api-card) :lib/metadata
                         (lib.metadata.jvm/application-database-metadata-provider 7))
            reconstructed (assoc-in metadata [:cards 17 :dataset_query] (-> query json/encode json/decode+kw))]
        (is (= pins (snapshot/pins-from-api fixtures/report reconstructed)))))
    ;; Fixed invented definition only; compare this digest across separate test JVMs without printing SQL or DTOs.
    #_{:clj-kondo/ignore [:discouraged-var]}
    (println "NMCP_FIXED_DEFINITION_SHA256" (:sha256 pins))))

(defn- diagnostic-node [id source-id]
  (assoc api-card :id id
         :result_metadata [{:name "visits" :base_type :type/Integer
                            :display_name "NMCP6-SENTINEL-metadata-987654321"}]
         :dataset_query {:database 7 :type :native
                         :native {:query (if source-id (str "SELECT * FROM {{#" source-id "}}")
                                             "SELECT 41 AS visits /* NMCP6-SENTINEL-SQL-987654321 */")
                                  :template-tags (if source-id
                                                   {(str "#" source-id) {:name (str "#" source-id)
                                                                         :display-name "NMCP6-SENTINEL-tag"
                                                                         :type :card :card-id source-id}}
                                                   {})}}))

(defn- snapshot-diagnostic! [fault]
  (let [sentinel "NMCP6-SENTINEL-token-user-client-report-SQL-hash-values-987654321"
        private-data {:token sentinel :user-id 987654321 :client-id sentinel :report-id 987654321
                      :query sentinel :metadata sentinel :hash sentinel :rows [[sentinel]]}
        failure (ex-info sentinel private-data (ex-info sentinel private-data))
        root (diagnostic-node 17 18)
        child (diagnostic-node 18 nil)
        metadata {:cards {17 root 18 child} :collections {4 api-collection} :snippets {}}
        report (merge fixtures/report (snapshot/pins-from-api fixtures/report metadata))
        report (case fault
                 :root-pin (assoc report :sha256 (apply str (repeat 64 "0")))
                 :dependency-set (assoc report :dependencies [])
                 :dependency-pin (assoc-in report [:dependencies 0 :sha256] (apply str (repeat 64 "0")))
                 :collection-binding (assoc report :collection-id 5)
                 report)
        normalize (mt/original-fn #'lib/normalize)
        references (mt/original-fn #'lib/all-template-tags)
        fingerprint (mt/original-fn #'policy/fingerprint)
        select! (fn [model id]
                  (if (vector? model)
                    (case fault
                      :collection-read (throw failure)
                      :collection-shape (dissoc api-collection :namespace)
                      api-collection)
                    (case fault
                      :entity (throw failure)
                      :entity-missing nil
                      :entity-archived (assoc root :archived true)
                      :required-shape (dissoc root :parameters)
                      :cycle (diagnostic-node 17 17)
                      :graph-limit (diagnostic-node id (inc id))
                      :database-binding (assoc root :database_id 8)
                      :parameters (assoc root :parameters [private-data])
                      (get (:cards metadata) id))))]
    (mt/with-dynamic-fn-redefs
      [t2/select-one select!
       api/read-check (fn [entity]
                        (case fault
                          :read-authority (throw failure)
                          :read-authority-error (throw (Error. sentinel))
                          entity))
       lib/normalize (fn [& args] (if (= fault :normalization) (throw failure) (apply normalize args)))
       lib/all-template-tags (fn [query] (if (= fault :references) (throw failure) (references query)))
       policy/fingerprint (fn [node]
                            (if (or (and (= fault :root-fingerprint) (= 17 (:id node)))
                                    (and (= fault :dependency-fingerprint) (= 18 (:id node))))
                              (throw failure)
                              (fingerprint node)))]
      (log.capture/with-log-messages-for-level [messages [metabase.mcp.pilot-snapshot :trace]]
        (let [outcome (try (snapshot/validate! report) (catch Throwable e e))]
          {:outcome outcome :logs (messages) :failure failure})))))

(deftest snapshot-failure-diagnostics-are-finite-and-private-test
  (doseq [[fault substage] [[:entity "entity"] [:entity-missing "entity"] [:entity-archived "entity"]
                            [:read-authority "read-authority"] [:read-authority-error "read-authority"]
                            [:required-shape "required-shape"]
                            [:collection-read "collection-read"] [:collection-shape "collection-shape"]
                            [:normalization "normalization"] [:references "references"] [:parameters "references"]
                            [:cycle "cycle"] [:graph-limit "graph-limit"]
                            [:database-binding "database-binding"] [:collection-binding "collection-binding"]
                            [:root-fingerprint "root-fingerprint"] [:root-pin "root-pin"]
                            [:dependency-set "dependency-set"]
                            [:dependency-fingerprint "dependency-fingerprint"] [:dependency-pin "dependency-pin"]]]
    (testing (name fault)
      (let [{:keys [outcome logs failure]} (snapshot-diagnostic! fault)]
        (is (instance? Throwable outcome))
        (when (contains? #{:entity :read-authority :collection-read :normalization :references
                           :root-fingerprint :dependency-fingerprint} fault)
          (is (identical? failure outcome)))
        ;; Exact equality excludes raw errors, stacks, sentinels, hashes and arbitrary extra fields.
        (is (= [{:namespace 'metabase.mcp.pilot-snapshot :level :warn :e nil
                 :message (str "MCP pilot snapshot failure substage=" substage)}]
               logs))))))

(deftest successful-snapshot-has-no-diagnostic-log-test
  (let [{:keys [outcome logs]} (snapshot-diagnostic! nil)]
    (is (= #{:root :dependencies} (set (keys outcome))))
    (is (= #{["card" 18]} (set (keys (:dependencies outcome)))))
    (is (empty? logs))))
