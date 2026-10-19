(ns metabase.mcp.pilot-snapshot-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [metabase.lib-be.metadata.jvm :as lib.metadata.jvm]
   [metabase.mcp.pilot-policy :as policy]
   [metabase.mcp.pilot-policy-test :as fixtures]
   [metabase.mcp.pilot-snapshot :as snapshot]
   [metabase.util.json :as json]))

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
