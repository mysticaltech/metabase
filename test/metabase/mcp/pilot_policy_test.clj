(ns metabase.mcp.pilot-policy-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [metabase.mcp.pilot-policy :as pilot]))

(def report
  {:id 17
   :title "Invented website totals"
   :collection-id 4
   :database-id 7
   :sha256 (apply str (repeat 64 "a"))
   :dependencies []
   :columns [{:name "day" :base-type "type/Date" :kind "date"}
             {:name "visits" :base-type "type/Integer" :kind "integer"}
             {:name "complete" :base-type "type/Boolean" :kind "boolean"}]
   :max-rows 3
   :max-bytes 2000})

(def policy
  {:version 1
   :user-id 23
   :resource "https://analytics.example.invalid/api/metabase-mcp"
   :clients [{:id "invented-cli" :redirect-uris ["http://127.0.0.1:38171/callback"]}]
   :reports [report]})

(def client
  {:client-id "invented-cli"
   :client-type "public"
   :registration-type "static"
   :application-type "native"
   :token-endpoint-auth-method "none"
   :redirect-uris ["http://127.0.0.1:38171/callback"]
   :response-types ["code"]
   :grant-types ["authorization_code" "refresh_token"]
   :scopes ["agent:question:execute"]})

(def grant
  {:user-id "23" :client-id "invented-cli"
   :scope ["agent:question:execute"] :resource [(:resource policy)]})

(def native-result
  {:status "completed"
   :data {:cols [{:name "day" :base_type "type/Date" :display_name "Do not trust this label"}
                 {:name "visits" :base_type "type/Integer"}
                 {:name "complete" :base_type "type/Boolean"}]
          :rows [["2026-10-18" 41 true]]}
   :row_count 1 :running_time 9
   :json_query {:database 7 :private "must never be released"}})

(deftest policy-shape-test
  (is (true? (pilot/valid-policy? policy)))
  (doseq [bad [nil {} (assoc policy :version 2) (assoc policy :clients [])
               (assoc policy :reports []) (assoc policy :user-id 0)
               (assoc policy :extra true) (assoc policy :resource "https://example.invalid/api/mcp/subpath")
               (assoc-in policy [:clients 0 :redirect-uris] ["https://*.example.invalid/callback"])
               (assoc-in policy [:reports 0 :columns 0 :kind] "text")
               (assoc-in policy [:reports 0 :max-rows] 0)
               (assoc-in policy [:reports 0 :sha256] "unpinned")]]
    (is (false? (pilot/valid-policy? bad)))))

(deftest exact-path-test
  (doseq [path ["/api/metabase-mcp" "/api/metabase-mcp/" "/api/mcp" "/api/mcp/"]]
    (is (true? (pilot/mcp-path? path))))
  (doseq [path [nil "/api/mcp//" "/api/mcp/query" "/api/mcp/../agent"
                "/api/%6dcp" "/api/mcp%2f" "/api/metabase-mcp;anything"
                "/api/agent/v1/question/17/query" "/api/mcp?x=1"]]
    (is (false? (pilot/mcp-path? path)))))

(deftest grant-and-current-client-ceiling-test
  (is (true? (pilot/grant-valid? policy grant client true)))
  (is (true? (pilot/grant-valid? policy grant (assoc client :registration-type "dynamic") true)))
  (doseq [scopes [[] ["mb:full"] ["agent:*"] ["agent:question:execute" "mb:full"]]]
    (is (false? (pilot/grant-valid? policy (assoc grant :scope scopes) client true)))
    (is (false? (pilot/grant-valid? policy grant (assoc client :scopes scopes) true))))
  (doseq [bad [(assoc grant :user-id "24") (assoc grant :client-id "unknown")
               (dissoc grant :resource) (assoc grant :resource ["https://other.example.invalid/api/mcp"])
               (assoc grant :resource [(:resource policy) "https://extra.example.invalid"])]]
    (is (false? (pilot/grant-valid? policy bad client true))))
  (doseq [bad [nil (assoc client :client-type "confidential")
               (assoc client :redirect-uris ["http://127.0.0.1:38172/callback"])
               (assoc client :grant-types ["authorization_code" "client_credentials"])
               (assoc client :response-types ["token"])]]
    (is (false? (pilot/grant-valid? policy grant bad true))))
  (is (false? (pilot/grant-valid? policy grant client false))))

(deftest exact-tool-arguments-test
  (is (= report (pilot/validate-arguments! policy "execute_question" {:id 17})))
  (doseq [[tool args] [["execute_sql" {:id 17}] ["execute_question" {:id 18}]
                       ["execute_question" {:id "17"}] ["execute_question" {:id 17 :query nil}]
                       ["execute_question" {:id 17 :filters []}] ["execute_question" {:id 17 :url "x"}]
                       ["execute_question" nil] ["execute_question" [{:id 17}]]]]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"unavailable"
                          (pilot/validate-arguments! policy tool args)))))

(deftest complete-native-output-contract-test
  (is (= {:status "completed"
          :data {:cols [{:name "day" :base_type "type/Date"}
                        {:name "visits" :base_type "type/Integer"}
                        {:name "complete" :base_type "type/Boolean"}]
                 :rows [["2026-10-18" 41 true]]}
          :row_count 1}
         (pilot/safe-result! report native-result)))
  (testing "Metadata is projected only after validating every column and cell"
    (doseq [bad [(dissoc native-result :data)
                 (assoc native-result :status "failed" :error "invented private failure")
                 (assoc native-result :row_count 2)
                 (assoc-in native-result [:data :rows_truncated] 1)
                 (assoc-in native-result [:data :pivot_rows_truncated] 1)
                 (assoc-in native-result [:data :cols 1 :name] "email")
                 (assoc-in native-result [:data :cols 1 :base_type] "type/Text")
                 (update-in native-result [:data :cols] conj {:name "private" :base_type "type/Text"})
                 (assoc-in native-result [:data :rows 0 0] "2026-02-30")
                 (assoc-in native-result [:data :rows 0 1] nil)
                 (assoc-in native-result [:data :rows 0 1] "41")
                 (assoc-in native-result [:data :rows 0 1] Double/POSITIVE_INFINITY)
                 (assoc-in native-result [:data :rows 0 2] "true")
                 (assoc-in native-result [:data :rows 0 1] {:email "invented@example.invalid"})
                 (assoc-in native-result [:data :rows] (vec (repeat 4 ["2026-10-18" 41 true])))
                 (assoc native-result :continuation_token "must not escape")]]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"unavailable"
                            (pilot/safe-result! report bad)))))
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"unavailable"
                        (pilot/safe-result! (assoc report :max-bytes 10) native-result))))
