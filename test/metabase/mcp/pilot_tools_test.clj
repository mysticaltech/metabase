(ns metabase.mcp.pilot-tools-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [metabase.mcp.pilot-auth :as auth]
   [metabase.mcp.pilot-config :as config]
   [metabase.mcp.pilot-policy :as policy]
   [metabase.mcp.pilot-policy-test :as fixtures]
   [metabase.mcp.pilot-snapshot :as snapshot]
   [metabase.mcp.pilot-tools :as pilot]
   [metabase.mcp.resources :as resources]
   [metabase.mcp.tools :as tools]
   [metabase.test :as mt]
   [metabase.util.json :as json]
   [metabase.util.log.capture :as log.capture]))

(set! *warn-on-reflection* true)

(defn- successful-native [] {:structuredContent fixtures/native-result})

(defn- diagnostic-call! [fault]
  (let [sentinel "NMCP-5-SENTINEL-token-user-client-report-SQL-rows-987654321"
        private-data {:token sentinel :user-id 987654321 :client-id sentinel :report-id 987654321
                      :url sentinel :query sentinel :metadata sentinel :rows [[sentinel]]}
        fail! #(throw (ex-info sentinel private-data (ex-info sentinel private-data)))
        report (cond-> fixtures/report
                 (= fault :final-envelope)
                 (assoc :max-bytes (policy/encoded-size
                                    (policy/safe-result! fixtures/report fixtures/native-result))))
        p (assoc fixtures/policy :reports [report])
        auth-checks (atom 0)
        pin-checks (atom 0)
        native (assoc fixtures/native-result :json_query private-data)
        args (cond-> {:id 17} (= fault :arguments) (assoc :private private-data))]
    (mt/with-dynamic-fn-redefs
      [auth/ensure-authorized!
       (fn []
         (let [check (swap! auth-checks inc)]
           (cond
             (or (= fault :pre-auth) (and (= fault :post-auth) (> check 1))) (fail!)
             (and (= fault :post-auth-change) (> check 1)) (assoc p :user-id 24)
             :else p)))
       snapshot/validate!
       (fn [_]
         (let [check (swap! pin-checks inc)]
           (cond
             (or (= fault :pre-pin) (and (= fault :post-pin-error) (> check 1))) (fail!)
             (and (= fault :post-pin) (> check 1)) {:root private-data :changed sentinel}
             :else {:root private-data})))]
      (log.capture/with-log-messages-for-level [messages [metabase.mcp.pilot-tools :trace]]
        (let [result (pilot/call-tool
                      #{policy/execute-scope} "execute_question" args
                      (fn []
                        (case fault
                          :native-invocation (fail!)
                          :native-invocation-error (throw (Error. sentinel))
                          :native-error {:isError true :content [{:type "text" :text sentinel}]
                                         :structuredContent private-data}
                          :safe-result {:structuredContent (assoc-in native [:data :rows 0 0] sentinel)}
                          {:structuredContent native})))]
          {:result result :logs (messages)})))))

(deftest failure-stage-diagnostics-are-finite-and-private-test
  (doseq [[fault stage] [[:pre-auth "pre-auth"] [:arguments "arguments"] [:pre-pin "pre-pin"]
                         [:native-invocation "native-invocation"]
                         [:native-invocation-error "native-invocation"] [:native-error "native-error"]
                         [:post-auth "post-auth"] [:post-auth-change "post-auth"]
                         [:post-pin "post-pin"] [:post-pin-error "post-pin"]
                         [:safe-result "safe-result"] [:final-envelope "final-envelope"]]]
    (testing (name fault)
      (let [{:keys [result logs]} (diagnostic-call! fault)]
        (is (= {:content [{:type "text" :text "Approved report unavailable."}] :isError true} result))
        ;; Exact entries exclude sentinels, exception objects/stacks and any input/result-derived fields.
        (is (= [{:namespace 'metabase.mcp.pilot-tools :level :warn :e nil
                 :message (str "MCP pilot failure stage=" stage)}]
               logs))))))

(deftest successful-tool-execution-has-no-diagnostic-log-test
  (let [{:keys [result logs]} (diagnostic-call! nil)]
    (is (= (policy/safe-result! fixtures/report fixtures/native-result) (:structuredContent result)))
    (is (nil? (:isError result)))
    (is (empty? logs))))

(deftest native-output-and-pre-post-checks-test
  (let [calls (atom 0)
        invoke #(do (swap! calls inc) (successful-native))]
    (with-redefs [auth/ensure-authorized! (constantly fixtures/policy)
                  snapshot/validate! (constantly {:root "invented-pinned-query"})]
      (let [result (pilot/call-tool #{policy/execute-scope} "execute_question" {:id 17} invoke)]
        (is (= 1 @calls))
        (is (nil? (:isError result)))
        (is (= (policy/safe-result! fixtures/report fixtures/native-result) (:structuredContent result))))
      (doseq [[tool args] [["execute_sql" {:id 17}] ["execute_question" {:id 17 :query nil}]
                           ["execute_question" {:id 18}]]]
        (is (true? (:isError (pilot/call-tool #{policy/execute-scope} tool args invoke)))))
      (is (= 1 @calls))
      (is (true? (:isError (pilot/call-tool #{"mb:full"} "execute_question" {:id 17} invoke)))))
    (testing "Concurrent policy, permission, token and dependency changes suppress the entire result"
      (doseq [change [:policy :snapshot :revocation]]
        (let [checks (atom 0)]
          (with-redefs [auth/ensure-authorized! (fn []
                                                  (if (and (= change :revocation) (> (swap! checks inc) 1))
                                                    (policy/unavailable!)
                                                    (if (and (= change :policy) (> (swap! checks inc) 1))
                                                      (assoc fixtures/policy :user-id 24) fixtures/policy)))
                        snapshot/validate! (fn [_] (if (= change :snapshot) (swap! checks inc) :same))]
            (let [result (pilot/call-tool #{policy/execute-scope} "execute_question" {:id 17} successful-native)]
              (is (= {:content [{:type "text" :text "Approved report unavailable."}] :isError true} result)))))))))

(deftest direct-tool-and-resource-bypasses-denied-test
  (with-redefs [config/current (constantly {:mode :invalid-policy :client-ids #{"invented-cli"}})]
    (is (= [] (tools/list-tools nil)))
    (doseq [name ["execute_question" "execute_sql" "query" "search" "visualize_query" "construct_query"]]
      (is (true? (:isError (tools/call-tool nil "invented-session" name {:id 17 :query "invented"})))))
    (is (= {:resources []} (resources/list-resources nil)))
    (is (empty? (resources/list-ui-tools)))
    (doseq [uri ["metabase://docs/construct-query.md" "ui://metabase/visualize-query.html"]]
      (is (= :scope-denied (resources/check-resource-access uri nil)))
      (is (= {:status :scope-denied} (resources/read-resource uri nil {}))))))

(deftest full-raw-buffer-bound-test
  (let [buffer (pilot/limited-buffer 3)]
    (.write ^java.io.OutputStream buffer (.getBytes "abc" java.nio.charset.StandardCharsets/UTF_8))
    (is (= 3 (.size ^java.io.ByteArrayOutputStream buffer)))
    (is (thrown? clojure.lang.ExceptionInfo (.write ^java.io.OutputStream buffer (int 100))))))

(deftest date-wire-tool-projection-is-canonical-and-complete-test
  (with-redefs [auth/ensure-authorized! (constantly fixtures/policy)
                snapshot/validate! (constantly {:root "invented-pinned-query"})]
    (doseq [wire ["2024-02-29T00:00:00+14:00" "2024-02-29T00:00:00.000-12:00"
                  "2024-02-29T00:00:00"]]
      (let [native (assoc-in fixtures/native-result [:data :rows 0 0] wire)
            result (pilot/call-tool #{policy/execute-scope} "execute_question" {:id 17}
                                    (constantly {:structuredContent native}))]
        (is (nil? (:isError result)))
        (is (= [["2024-02-29" 41 true]] (get-in result [:structuredContent :data :rows])))
        (is (= (:structuredContent result)
               (when (:structuredContent result) (json/decode+kw (get-in result [:content 0 :text])))))))
    (doseq [wire ["2024-02-29T00:00:01Z" "2023-02-29T00:00:00Z"]]
      (is (= {:content [{:type "text" :text "Approved report unavailable."}] :isError true}
             (pilot/call-tool #{policy/execute-scope} "execute_question" {:id 17}
                              (constantly {:structuredContent
                                           (assoc-in fixtures/native-result [:data :rows 0 0] wire)})))))))
