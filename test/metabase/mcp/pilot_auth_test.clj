(ns metabase.mcp.pilot-auth-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [metabase.api.common :as api]
   [metabase.mcp.pilot-auth :as auth]
   [metabase.mcp.pilot-config :as config]
   [metabase.mcp.pilot-policy-test :as fixtures]
   [metabase.oauth-server.core :as oauth]
   [metabase.server.middleware.session :as session]))

(def active-config {:mode :active :client-ids #{"invented-cli"} :policy fixtures/policy})

(deftest native-grant-current-ceiling-test
  (with-redefs-fn {#'config/current (constantly active-config)
                   #'auth/current-client (constantly fixtures/client)
                   #'auth/active-user? (constantly true)}
    (fn []
      (is (true? (auth/validate-grant! fixtures/grant)))
      (doseq [grant [(assoc fixtures/grant :scope ["mb:full"])
                     (assoc fixtures/grant :scope [])
                     (dissoc fixtures/grant :resource)
                     (assoc fixtures/grant :user-id "24")]]
        (is (thrown? clojure.lang.ExceptionInfo (auth/validate-grant! grant))))
      (with-redefs-fn {#'auth/current-client (constantly (assoc fixtures/client :scopes []))}
        #(is (thrown? clojure.lang.ExceptionInfo (auth/validate-grant! fixtures/grant))))
      (with-redefs-fn {#'auth/active-user? (constantly false)}
        #(is (thrown? clojure.lang.ExceptionInfo (auth/validate-grant! fixtures/grant))))
      (is (true? (auth/validate-grant! {:client-id "not-a-pilot"}))))))

(deftest captured-authority-drift-test
  (let [grant (assoc fixtures/grant :user-id 23)]
    (binding [api/*current-user-id* 23
              auth/*authorization* {:config active-config :resolve-grant (constantly grant)}]
      (with-redefs-fn {#'config/current (constantly active-config)
                       #'auth/current-client (constantly fixtures/client)
                       #'auth/active-user? (constantly true)}
        #(is (= fixtures/policy (auth/ensure-authorized!))))
      (with-redefs [config/current (constantly {:mode :off})]
        (is (thrown? clojure.lang.ExceptionInfo (auth/ensure-authorized!)))
        (is (true? (auth/restricted-request?)))))
    (binding [api/*current-user-id* 24
              auth/*authorization* {:config active-config :resolve-grant (constantly grant)}]
      (is (thrown? clojure.lang.ExceptionInfo (auth/ensure-authorized!))))
    (binding [api/*current-user-id* 23
              auth/*authorization* {:config active-config :resolve-grant (constantly nil)}]
      (is (thrown? clojure.lang.ExceptionInfo (auth/ensure-authorized!))))))

(deftest bearer-route-and-degraded-mode-test
  (doseq [path ["/api/agent/v1/question/17/query" "/api/card/17/query" "/api/user/current"
                "/api/mcp/subpath" "/api/mcp//" "/api/%6dcp" "/api/mcp/../agent"]]
    (is (= 403 (:status (auth/bearer-request-error active-config "invented-cli" path false)))))
  (doseq [path ["/api/metabase-mcp" "/api/metabase-mcp/" "/api/mcp" "/api/mcp/"]]
    (is (nil? (auth/bearer-request-error active-config "invented-cli" path false)))
    (is (= 403 (:status (auth/bearer-request-error active-config "invented-cli" path true)))))
  (is (nil? (auth/bearer-request-error active-config "other-client" "/api/user/current" true)))
  (is (= 401 (:status (auth/bearer-request-error active-config nil "/api/mcp" true))))
  (let [c {:mode :invalid-policy :client-ids #{"invented-cli"}}]
    (is (= 503 (:status (auth/bearer-request-error c "invented-cli" "/api/mcp" false))))
    (is (nil? (auth/bearer-request-error c "other-client" "/api/user/current" false)))))

(deftest deny-before-session-or-api-key-fallback-test
  (let [merge-called? (atom false)
        wrapped (session/wrap-current-user-info (fn [_ respond _] (respond {:status 200})))
        invoke (fn [request]
                 (let [result (promise)]
                   (wrapped request #(deliver result %) #(deliver result %))
                   (deref result 1000 ::timeout)))]
    (with-redefs-fn {#'config/current (constantly active-config)
                     #'oauth/access-token-client-id (constantly "invented-cli")
                     #'session/merge-current-user-info (fn [request] (reset! merge-called? true) request)}
      (fn []
        (doseq [request [{:uri "/api/agent/v1/question/17/query" :headers {"authorization" "Bearer invented"}}
                         {:uri "/api/mcp" :metabase-session-key "invented-session"
                          :headers {"authorization" "Bearer invented"}}
                         {:uri "/api/mcp" :headers {"authorization" "Bearer invented" "x-api-key" "invented-key"}}]]
          (is (= 403 (:status (invoke request))))
          (is (false? @merge-called?)))
        (testing "Session-only operations still reach normal authentication"
          (is (= 200 (:status (invoke {:uri "/api/user/current" :metabase-session-key "invented-session" :headers {}}))))
          (is (true? @merge-called?)))))
    (with-redefs [config/current (constantly {:mode :invalid-registry})]
      (reset! merge-called? false)
      (is (= 503 (:status (invoke {:uri "/api/mcp" :headers {"authorization" "Bearer"}}))))
      (is (false? @merge-called?)))))
