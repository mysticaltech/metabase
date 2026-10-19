(ns metabase.mcp.pilot-api-test
  "Invented-grant handler tests. DB-backed issuance/query execution is verified separately."
  (:require
   [clojure.test :refer [deftest is testing]]
   [metabase.api.common :as api]
   [metabase.mcp.api :as mcp]
   [metabase.mcp.pilot-auth :as auth]
   [metabase.mcp.pilot-config :as config]
   [metabase.mcp.pilot-policy-test :as fixtures]
   [metabase.mcp.session :as session]
   [metabase.mcp.tools :as tools]
   [metabase.oauth-server.core :as oauth]
   [metabase.test :as mt]))

(def active-config {:mode :active :client-ids #{"invented-cli"} :policy fixtures/policy})
(def grant (assoc fixtures/grant :user-id 23 :scopes #{"agent:question:execute"}))

(defn- invoke [request]
  (let [result (promise)]
    (mcp/handler request #(deliver result %) #(deliver result %))
    (deref result 1000 ::timeout)))

(defn- head-request [path]
  {:uri path :request-method :head :headers {"authorization" "Bearer invented-access"}})

(defn- with-invented-authority! [f]
  (with-redefs-fn {#'config/current (constantly active-config)
                   #'oauth/resolve-access-token-details (constantly grant)
                   #'auth/current-client (constantly fixtures/client)
                   #'auth/active-user? (constantly true)}
    f))

(deftest canonical-head-admission-proof-test
  (with-invented-authority!
    (fn []
      (with-redefs [session/create! (fn [& _] (throw (AssertionError. "HEAD created a session")))
                    tools/call-tool (fn [& _] (throw (AssertionError. "HEAD executed a query")))]
        (let [response (invoke (head-request "/api/metabase-mcp"))]
          (is (= 204 (:status response)))
          (is (= "" (:body response)))
          (is (= "1" (get-in response [:headers "X-Metabase-MCP-Pilot-Proof"])))
          (is (some? (some->> (get-in response [:headers "X-Metabase-MCP-Pilot-Digest"])
                              (re-matches #"[0-9a-f]{64}"))))
          (is (= "no-store" (get-in response [:headers "Cache-Control"]))))))))

(deftest admission-proof-denials-test
  (with-invented-authority!
    (fn []
      (doseq [path ["/api/mcp" "/api/mcp/" "/api/metabase-mcp/" "/api/metabase-mcp//"
                    "/api/metabase-mcp/anything" "/api/%6detabase-mcp" "/api/metabase-mcp/../agent"]]
        (let [response (invoke (head-request path))]
          (is (not= 204 (:status response)))
          (is (nil? (get-in response [:headers "X-Metabase-MCP-Pilot-Proof"])))))
      (doseq [g [nil (assoc grant :scope ["mb:full"] :scopes #{"mb:full"})
                 (assoc grant :client-id "other-client") (assoc grant :user-id 24)
                 (assoc grant :resource ["https://other.example.invalid/api/metabase-mcp"])]]
        (with-redefs [oauth/resolve-access-token-details (constantly g)]
          (let [response (invoke (head-request "/api/metabase-mcp"))]
            (is (not= 204 (:status response)))
            (is (nil? (get-in response [:headers "X-Metabase-MCP-Pilot-Proof"]))))))
      (doseq [c [{:mode :invalid-registry} {:mode :invalid-policy :client-ids #{"invented-cli"}}]]
        (with-redefs [config/current (constantly c)]
          (let [response (invoke (head-request "/api/metabase-mcp"))]
            (is (= 503 (:status response)))
            (is (nil? (get-in response [:headers "X-Metabase-MCP-Pilot-Proof"]))))))
      (testing "Session, API-key and caller proof headers cannot authenticate the probe"
        (doseq [headers [{"x-metabase-session" "invented-session"}
                         {"x-api-key" "invented-key"}
                         {"x-metabase-mcp-pilot-proof" "1"}]]
          (binding [api/*current-user-id* 23 api/*is-superuser?* true]
            (let [response (invoke {:uri "/api/metabase-mcp" :request-method :head :headers headers})]
              (is (= 401 (:status response)))
              (is (nil? (get-in response [:headers "X-Metabase-MCP-Pilot-Proof"])))))))
      (doseq [extra [{"x-api-key" "invented-key"} {"x-metabase-session" "invented-session"}]]
        (let [response (invoke (update (head-request "/api/metabase-mcp") :headers merge extra))]
          (is (= 403 (:status response)))
          (is (nil? (get-in response [:headers "X-Metabase-MCP-Pilot-Proof"])))))
      (with-redefs [config/current (constantly {:mode :off})]
        (let [response (invoke {:uri "/api/metabase-mcp" :request-method :head :headers {}})]
          (is (= 401 (:status response)))
          (is (nil? (get-in response [:headers "X-Metabase-MCP-Pilot-Proof"]))))))))

(deftest configured-profile-does-not-echo-or-log-inputs-and-upstream-errors-test
  (with-invented-authority!
    (fn []
      (mt/with-log-messages-for-level [messages [metabase.mcp.api :info]]
        (#'mcp/handle-initialize 1 {:clientInfo {:name "invented-sensitive-input" :version "invented-detail"}})
        (is (empty? (messages))))
      (mt/with-log-messages-for-level [messages [metabase.mcp.api :error]]
        (with-redefs [tools/call-tool (fn [& _] (throw (ex-info "invented-sensitive-upstream-detail" {})))]
          (let [response (#'mcp/dispatch-request
                          {:jsonrpc "2.0" :id 2 :method "tools/call"
                           :params {:name "execute_question" :arguments {:id 17}}}
                          "invented-session" #{"agent:question:execute"})]
            (is (= "Approved report unavailable." (get-in response [:error :message])))
            (is (empty? (messages))))))
      (let [response (#'mcp/dispatch-request
                      {:jsonrpc "2.0" :id 2 :method "invented-sensitive-input"}
                      "invented-session" #{"agent:question:execute"})]
        (is (= "Request unavailable for this MCP profile." (get-in response [:error :message])))))))
