(ns metabase.mcp.native-access-legacy-test
  "Focused legacy HTTP contracts without the unrelated full application test harness."
  (:require
   [clojure.test :refer [deftest is]]
   [metabase.api.common :as api]
   [metabase.mcp.api :as mcp]
   [metabase.mcp.native-access :as access]
   [metabase.mcp.pilot-auth :as auth]
   [metabase.mcp.pilot-config :as config]
   [metabase.mcp.pilot-policy-test :as fixtures]
   [metabase.mcp.session :as session]
   [metabase.mcp.tools :as tools]
   [metabase.oauth-server.core :as oauth]
   [metabase.util.json :as json]))

(def active-config {:mode :active :client-ids #{"invented-cli"} :policy fixtures/policy})
(def grant (assoc fixtures/grant :user-id 23 :scopes #{"agent:question:execute"}))

(defn fixture [f]
  (with-redefs-fn {#'access/inputs (constantly {:mode nil :users nil})
                   #'config/current (constantly active-config)
                   #'oauth/resolve-access-token-details (constantly grant)
                   #'auth/current-client (constantly fixtures/client)
                   #'auth/active-user? (constantly true)}
    f))

(defn invoke [request]
  (let [out (promise)]
    (mcp/handler request #(deliver out %) #(deliver out %))
    (deref out 1000 ::timeout)))

(defn request [path]
  {:uri path :request-method :head :headers {"authorization" "Bearer invented-access"}})

(deftest legacy-native-head-proof-still-does-not-create-session-or-execute-test
  (fixture
   (fn []
     (with-redefs [session/create! (fn [& _] (throw (AssertionError. "unexpected session")))
                   tools/call-tool (fn [& _] (throw (AssertionError. "unexpected execution")))]
       (let [response (invoke (request "/api/metabase-mcp"))]
         (is (= 204 (:status response)))
         (is (= "" (:body response)))
         (is (= "1" (get-in response [:headers "X-Metabase-MCP-Pilot-Proof"])))
         (is (some? (some->> (get-in response [:headers "X-Metabase-MCP-Pilot-Digest"])
                             (re-matches #"[0-9a-f]{64}"))))
         (is (= "no-store" (get-in response [:headers "Cache-Control"]))))))))

(deftest legacy-head-alias-grant-and-mixed-auth-denials-stay-closed-test
  (fixture
   (fn []
     (doseq [path ["/api/mcp" "/api/mcp/" "/api/metabase-mcp/" "/api/metabase-mcp//"
                   "/api/metabase-mcp/anything" "/api/%6detabase-mcp" "/api/metabase-mcp/../agent"]]
       (let [response (invoke (request path))]
         (is (not= 204 (:status response)))
         (is (nil? (get-in response [:headers "X-Metabase-MCP-Pilot-Proof"])))))
     (doseq [g [nil (assoc grant :scope ["mb:full"] :scopes #{"mb:full"})
                  (assoc grant :client-id "other-client") (assoc grant :user-id 24)
                  (assoc grant :resource ["https://other.example.invalid/api/metabase-mcp"])]]
       (with-redefs [oauth/resolve-access-token-details (constantly g)]
         (is (not= 204 (:status (invoke (request "/api/metabase-mcp")))))))
     (doseq [headers [{"x-api-key" "invented"} {"x-metabase-session" "invented"}
                      {"x-metabase-mcp-pilot-proof" "1"}]]
       (binding [api/*current-user-id* 23 api/*is-superuser?* true]
         (is (= 401 (:status (invoke (assoc (request "/api/metabase-mcp") :headers headers)))))))
     (doseq [extra [{"x-api-key" "invented"} {"x-metabase-session" "invented"}]]
       (is (= 403 (:status (invoke (update (request "/api/metabase-mcp") :headers merge extra)))))))))

(deftest legacy-degraded-config-origin-and-private-error-response-test
  (fixture
   (fn []
     (doseq [c [{:mode :invalid-registry} {:mode :invalid-policy :client-ids #{"invented-cli"}}]]
       (with-redefs [config/current (constantly c)]
         (is (= 503 (:status (invoke (request "/api/metabase-mcp")))))))
     (is (= 403 (:status (invoke (update (request "/api/metabase-mcp") :headers merge
                                         {"origin" "https://untrusted.example.invalid"
                                          "host" "analytics.example.invalid"})))))
     (with-redefs [tools/call-tool (fn [& _] (throw (ex-info "INVENTED-PRIVATE-SENTINEL" {})))]
       (let [response (#'mcp/dispatch-request
                        {:jsonrpc "2.0" :id 2 :method "tools/call"
                         :params {:name "execute_question" :arguments {:id 17}}}
                        "invented-session" #{"agent:question:execute"})]
         (is (= "Approved report unavailable." (get-in response [:error :message])))
         (is (not (.contains ^String (json/encode response) "INVENTED-PRIVATE-SENTINEL"))))))))
