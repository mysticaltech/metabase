(ns metabase.mcp.native-access-test
  "Synthetic account/grant fixtures exercise real native handlers. No live account or deployment claim."
  (:require
   [clojure.test :refer [deftest is]]
   [metabase.api.common :as api]
   [metabase.mcp.api :as mcp.api]
   [metabase.mcp.core :as mcp]
   [metabase.mcp.native-access :as access]
   [metabase.mcp.pilot-config :as pilot.config]
   [metabase.mcp.session :as session]
   [metabase.mcp.tools :as tools]
   [metabase.oauth-server.core :as oauth]
   [metabase.request.session :as request.session]
   [metabase.system.core :as system]
   [metabase.util.json :as json]
   [oidc-provider.store :as oidc.store]
   [toucan2.core :as t2]))

(def resource "https://analytics.example.invalid/api/metabase-mcp")
(def grant {:user-id 23 :client-id "invented-native-client" :resource [resource]
            :scope ["agent:question:create" "agent:question:execute"]
            :scopes #{"agent:question:create" "agent:question:execute"}})

(defn status [f]
  (try (f) nil
       (catch clojure.lang.ExceptionInfo e
         (is (nil? (ex-cause e)))
         (is (= #{:status-code :type} (set (keys (ex-data e)))))
         (:status-code (ex-data e)))))

(defn fixture [f]
  (let [active (atom #{23 47}) inputs (atom {:mode "two-accounts" :users "[23,47]"})]
    (with-redefs [access/inputs #(deref inputs)
                  pilot.config/inputs (constantly {:registry nil :path nil})
                  system/site-url (constantly "https://analytics.example.invalid")
                  t2/exists? (fn [model & args]
                               (is (= :model/User model))
                               (let [{:keys [id is_active]} (apply hash-map args)]
                                 (is (true? is_active)) (contains? @active id)))
                  request.session/with-current-user-fetch-user-for-id
                  (fn [id] {:metabase-user-id id :is-superuser? false :settings {}})]
      (f active inputs))))

(defn invoke [request]
  (let [out (promise)]
    (mcp.api/handler request #(deliver out %) #(deliver out %))
    (deref out 1000 ::timeout)))

(defn request [method]
  {:uri "/api/metabase-mcp" :request-method :post
   :headers {"authorization" "Bearer invented-token"}
   :body {:jsonrpc "2.0" :id 1 :method method :params {}}})

(deftest exact-two-account-input-and-no-last-good-fallback-test
  (fixture
   (fn [_ inputs]
     (is (= {:mode :active :user-ids #{23 47}} (access/current)))
     (doseq [bad [{:mode nil :users "[23,47]"} {:mode "two-accounts" :users nil}
                   {:mode "off" :users "[23,47]"} {:mode "two-accounts" :users "[23]"}
                   {:mode "two-accounts" :users "[23,23]"} {:mode "two-accounts" :users "[23,47,99]"}
                   {:mode "two-accounts" :users "[23,47] {}"} {:mode "two-accounts" :users "[23,47.0]"}
                   {:mode "two-accounts" :users "[23,\"47\"]"} {:mode "two-accounts" :users "[0,47]"}
                   {:mode "two-accounts" :users "[23,2147483648]"}]]
       (reset! inputs bad)
       (is (= {:mode :invalid} (access/current)))
       (is (= 503 (status #(access/validate-grant! grant)))))
     (reset! inputs {:mode nil :users nil})
     (is (= {:mode :off} (access/current)))
     (is (true? (access/validate-grant! {}))))))

(deftest competing-pilot-mode-cannot-activate-native-fallback-test
  (fixture
   (fn [_ _]
     (doseq [legacy [{:registry "[]" :path nil} {:registry nil :path "invented-path"}]]
       (with-redefs [pilot.config/inputs (constantly legacy)]
         (is (= {:mode :invalid} (access/current)))
         (is (= 503 (status #(access/validate-grant! grant)))))))))

(deftest both-accounts-with-full-native-scopes-not-readonly-filtered-test
  (fixture
   (fn [_ _]
     (doseq [id [23 "23" 47 "47"] scopes [(:scope grant) ["agent:sql:execute"] ["agent:dashboard:create"]]]
       (is (true? (access/validate-grant! (assoc grant :user-id id :scope scopes))))))))

(deftest foreign-noncanonical-and-deactivated-accounts-denied-test
  (fixture
   (fn [active _]
     (doseq [id [nil 99 "99" "023" " 23" "23.0" -1 true 23.0 {}]]
       (is (= 403 (status #(access/validate-grant! (assoc grant :user-id id))))))
     (swap! active disj 47)
     (is (= 403 (status #(access/validate-grant! (assoc grant :user-id 47))))))))

(deftest canonical-resource-is-required-for-native-token-grants-test
  (fixture
   (fn [_ _]
     (doseq [r [nil [] [resource resource] [(str resource "/")] "https://other.example.invalid/api/metabase-mcp"]]
       (is (= 403 (status #(access/validate-grant! (assoc grant :resource r))))))
     (is (true? (access/validate-grant! (assoc grant :resource resource)))))))

(deftest captured-configuration-is-rechecked-before-and-after-user-query-test
  (fixture
   (fn [_ inputs]
     (let [before (access/current)]
       (reset! inputs {:mode "two-accounts" :users "[23,99]"})
       (is (= 503 (status #(access/authorize! before grant)))))
     (reset! inputs {:mode "two-accounts" :users "[23,47]"})
     (with-redefs [t2/exists? (fn [& _] (reset! inputs {:mode nil :users nil}) true)]
       (is (= 503 (status #(access/validate-grant! grant))))))))

(deftest native-core-and-provider-authorization-hooks-enforce-account-admission-test
  (fixture
   (fn [_ _]
     (is (true? (mcp/validate-pilot-grant! grant)))
     (is (= 403 (status #(mcp/validate-pilot-grant! (assoc grant :user-id 99)))))
     (is (true? (oauth/validate-pilot-authorization!
                 {:client_id (:client-id grant) :scope "agent:question:create" :resource [resource]} 23)))
     (is (= 403 (status #(oauth/validate-pilot-authorization!
                          {:client_id (:client-id grant) :scope "agent:question:create" :resource [resource]} 99)))))))

(deftest native-ui-credentials-have-the-same-account-boundary-test
  (fixture
   (fn [active inputs]
     (with-redefs [session/resolve-ui-credential (fn [credential] {:uid credential :sid "invented"})]
       (is (= {:uid 23 :sid "invented"} (mcp/resolve-ui-credential 23)))
       (is (nil? (mcp/resolve-ui-credential 99)))
       (swap! active disj 47)
       (is (nil? (mcp/resolve-ui-credential 47)))
       (reset! inputs {:mode "two-accounts" :users nil})
       (is (nil? (mcp/resolve-ui-credential 23)))))))

(deftest missing-bearer-and-cookie-or-apikey-cannot-admit-an-account-test
  (fixture
   (fn [_ _]
     (binding [api/*current-user-id* 23 api/*is-superuser?* true]
       (doseq [headers [{} {"x-api-key" "invented"} {"x-metabase-session" "invented"}]]
         (let [response (invoke (assoc (request "ping") :headers headers))]
           (is (= 401 (:status response)))
           (is (string? (get-in response [:headers "WWW-Authenticate"])))))
       (doseq [extra [{:metabase-session-key "invented"}
                      {:headers {"authorization" "Bearer invented-token" "x-api-key" "invented"}}
                      {:headers {"authorization" "Bearer invented-token" "x-metabase-session" "invented"}}]]
         (is (= 403 (:status (invoke (merge (request "ping") extra))))))))))

(deftest only-canonical-machine-path-reaches-native-dispatch-test
  (fixture
   (fn [_ _]
     (doseq [path ["/api/mcp" "/api/metabase-mcp/" "/api/metabase-mcp/not-allowed" "/api/%6detabase-mcp"]]
       (is (= 403 (:status (invoke (assoc (request "ping") :uri path)))))))))

(deftest real-native-handler-admits-both-accounts-and-denies-everyone-else-test
  (fixture
   (fn [_ _]
     (doseq [id [23 47 99]]
       (with-redefs [oauth/resolve-access-token-details (constantly (assoc grant :user-id id))]
         (let [response (invoke (request "initialize"))]
           (is (= (if (= id 99) 403 200) (:status response)))
           (when (not= id 99)
             (is (= {:listChanged true} (get-in (json/decode+kw (:body response)) [:result :capabilities :tools])))))))
     (with-redefs [oauth/resolve-access-token-details (constantly nil)]
       (is (= 401 (:status (invoke (request "ping")))))))))

(deftest native-tool-dispatch-keeps-role-identity-and-full-scopes-test
  (fixture
   (fn [_ _]
     (let [seen (atom [])]
       (with-redefs [oauth/resolve-access-token-details (constantly grant)
                     session/owned-by-user? (constantly true)
                     session/supports-mcp-ui? (constantly false)
                     tools/call-tool (fn [scopes _ tool args _]
                                       (swap! seen conj [api/*current-user-id* api/*is-superuser?* scopes tool args])
                                       {:content [{:type "text" :text "invented-native-result"}]})]
         (let [r (-> (request "tools/call")
                     (assoc-in [:headers "mcp-session-id"] (str (random-uuid)))
                     (assoc-in [:body :params] {:name "create_question" :arguments {:name "invented"}}))]
           (is (= 200 (:status (invoke r))))
           (is (= [[23 false (:scopes grant) "create_question" {:name "invented"}]] @seen))))))))

(deftest native-catalog-retains-write-and-query-tools-test
  (fixture
   (fn [_ _]
     (let [scopes (vec (mcp/all-scopes))]
       (with-redefs [oauth/get-provider (constantly {:token-store :invented-token-store})
                     oidc.store/get-access-token
                     (fn [store token]
                       (is (= :invented-token-store store))
                       (is (= "invented-native-token" token))
                       (assoc grant :user-id "23" :scope scopes))]
         (let [resolved (oauth/resolve-access-token "invented-native-token")
               token-scopes (:scopes resolved)
               catalog (tools/list-tools token-scopes {:supports-mcp-ui? false})
               names (set (map :name catalog))]
           (is (= 23 (:user-id resolved)))
           (is (set? token-scopes))
           (is (not (sorted? token-scopes)))
           (is (= (into #{} scopes) token-scopes))
           (is (every? string? token-scopes))
           (is (contains? names "create_question"))
           (is (contains? names "execute_question"))
           (is (contains? names "query"))
           (is (contains? names "create_dashboard"))))))))

(deftest revoked-account-after-native-call-withholds-response-test
  (fixture
   (fn [active _]
     (with-redefs [oauth/resolve-access-token-details (constantly grant)
                   session/owned-by-user? (constantly true)
                   session/supports-mcp-ui? (constantly false)
                   tools/call-tool (fn [& _] (swap! active disj 23) {:content []})]
       (let [r (-> (request "tools/call")
                   (assoc-in [:headers "mcp-session-id"] (str (random-uuid)))
                   (assoc-in [:body :params] {:name "query" :arguments {}}))]
         (is (= 403 (:status (invoke r)))))))))
