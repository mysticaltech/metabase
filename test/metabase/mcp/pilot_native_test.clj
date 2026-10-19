(ns metabase.mcp.pilot-native-test
  "Invented-H2 native OAuth, Ring transport and saved-question execution. No production configuration is used."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [metabase.agent-api.api]
   [metabase.api.macros :as api.macros]
   [metabase.api.macros.scope :as api.scope]
   [metabase.collections-rest.api]
   [metabase.initialization-status.core :as init-status]
   [metabase.lib-be.metadata.jvm :as lib.metadata.jvm]
   [metabase.lib.core :as lib]
   [metabase.mcp.api :as mcp]
   [metabase.mcp.pilot-config :as config]
   [metabase.mcp.pilot-policy :as policy]
   [metabase.mcp.pilot-policy-test :as fixture]
   [metabase.mcp.pilot-snapshot :as snapshot]
   [metabase.mcp.session :as session]
   [metabase.mcp.tools :as tools]
   [metabase.native-query-snippets.api]
   [metabase.oauth-server.api :as oauth.api]
   [metabase.oauth-server.core :as oauth]
   [metabase.permissions.core :as perms]
   [metabase.permissions.models.permissions-group :as perms-group]
   [metabase.queries-rest.api.card]
   [metabase.request.core :as request]
   [metabase.server.middleware.session :as middleware]
   [metabase.test :as mt]
   [metabase.test.fixtures :as fixtures]
   [metabase.util.json :as json]
   [oidc-provider.core :as oidc]
   [oidc-provider.store :as store]
   [oidc-provider.util :as oidc.util]
   [ring.util.codec :as codec]
   [toucan2.core :as t2])
  (:import
   (java.net URI)
   (java.nio.charset StandardCharsets)
   (java.security MessageDigest)
   (java.util Base64)))

(set! *warn-on-reflection* true)

(use-fixtures :once (fixtures/initialize :db :test-users))

(defn- invoke [handler request]
  (let [response (promise)]
    (handler request #(deliver response %) #(deliver response %))
    (deref response 40000 ::timeout)))

(defn- decoded-body [response]
  (let [body (:body response)] (if (string? body) (json/decode+kw body) body)))

(defn- oauth-post [path body]
  (invoke oauth.api/oauth-routes
          {:uri path :request-method :post :remote-addr "127.0.0.1"
           :headers {"content-type" "application/x-www-form-urlencoded"}
           :body body :params body :form-params body}))

(defn- token-pair! [p]
  (let [provider (oauth/get-provider)
        client-id (get-in p [:clients 0 :id])
        callback (get-in p [:clients 0 :redirect-uris 0])
        ^String verifier (apply str (repeat 64 "a"))
        challenge (.encodeToString (.withoutPadding (Base64/getUrlEncoder))
                                   (.digest (MessageDigest/getInstance "SHA-256")
                                            (.getBytes verifier StandardCharsets/US_ASCII)))
        parsed (oidc/parse-authorization-request
                provider {:client_id client-id :redirect_uri callback :response_type "code"
                          :scope policy/execute-scope :resource (:resource p)
                          :code_challenge challenge :code_challenge_method "S256"})
        _ (oauth/validate-pilot-authorization! parsed (:user-id p))
        ^String redirect (oidc/authorize provider parsed (str (:user-id p)))
        code (get (codec/form-decode (.getRawQuery (URI. redirect))) "code")
        response (oauth-post "/token" {:grant_type "authorization_code" :client_id client-id
                                       :redirect_uri callback :code code :code_verifier verifier})]
    ;; Deliberately assert only status and non-secret metadata; never print the token response.
    (is (= 200 (:status response)))
    (is (= "Bearer" (:token_type (decoded-body response))))
    (decoded-body response)))

(defn- mcp-request
  ([token body] (mcp-request token "/api/metabase-mcp" body {}))
  ([token path body headers]
   (invoke mcp/handler {:uri path :request-method :post :body body
                        :headers (merge {"authorization" (str "Bearer " token)} headers)})))

(defn- initialize! [token path]
  (mcp-request token path {:jsonrpc "2.0" :id 1 :method "initialize"
                           :params {:protocolVersion "2025-03-26" :capabilities {}
                                    :clientInfo {:name "Invented local native test" :version "1"}}} {}))

(defn- call! [token session-id args]
  (mcp-request token "/api/metabase-mcp"
               {:jsonrpc "2.0" :id 2 :method "tools/call"
                :params {:name "execute_question" :arguments args}}
               {"mcp-session-id" session-id}))

(defn- with-native-pilot! [username f]
  (mt/with-temporary-setting-values [site-url "http://localhost:3000"]
    (init-status/set-complete!)
    (oauth/reset-provider!)
    (let [user-id (mt/user->id username)
          client-id (str "nmcp-invented-" (random-uuid))
          callback "http://127.0.0.1:38171/callback"]
      (mt/with-temp [:model/OAuthClient client {:client_id client-id :client_type "public"
                                                :application_type "native" :registration_type "static"
                                                :token_endpoint_auth_method "none"
                                                :redirect_uris [callback] :response_types ["code"]
                                                :grant_types ["authorization_code" "refresh_token"]
                                                :scopes [policy/execute-scope]}
                     :model/Collection collection {:name "Invented pilot aggregates"}
                     :model/Card card {:name "Invented pilot visits" :type :question :display :table
                                       :database_id (mt/id) :collection_id (:id collection)
                                       :dataset_query {:database (mt/id) :type :native
                                                       :native {:query "SELECT 41 AS \"visits\"" :template-tags {}}}}]
        (when-not (= username :crowberto)
          (perms/grant-collection-read-permissions! (perms-group/all-users) (:id collection)))
        ;; Native queries can populate saved result metadata on first execution.
        ;; Warm this invented fixture before reviewing and pinning its stable definition.
        (request/with-current-user (mt/user->id :crowberto)
          (let [warm (tools/call-tool #{policy/execute-scope} (session/create! user-id)
                                      "execute_question" {:id (:id card)})]
            (is (not (:isError warm)))))
        (let [report (assoc fixture/report :id (:id card) :collection-id (:id collection) :database-id (mt/id)
                            :columns [{:name "visits" :base-type "type/Integer" :kind "integer"}])
              captured (request/with-current-user (mt/user->id :crowberto) (snapshot/capture! report))
              p (assoc fixture/policy :user-id user-id :clients [{:id client-id :redirect-uris [callback]}]
                       :reports [(assoc report :sha256 (policy/fingerprint (:root captured)))])
              c {:mode :active :client-ids #{client-id} :policy p}]
          (with-redefs [config/current (constantly c)]
            (try
              (f {:policy p :config c :card card :collection collection :client client :user-id user-id
                  :tokens (token-pair! p)})
              (finally
                (t2/delete! :model/OAuthAccessToken :client_id client-id)
                (t2/delete! :model/OAuthRefreshToken :client_id client-id)
                (t2/delete! :model/OAuthAuthorizationCode :client_id client-id)))))))
    (oauth/reset-provider!)))

(defn- with-dcr-client! [metadata f]
  (mt/with-temporary-setting-values [oauth-server-dynamic-registration-enabled true]
    (let [response (invoke oauth.api/oauth-routes
                           {:uri "/register" :request-method :post :remote-addr "127.0.0.1"
                            :headers {"content-type" "application/json"} :body metadata})
          client-id (:client_id (decoded-body response))]
      (is (= 201 (:status response)))
      (when (string? client-id)
        (try
          (f (t2/select-one :model/OAuthClient :client_id client-id))
          (finally
            (t2/delete! :model/OAuthAccessToken :client_id client-id)
            (t2/delete! :model/OAuthRefreshToken :client_id client-id)
            (t2/delete! :model/OAuthAuthorizationCode :client_id client-id)
            (t2/delete! :model/OAuthClientEvent :oauth_client_id
                        (t2/select-one-pk :model/OAuthClient :client_id client-id))
            (t2/delete! :model/OAuthClient :client_id client-id)))))))

(defn- api-json [ns-sym id]
  (let [response (invoke (:handler (api.macros/find-route ns-sym :get "/:id"))
                         {:uri (str "/" id) :request-method :get :headers {}
                          :route-params {:id (str id)} :query-params {}})]
    (when (instance? Throwable response) (throw response))
    (is (= 200 (:status response)))
    ;; The same encoder used by the native JSON response middleware, retained only in memory.
    (json/decode+kw (json/encode (:body response)))))

(deftest persisted-query-does-not-pin-runtime-provider-test
  (with-native-pilot!
    :crowberto
    (fn [{:keys [policy user-id card]}]
      (let [report (get-in policy [:reports 0])
            capture (fn []
                      (binding [lib.metadata.jvm/*metadata-provider-cache* nil]
                        (request/with-current-user user-id (snapshot/capture! report))))
            first-snapshot (capture)
            next-snapshot (capture)
            api-card (request/with-current-user user-id (api-json 'metabase.queries-rest.api.card (:id card)))
            persisted (-> (:dataset_query api-card) lib/->mbql5
                          (as-> q (lib/normalize :metabase.lib.schema/query q))
                          lib/prepare-for-serialization)]
        (is (not (contains? (get-in first-snapshot [:root :dataset_query]) :lib/metadata)))
        (is (= persisted (get-in first-snapshot [:root :dataset_query])))
        (is (= (policy/fingerprint first-snapshot) (policy/fingerprint next-snapshot)))
        (request/with-current-user user-id
          (let [collection-id (:collection_id card)
                metadata {:cards {(:id card) api-card}
                          :collections {collection-id (api-json 'metabase.collections-rest.api collection-id)}
                          :snippets {}}]
            (is (= (snapshot/pins! report) (snapshot/pins-from-api report metadata)))))))))

(deftest complete-api-graph-pins-match-capture-test
  (with-native-pilot!
    :crowberto
    (fn [{:keys [user-id card collection]}]
      (request/with-current-user user-id
        (mt/with-temp [:model/Collection snippet-collection {:name "Invented snippets" :namespace :snippets}
                       :model/NativeQuerySnippet snippet {:name "nmcp invented condition" :content "true"
                                                          :collection_id (:id snippet-collection)}
                       :model/Card root {:name "Invented dependent aggregate" :type :question :display :table
                                         :database_id (mt/id) :collection_id (:id collection)
                                         :dataset_query
                                         {:database (mt/id) :type :native
                                          :native {:query (str "SELECT * FROM {{#" (:id card)
                                                               "}} WHERE {{snippet: nmcp invented condition}}")
                                                   :template-tags
                                                   {(str "#" (:id card))
                                                    {:name (str "#" (:id card)) :display-name "Invented source"
                                                     :type :card :card-id (:id card)}
                                                    "snippet: nmcp invented condition"
                                                    {:name "snippet: nmcp invented condition" :display-name "Invented condition"
                                                     :type :snippet :snippet-id (:id snippet)
                                                     :snippet-name "nmcp invented condition"}}}}}]
          (let [report (assoc fixture/report :id (:id root) :database-id (mt/id) :collection-id (:id collection))
                metadata {:cards (into {} (for [id [(:id root) (:id card)]]
                                            [id (api-json 'metabase.queries-rest.api.card id)]))
                          :snippets {(:id snippet) (api-json 'metabase.native-query-snippets.api (:id snippet))}
                          :collections (into {} (for [id [(:id collection) (:id snippet-collection)]]
                                                  [id (api-json 'metabase.collections-rest.api id)]))}
                expected (snapshot/pins! report)]
            (is (= 2 (count (:dependencies expected))))
            (is (= expected (snapshot/pins-from-api report metadata)))
            (is (thrown? clojure.lang.ExceptionInfo
                         (snapshot/pins-from-api report (assoc metadata :snippets {}))))
            (doseq [changed [(assoc-in metadata [:cards (:id card) :dataset_query :stages 0 :native] "SELECT 99")
                             (assoc-in metadata [:snippets (:id snippet) :content] "false")
                             (assoc-in metadata [:collections (:id collection) :location] "/9/")]]
              (is (not= expected (snapshot/pins-from-api report changed))))))))))

(deftest explicitly-pinned-native-dcr-client-test
  (with-native-pilot!
    :crowberto
    (fn [{:keys [policy card]}]
      (let [callback "http://127.0.0.1:38171/callback"
            metadata {:client_name "Invented reviewed pilot" :application_type "native"
                      :token_endpoint_auth_method "none" :redirect_uris [callback]
                      :response_types ["code"] :grant_types ["authorization_code" "refresh_token"]}]
        (with-dcr-client!
          (assoc metadata :scope policy/execute-scope)
          (fn [client]
            (is (= "dynamic" (:registration_type client)))
            (let [p (assoc policy :clients [{:id (:client_id client) :redirect-uris [callback]}])
                  tokens (token-pair! p)
                  access (:access_token tokens)]
              (testing "Registration alone never grants MCP admission"
                (is (= 403 (:status (initialize! access "/api/metabase-mcp")))))
              (with-redefs [config/current (constantly {:mode :active :client-ids #{(:client_id client)} :policy p})]
                (let [init (initialize! access "/api/metabase-mcp")
                      session-id (get-in init [:headers "Mcp-Session-Id"])]
                  (is (= 200 (:status init)))
                  (is (= [[41]] (get-in (decoded-body (call! access session-id {:id (:id card)}))
                                        [:result :structuredContent :data :rows]))))
                (let [refresh (oauth-post "/token" {:grant_type "refresh_token" :client_id (:client_id client)
                                                    :refresh_token (:refresh_token tokens)})
                      refreshed (:access_token (decoded-body refresh))]
                  (is (= 200 (:status refresh)))
                  (doseq [drift [{:redirect_uris ["http://127.0.0.1:38172/callback"]}
                                 {:scopes ["mb:full"]}]]
                    (t2/update! :model/OAuthClient (:id client) drift)
                    (is (thrown? clojure.lang.ExceptionInfo (oauth/resolve-access-token refreshed)))
                    (t2/update! :model/OAuthClient (:id client)
                                {:redirect_uris [callback] :scopes [policy/execute-scope]})))))))
        (testing "Explicitly naming a default broad DCR client cannot widen the scope ceiling"
          (with-dcr-client!
            metadata
            (fn [client]
              (let [p (assoc policy :clients [{:id (:client_id client) :redirect-uris [callback]}])]
                (with-redefs [config/current (constantly {:mode :active :client-ids #{(:client_id client)} :policy p})]
                  (is (thrown? clojure.lang.ExceptionInfo (token-pair! p))))))))))))

(deftest real-native-question-and-alias-guard-test
  (with-native-pilot!
    :crowberto
    (fn [{:keys [tokens card]}]
      (let [access (:access_token tokens)]
        (doseq [path ["/api/metabase-mcp" "/api/metabase-mcp/" "/api/mcp" "/api/mcp/"]]
          (let [init (initialize! access path)
                session-id (get-in init [:headers "Mcp-Session-Id"])
                response (call! access session-id {:id (:id card)})
                result (:result (decoded-body response))]
            (is (= 200 (:status init)))
            (is (= {:tools {}} (get-in (decoded-body init) [:result :capabilities])))
            (is (not (:isError result)))
            (is (= [[41]] (get-in result [:structuredContent :data :rows])))
            (is (= #{:status :data :row_count} (set (keys (:structuredContent result)))))
            (doseq [args [{:id (inc (:id card))} {:id (:id card) :query nil} {:id (:id card) :filters []}]]
              (is (true? (get-in (decoded-body (call! access session-id args)) [:result :isError]))))
            (is (= 400 (:status (mcp-request access path [{:jsonrpc "2.0" :id 3 :method "ping"}]
                                             {"mcp-session-id" session-id}))))))
        (doseq [path ["/api/mcp/subpath" "/api/mcp//" "/api/metabase-mcp/../agent"]]
          (is (= 403 (:status (initialize! access path)))))))))

(deftest actual-native-date-question-projection-test
  (with-native-pilot!
    :crowberto
    (fn [{:keys [tokens policy config collection user-id]}]
      (mt/with-temp [:model/Card card {:name "Invented leap-day aggregate" :type :question :display :table
                                       :database_id (mt/id) :collection_id (:id collection)
                                       :dataset_query {:database (mt/id) :type :native
                                                       :native {:query "SELECT DATE '2024-02-29' AS \"day\", 41 AS \"visits\""
                                                                :template-tags {}}}}]
        (let [warm (with-redefs [config/current (constantly {:mode :off})]
                     (request/with-current-user user-id
                       (tools/call-tool #{policy/execute-scope} (session/create! user-id)
                                        "execute_question" {:id (:id card)})))
              report (assoc fixture/report :id (:id card) :collection-id (:id collection) :database-id (mt/id)
                            :columns [{:name "day" :base-type "type/Date" :kind "date"}
                                      {:name "visits" :base-type "type/Integer" :kind "integer"}])
              captured (request/with-current-user user-id (snapshot/capture! report))
              p (assoc policy :reports [(assoc report :sha256 (policy/fingerprint (:root captured)))])]
          (is (not (:isError warm)))
          (is (= "type/Date" (get-in warm [:structuredContent :data :cols 0 :base_type])))
          (with-redefs [config/current (constantly (assoc config :policy p))]
            (let [access (:access_token tokens)
                  init (initialize! access "/api/metabase-mcp")
                  session-id (get-in init [:headers "Mcp-Session-Id"])
                  result (:result (decoded-body (call! access session-id {:id (:id card)})))]
              (is (= 200 (:status init)))
              (is (nil? (:isError result)))
              (is (= [["2024-02-29" 41]] (get-in result [:structuredContent :data :rows])))
              (is (= (:structuredContent result)
                     (when (:structuredContent result)
                       (json/decode+kw (get-in result [:content 0 :text]))))))))))))

(deftest native-refresh-revocation-expiry-and-client-drift-test
  (with-native-pilot!
    :crowberto
    (fn [{:keys [tokens policy client user-id]}]
      (let [client-id (:client_id client)
            refresh (oauth-post "/token" {:grant_type "refresh_token" :client_id client-id
                                          :refresh_token (:refresh_token tokens)})
            next-pair (decoded-body refresh)]
        (is (= 200 (:status refresh)))
        (is (true? (not= (:access_token tokens) (:access_token next-pair))))
        (is (= #{policy/execute-scope} (:scopes (oauth/resolve-access-token-details (:access_token next-pair)))))
        (is (= 400 (:status (oauth-post "/token" {:grant_type "refresh_token" :client_id client-id
                                                  :refresh_token (:refresh_token tokens)}))))
        (is (= 200 (:status (oauth-post "/revoke" {:client_id client-id :token_type_hint "access_token"
                                                   :token (:access_token next-pair)}))))
        (is (nil? (oauth/resolve-access-token (:access_token next-pair))))
        (is (= 200 (:status (oauth-post "/revoke" {:client_id client-id :token_type_hint "refresh_token"
                                                   :token (:refresh_token next-pair)}))))
        (is (= 400 (:status (oauth-post "/token" {:grant_type "refresh_token" :client_id client-id
                                                  :refresh_token (:refresh_token next-pair)}))))
        (let [expired (str (random-uuid))]
          (store/save-access-token (:token-store (oauth/get-provider)) expired (str user-id) client-id
                                   [policy/execute-scope] (- (inst-ms (java.util.Date.)) 1000) [(:resource policy)])
          (is (nil? (oauth/resolve-access-token expired))))
        (let [pair (token-pair! policy)]
          (t2/update! :model/OAuthClient (:id client) {:scopes ["mb:full"]})
          (is (thrown? clojure.lang.ExceptionInfo (oauth/resolve-access-token (:access_token pair))))
          (is (= 403 (:status (oauth-post "/token" {:grant_type "refresh_token" :client_id client-id
                                                    :refresh_token (:refresh_token pair)}))))
          (testing "Even drifted credentials can still be revoked through the normal native endpoint"
            (is (= 200 (:status (oauth-post "/revoke" {:client_id client-id :token (:refresh_token pair)})))))
          (t2/update! :model/OAuthClient (:id client) {:scopes [policy/execute-scope]}))))))

(deftest real-token-pre-fallback-rest-and-mixed-auth-denial-test
  (with-native-pilot!
    :crowberto
    (fn [{:keys [tokens]}]
      (init-status/set-complete!)
      (let [called? (atom false)
            wrapped (middleware/wrap-current-user-info (fn [_ respond _] (reset! called? true) (respond {:status 200})))
            headers {"authorization" (str "Bearer " (:access_token tokens))}]
        (doseq [req [{:uri "/api/agent/v1/question/17/query" :headers headers}
                     {:uri "/api/metabase-mcp" :headers (assoc headers "x-api-key" "invented-key")}
                     {:uri "/api/metabase-mcp" :headers headers :metabase-session-key "invented-session"}]]
          (is (= 403 (:status (invoke wrapped req))))
          (is (false? @called?)))))))

(deftest other-superuser-and-non-pilot-oauth-behavior-test
  (with-native-pilot!
    :rasta
    (fn [{:keys [policy]}]
      (let [other-user-token (str (random-uuid))
            baseline-token (str (random-uuid))
            user-id (mt/user->id :crowberto)
            token-store (:token-store (oauth/get-provider))
            expiry (+ (inst-ms (java.util.Date.)) 3600000)
            client-id (get-in policy [:clients 0 :id])]
        (try
          (with-redefs [config/current (constantly {:mode :off})]
            (store/save-access-token token-store other-user-token (str user-id) client-id
                                     [policy/execute-scope] expiry [(:resource policy)]))
          (is (= 403 (:status (initialize! other-user-token "/api/metabase-mcp"))))
          (store/save-access-token token-store baseline-token (str user-id) "invented-baseline-client"
                                   ["mb:full"] expiry nil)
          (let [wrapped (middleware/wrap-current-user-info
                         (fn [req respond _]
                           (respond {:status 200 :resolved-user (:metabase-user-id req)
                                     :scopes (:token-scopes req)})))
                response (invoke wrapped {:uri "/api/user/current"
                                          :headers {"authorization" (str "Bearer " baseline-token)}})]
            (is (= 200 (:status response)))
            (is (= user-id (:resolved-user response)))
            (is (= #{::api.scope/unrestricted} (:scopes response))))
          (is (= 403 (:status (initialize! baseline-token "/api/metabase-mcp"))))
          (finally
            (t2/delete! :model/OAuthAccessToken :token (oidc.util/hash-token baseline-token))))))))

(deftest existing-permission-and-deactivated-user-denials-test
  (mt/with-non-admin-groups-no-root-collection-perms
    (with-native-pilot!
      :rasta
      (fn [{:keys [tokens card collection user-id]}]
        (let [access (:access_token tokens)
              session-id (get-in (initialize! access "/api/metabase-mcp") [:headers "Mcp-Session-Id"])]
          (is (= [[41]] (get-in (decoded-body (call! access session-id {:id (:id card)}))
                                [:result :structuredContent :data :rows])))
          (perms/revoke-collection-permissions! (perms-group/all-users) (:id collection))
          (is (true? (get-in (decoded-body (call! access session-id {:id (:id card)})) [:result :isError])))
          (try
            (t2/update! :model/User user-id {:is_active false})
            (is (thrown? clojure.lang.ExceptionInfo (oauth/resolve-access-token access)))
            (finally (t2/update! :model/User user-id {:is_active true}))))))))

(deftest policy-drift-during-initialize-fails-response-closed-test
  (with-native-pilot!
    :crowberto
    (fn [{:keys [tokens config]}]
      (let [current (atom config)
            create-session session/create!]
        (with-redefs [config/current #(deref current)
                      session/create! (fn [& args]
                                        (let [id (apply create-session args)]
                                          (reset! current {:mode :invalid-policy :client-ids (:client-ids config)})
                                          id))]
          (let [response (initialize! (:access_token tokens) "/api/metabase-mcp")]
            (is (= 503 (:status response)))
            (is (nil? (get-in response [:headers "Mcp-Session-Id"])))))))))
