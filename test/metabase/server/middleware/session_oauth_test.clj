(ns metabase.server.middleware.session-oauth-test
  "Tests for the OAuth bearer-token bridge in the core session middleware — the single place an OAuth
  access token authenticates a request to the general (`/api/*`) API, and the single place the granted
  OAuth scopes are mapped onto `:token-scopes` for the scope-enforcement middleware."
  (:require
   [clj-http.client :as http]
   [clojure.test :refer [deftest is testing]]
   ;; Loaded for its load-time side effects: the OAuth provider's scopes-supported is derived by
   ;; reflecting over the agent API route table (see [[metabase.mcp.core/all-scopes]]), which in a
   ;; full server boot is loaded by [[metabase.api-routes.routes]]. The isolated test classpath does
   ;; not mount the routes, so require it here as that route ns does.
   [metabase.agent-api.api]
   [metabase.api.macros.scope :as scope]
   [metabase.initialization-status.core :as init-status]
   [metabase.mcp.core :as mcp]
   [metabase.oauth-server.core :as oauth-server]
   [metabase.server.instance :as server.instance]
   [metabase.server.middleware.json :as mw.json]
   [metabase.server.middleware.session :as mw.session]
   [metabase.test :as mt]
   [metabase.util.json :as json]
   [oidc-provider.store :as oidc.store]
   [toucan2.core :as t2])
  (:import
   (org.eclipse.jetty.server Server)))

(set! *warn-on-reflection* true)

;; The OAuth bearer path is gated on initialization being complete (like the session/api-key paths);
;; the isolated test runner never boots the web server, so mark init complete as session_test does.
(init-status/set-complete!)

(def ^:private merge-current-user-info #'mw.session/merge-current-user-info)
(def ^:private oauth-token->token-scopes #'mw.session/oauth-token->token-scopes)

(defn- bearer-request [token]
  {:headers {"authorization" (str "Bearer " token)}})

(defn- with-http-handler! [handler f]
  (let [^Server server (server.instance/create-server handler {:host "127.0.0.1" :port 0 :join? false})]
    (try
      (.start server)
      (f (str "http://127.0.0.1:" (.. server getURI getPort)))
      (finally
        (.stop server)))))

(deftest pilot-rest-denial-on-http-wire-test
  (let [called (atom 0)
        handler (-> (fn [_ respond _]
                      (swap! called inc)
                      (respond {:status 200 :body {:reached true}}))
                    mw.json/wrap-streamed-json-response
                    mw.session/wrap-current-user-info)]
    ;; Jetty dispatches on its own threads: these lookup stubs must be visible outside the test thread.
    (with-redefs [mcp/pilot-configuration (constantly {:mode :active :client-ids #{"invented-pilot"}})
                  oauth-server/access-token-client-id (constantly "invented-pilot")]
      (with-http-handler!
        handler
        (fn [url]
          (let [{:keys [status headers body]}
                (http/get (str url "/api/user/current")
                          {:headers {"authorization" "Bearer invented-wire-token"}
                           :throw-exceptions false :socket-timeout 5000 :connection-timeout 5000})]
            (is (= 403 status))
            (is (= "application/json" (get headers "content-type")))
            (is (= "no-store" (get headers "cache-control")))
            (is (= {:message "MCP pilot authorization unavailable."}
                   (try (json/decode+kw body) (catch Exception _ ::invalid-json))))
            (is (zero? @called))))))))

(deftest pilot-early-denials-preserve-http-status-and-privacy-test
  (let [configuration (atom nil)
        fallback (atom 0)
        called (atom 0)
        active {:mode :active :client-ids #{"invented-pilot"}}
        invalid-policy {:mode :invalid-policy :client-ids #{"invented-pilot"}}
        pilot {"authorization" "Bearer invented-pilot-token"}
        unknown {"authorization" "Bearer invented-unknown-token"}
        mixed-key (assoc pilot "x-api-key" "invented-key")
        mixed-session (assoc pilot "x-metabase-session" "invented-session")
        handler (-> (fn [_ respond _]
                      (swap! called inc)
                      (respond {:status 200 :body {:reached true}}))
                    mw.json/wrap-streamed-json-response
                    mw.session/wrap-current-user-info
                    mw.session/wrap-session-key)]
    (with-redefs-fn {#'mcp/pilot-configuration #(deref configuration)
                     #'oauth-server/access-token-client-id
                     (fn [token] (when (= token "invented-pilot-token") "invented-pilot"))
                     #'mw.session/merge-current-user-info
                     (fn [_] (swap! fallback inc) (throw (AssertionError. "Early denial reached auth fallback")))}
      (fn []
        (with-http-handler!
          handler
          (fn [url]
            (doseq [[config method path headers expected message]
                    [[active :get "/api/user/current" pilot 403 "MCP pilot authorization unavailable."]
                     [active :get "/api/user/current" unknown 401 "Bearer authentication unavailable."]
                     [{:mode :invalid-registry} :get "/api/user/current" pilot 503 "MCP pilot configuration unavailable."]
                     [invalid-policy :get "/api/user/current" pilot 503 "MCP pilot configuration unavailable."]
                     [active :get "/api/metabase-mcp" mixed-key 403 "MCP pilot authorization unavailable."]
                     [active :get "/api/metabase-mcp" mixed-session 403 "MCP pilot authorization unavailable."]
                     [active :get "/api/metabase-mcp" (assoc unknown "x-metabase-session" "invented-session")
                      401 "Bearer authentication unavailable."]
                     [active :head "/api/user/current" pilot 403 nil]
                     [active :head "/api/metabase-mcp" mixed-key 403 nil]
                     [active :head "/api/metabase-mcp" mixed-session 403 nil]]]
              (reset! configuration config)
              (let [response (http/request {:method method :url (str url path) :headers headers
                                            :throw-exceptions false :socket-timeout 5000 :connection-timeout 5000})]
                (is (= expected (:status response)))
                (is (= "application/json" (get-in response [:headers "content-type"])))
                (is (= "no-store" (get-in response [:headers "cache-control"])))
                (if (= method :head)
                  (is (empty? (:body response)))
                  (is (= {:message message}
                         (try (json/decode+kw (:body response)) (catch Exception _ ::invalid-json)))))
                (is (zero? @fallback))
                (is (zero? @called))))))))))

(deftest ordinary-session-api-key-and-nonpilot-oauth-still-reach-http-handler-test
  (let [configuration (atom nil)
        called (atom 0)
        active {:mode :active :client-ids #{"invented-pilot"}}
        handler (-> (fn [request respond _]
                      (swap! called inc)
                      (respond {:status 200 :body {:user (:metabase-user-id request)
                                                   :auth-method (:embedding/auth-method request)
                                                   :scopes (:token-scopes request)}}))
                    mw.json/wrap-streamed-json-response
                    mw.session/wrap-current-user-info
                    mw.session/wrap-session-key)]
    (with-redefs-fn {#'mcp/pilot-configuration #(deref configuration)
                     #'oauth-server/access-token-client-id
                     (fn [token] (if (= token "invented-pilot-token") "invented-pilot" "invented-other-client"))
                     #'mw.session/current-user-info-for-session
                     (fn [session _] (when (= session "invented-session") {:metabase-user-id 31}))
                     #'mw.session/current-user-info-for-api-key
                     (fn [key] (when (= key "invented-key") {:metabase-user-id 32}))
                     #'mw.session/current-user-info-for-oauth-token
                     (fn [_] {:metabase-user-id 33 :token-scopes #{"agent:query:execute"}})}
      (fn []
        (with-http-handler!
          handler
          (fn [url]
            (doseq [[config headers user method]
                    [[{:mode :invalid-registry} {"x-metabase-session" "invented-session"} 31 "session"]
                     [{:mode :invalid-registry} {"x-api-key" "invented-key"} 32 "api-key"]
                     [active {"authorization" "Bearer invented-other-token"} 33 "oauth"]
                     [{:mode :off} {"authorization" "Bearer invented-pilot-token"} 33 "oauth"]
                     [active {"authorization" "Bearer invented-other-token" "x-metabase-session" "invented-session"}
                      31 "session"]
                     [active {"authorization" "Bearer invented-other-token" "x-api-key" "invented-key"}
                      32 "api-key"]]]
              (reset! configuration config)
              (reset! called 0)
              (let [response (http/get (str url "/api/user/current")
                                       {:headers headers :throw-exceptions false
                                        :socket-timeout 5000 :connection-timeout 5000})]
                (is (= 200 (:status response)))
                (is (= {:user user :auth-method method :scopes (when (= method "oauth") ["agent:query:execute"])}
                       (json/decode+kw (:body response))))
                (is (= 1 @called))))))))))

(defn- save-access-token!
  "Persist an OAuth access token into the live provider's token store (the one [[oauth-server/resolve-access-token]]
   reads from) for the given user, scopes, and expiry (epoch millis)."
  [token user-id scopes expiry]
  (oidc.store/save-access-token (:token-store (oauth-server/get-provider))
                                token (str user-id) "test-client" (vec scopes) expiry nil))

(defn- revoke-access-token!
  "Revoke a token in the live provider's token store, as the `/oauth/revoke` endpoint does on logout."
  [token]
  (oidc.store/revoke-token (:token-store (oauth-server/get-provider)) token))

;; Wall-clock epoch millis for token expiry timestamps (not duration measurements) — use Date/inst-ms
;; rather than System/currentTimeMillis, matching the oauth-server store tests.
(defn- now-ms [] (inst-ms (java.util.Date.)))
(defn- in-one-hour [] (+ (now-ms) 3600000))
(defn- one-hour-ago [] (- (now-ms) 3600000))

;;; ----------------------------------------- scope mapping (the trust hinge) -----------------------------------------

(deftest oauth-token->token-scopes-test
  (testing "a token carrying the full-access scope maps to the unrestricted sentinel (general REST reachable)"
    (is (= #{::scope/unrestricted}
           (oauth-token->token-scopes #{oauth-server/full-access-scope})))
    (is (= #{::scope/unrestricted}
           (oauth-token->token-scopes #{oauth-server/full-access-scope "agent:query:execute"}))))
  (testing "any narrower scope set is passed through verbatim (only opted-in agent endpoints reachable)"
    (is (= #{"agent:query:execute"}
           (oauth-token->token-scopes #{"agent:query:execute"})))
    (is (= #{} (oauth-token->token-scopes #{})))))

(deftest token-scopes-satisfy-scope-middleware-test
  (testing "the full-access mapping passes endpoints that declare no :scope; a narrow one is rejected"
    (let [reached  (fn [token-scopes]
                     (let [p       (promise)
                           wrapped (scope/ensure-scopes-checked
                                    (fn [_ respond _] (respond {:status 200})))]
                       (wrapped {:token-scopes token-scopes}
                                (fn [resp] (deliver p (:status resp)))
                                (fn [e] (deliver p e)))
                       @p))]
      (is (= 200 (reached (oauth-token->token-scopes #{oauth-server/full-access-scope}))))
      (is (= 403 (reached (oauth-token->token-scopes #{"agent:query:execute"})))))))

;;; -------------------------------------------- end-to-end bridge (DB-backed) ----------------------------------------

;; The bearer bridge builds the OAuth provider (via `get-provider`), whose config derives its
;; issuer/endpoints from `site-url` — unset, that fails the provider's `ProviderSetup` schema. Set
;; it for every test that resolves a token, matching the other oauth-server tests.

(deftest bearer-bridge-full-access-test
  (mt/with-temporary-setting-values [site-url "http://localhost:3000"]
    (t2/with-transaction [_conn nil {:rollback-only true}]
      (let [user-id (mt/user->id :rasta)
            token   (str (random-uuid))]
        (save-access-token! token user-id [oauth-server/full-access-scope] (in-one-hour))
        (let [req (merge-current-user-info (bearer-request token))]
          (testing "resolves the bearer token to the user"
            (is (= user-id (:metabase-user-id req))))
          (testing "marks the request as oauth-authenticated"
            (is (= "oauth" (:embedding/auth-method req))))
          (testing "grants unrestricted token-scopes so the whole REST API is reachable"
            (is (= #{::scope/unrestricted} (:token-scopes req)))))))))

(deftest bearer-bridge-narrow-scope-test
  (mt/with-temporary-setting-values [site-url "http://localhost:3000"]
    (t2/with-transaction [_conn nil {:rollback-only true}]
      (let [user-id (mt/user->id :rasta)
            token   (str (random-uuid))]
        (save-access-token! token user-id ["agent:query:execute"] (in-one-hour))
        (let [req (merge-current-user-info (bearer-request token))]
          (testing "resolves the user but only carries the narrow granted scopes"
            (is (= user-id (:metabase-user-id req)))
            (is (= #{"agent:query:execute"} (:token-scopes req)))))))))

(deftest bearer-bridge-expired-token-test
  (mt/with-temporary-setting-values [site-url "http://localhost:3000"]
    (t2/with-transaction [_conn nil {:rollback-only true}]
      (let [token (str (random-uuid))]
        (save-access-token! token (mt/user->id :rasta) [oauth-server/full-access-scope] (one-hour-ago))
        (let [req (merge-current-user-info (bearer-request token))]
          (testing "an expired access token does not authenticate"
            (is (nil? (:metabase-user-id req)))
            (is (nil? (:token-scopes req)))))))))

(deftest bearer-bridge-unknown-token-test
  (mt/with-temporary-setting-values [site-url "http://localhost:3000"]
    (let [req (merge-current-user-info (bearer-request (str (random-uuid))))]
      (testing "an unknown bearer token does not authenticate"
        (is (nil? (:metabase-user-id req)))
        (is (nil? (:token-scopes req)))))))

(deftest bearer-bridge-revoked-token-test
  (mt/with-temporary-setting-values [site-url "http://localhost:3000"]
    (t2/with-transaction [_conn nil {:rollback-only true}]
      (let [user-id (mt/user->id :rasta)
            token   (str (random-uuid))]
        (save-access-token! token user-id [oauth-server/full-access-scope] (in-one-hour))
        (testing "the token authenticates before it is revoked"
          (is (= user-id (:metabase-user-id (merge-current-user-info (bearer-request token))))))
        (revoke-access-token! token)
        (testing "after revocation (as on logout) the same token no longer authenticates"
          (let [req (merge-current-user-info (bearer-request token))]
            (is (nil? (:metabase-user-id req)))
            (is (nil? (:token-scopes req)))))))))

(deftest bearer-bridge-precedence-test
  (testing "session/api-key auth takes precedence — bearer resolution is not even attempted"
    (let [called? (atom false)]
      (with-redefs [oauth-server/resolve-access-token (fn [_] (reset! called? true) nil)
                    ;; pretend an API key authenticated the request
                    mw.session/current-user-info-for-api-key (fn [_] {:metabase-user-id 99 :is-superuser? false})]
        (let [req (merge-current-user-info {:headers {"authorization" "Bearer anything"
                                                      "x-api-key"     "mb_whatever"}})]
          (is (= 99 (:metabase-user-id req)))
          (is (= "api-key" (:embedding/auth-method req)))
          (is (nil? (:token-scopes req)) "api-key auth must not set token-scopes")
          (is (false? @called?) "bearer token store must not be consulted when api-key already authenticated"))))))
