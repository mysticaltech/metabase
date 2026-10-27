(ns metabase.mcp.native-users-test
  "Active native accounts with real native handlers/stores and invented identities. No deployed-login claim."
  (:require
   [clojure.test :refer [deftest is]]
   [metabase.api.common :as api]
   [metabase.mcp.core :as mcp]
   [metabase.mcp.native-access :as access]
   [metabase.mcp.native-access-db-test :as db]
   [metabase.mcp.native-access-test :as fixture]
   [metabase.mcp.pilot-config :as pilot.config]
   [metabase.mcp.session :as session]
   [metabase.mcp.tools :as tools]
   [metabase.oauth-server.core :as oauth]
   [oidc-provider.protocol :as proto]
   [oidc-provider.store :as oidc.store]
   [toucan2.core :as t2]))

(def native-inputs {:mode "native-users" :users nil})

(deftest explicit-native-user-mode-requires-no-allowlist-or-competing-pilot-test
  (fixture/fixture
   (fn [_ inputs]
     (reset! inputs native-inputs)
     (is (= {:mode :active :audience :active-native-users} (access/current)))
     (doseq [users ["" "[]" "[23,47]" "*" "all"]]
       (reset! inputs (assoc native-inputs :users users))
       (is (= {:mode :invalid} (access/current)))
       (is (= 503 (fixture/status #(access/validate-grant! fixture/grant)))))
     (reset! inputs native-inputs)
     (with-redefs [pilot.config/inputs (constantly {:registry "[]" :path nil})]
       (is (= {:mode :invalid} (access/current)))))))

(deftest any-active-native-account-admitted-without-changing-scope-or-user-state-test
  (fixture/fixture
   (fn [active inputs]
     (reset! inputs native-inputs)
     (swap! active conj 99)
     (doseq [id [23 "23" 47 "47" 99 "99"]
             scopes [["agent:sql:execute"] ["agent:dashboard:create"] (:scope fixture/grant)]]
       (is (true? (access/validate-grant! (assoc fixture/grant :user-id id :scope scopes)))))
     (is (true? (access/ui-user-allowed? 99)))
     (doseq [id [nil 100 "099" " 99" -1 true 99.0 {}]]
       (is (= 403 (fixture/status #(access/validate-grant! (assoc fixture/grant :user-id id))))))
     (doseq [resource [nil [] [fixture/resource fixture/resource] [(str fixture/resource "/")]
                      "https://other.example.invalid/api/metabase-mcp"]]
       (is (= 403 (fixture/status #(access/validate-grant! (assoc fixture/grant :resource resource))))))
     (swap! active disj 99)
     (is (= 403 (fixture/status #(access/validate-grant! (assoc fixture/grant :user-id 99)))))
     (is (false? (boolean (access/ui-user-allowed? 99)))))))

(deftest native-handler-retains-third-account-role-and-full-tool-authority-test
  (fixture/fixture
   (fn [active inputs]
     (reset! inputs native-inputs)
     (swap! active conj 99)
     (let [grant (assoc fixture/grant :user-id 99) seen (atom nil)]
       (with-redefs [oauth/resolve-access-token-details (constantly grant)
                     session/owned-by-user? (constantly true)
                     session/supports-mcp-ui? (constantly false)
                     tools/call-tool (fn [scopes _ tool args _]
                                       (reset! seen [api/*current-user-id* api/*is-superuser?* scopes tool args])
                                       {:content []})]
         (binding [api/*current-user-id* 23 api/*is-superuser?* true]
           (let [request (-> (fixture/request "tools/call")
                             (assoc-in [:headers "mcp-session-id"] (str (random-uuid)))
                             (assoc-in [:body :params] {:name "create_question" :arguments {:name "invented"}}))]
             (is (= 200 (:status (fixture/invoke request))))
             (is (= [99 false (:scopes grant) "create_question" {:name "invented"}] @seen))
             (is (= 403 (:status (fixture/invoke (assoc request :metabase-session-key "invented"))))))))))))

(deftest native-oauth-hooks-and-current-config-remain-mandatory-test
  (fixture/fixture
   (fn [active inputs]
     (reset! inputs native-inputs)
     (swap! active conj 99)
     (is (true? (oauth/validate-pilot-authorization!
                 {:client_id (:client-id fixture/grant) :scope "agent:question:create"
                  :resource [fixture/resource]} 99)))
     (let [captured (access/current)]
       (reset! inputs {:mode nil :users nil})
       (is (= 503 (fixture/status #(access/authorize! captured fixture/grant))))))))

(deftest deactivated-native-user-after-tool-call-withholds-response-test
  (fixture/fixture
   (fn [active inputs]
     (reset! inputs native-inputs)
     (swap! active conj 99)
     (with-redefs [oauth/resolve-access-token-details (constantly (assoc fixture/grant :user-id 99))
                   session/owned-by-user? (constantly true)
                   session/supports-mcp-ui? (constantly false)
                   tools/call-tool (fn [& _] (swap! active disj 99) {:content []})]
       (let [r (-> (fixture/request "tools/call")
                   (assoc-in [:headers "mcp-session-id"] (str (random-uuid)))
                   (assoc-in [:body :params] {:name "query" :arguments {}}))]
         (is (= 403 (:status (fixture/invoke r)))))))))

(deftest real-native-db-all-active-account-token-code-and-refresh-admission-test
  (db/with-owner-db
    (fn [provider]
      (with-redefs [access/inputs (constantly native-inputs)]
        (doseq [id [23 47 99]]
          (let [tokens (db/save-tokens! provider id)
                code (db/save-code! provider id)]
            (is (= id (:user-id (oauth/resolve-access-token (:access tokens)))))
            (is (= (str id) (:user-id (oidc.store/get-refresh-token (:token-store provider) (:refresh tokens)))))
            (is (= (str id) (:user-id (proto/consume-authorization-code (:code-store provider) code))))))
        (is (= 3 (t2/count :core_user)))
        (is (= 0 (t2/count :oauth_authorization_code)))))))

(deftest real-native-db-deactivation-blocks-redemption-refresh-and-resolution-test
  (db/with-owner-db
    (fn [provider]
      (with-redefs [access/inputs (constantly native-inputs)]
        (let [tokens (db/save-tokens! provider 99)
              code (db/save-code! provider 99)]
          (t2/update! :core_user 99 {:is_active false})
          (let [before (db/snapshot)]
            (is (= 403 (db/denied-status #(oauth/resolve-access-token (:access tokens)))))
            (is (= 403 (db/denied-status #(oauth/validate-pilot-token-request!
                                         provider {:client_id "invented-native-client" :grant_type "refresh_token"
                                                   :refresh_token (:refresh tokens)}))))
            (is (= 403 (db/denied-status #(proto/consume-authorization-code (:code-store provider) code))))
            (is (= before (db/snapshot)))))))))

(deftest real-native-db-third-account-cannot-use-or-delete-another-users-session-test
  (db/with-owner-db
    (fn [provider]
      (with-redefs [access/inputs (constantly native-inputs)]
        (let [own (db/save-tokens! provider 23) third (db/save-tokens! provider 99)
              sid (session/create! 23) third-sid (session/create! 99)
              handle (session/store-handle! sid 23 "invented-query")
              before (db/snapshot)]
          (is (= 200 (:status (db/invoke (:access own) sid :post))))
          (is (= 404 (:status (db/invoke (:access third) sid :post))))
          (is (= 404 (:status (db/invoke (:access third) sid :delete))))
          (is (nil? (session/read-handle third-sid 99 handle)))
          (is (= before (db/snapshot))))))))
