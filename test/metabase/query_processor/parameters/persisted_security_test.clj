(ns metabase.query-processor.parameters.persisted-security-test
  "Focused v63 adapter contracts for the upstream82579 persisted-model restriction."
  (:require
   [clojure.test :refer :all]
   [metabase.api.common :as api]
   [metabase.permissions.core :as perms]
   [metabase.query-processor.middleware.persistence :as persistence]
   [metabase.query-processor.parameters.values :as values]))

(deftest persisted-cache-current-authority-test
  (doseq [[sandbox? impersonation? routing? expected]
          [[false false false true]
           [true false false false]
           [false true false false]
           [false false true false]
           [true true true false]]]
    (let [seen (atom [])]
      (binding [api/*current-user-id* 42]
        (with-redefs [perms/sandboxed-user-for-db? (fn [db] (swap! seen conj db) sandbox?)
                      perms/impersonation-enforced-for-db? (fn [db] (swap! seen conj db) impersonation?)
                      perms/row-restricted-by-routing? (fn [db] (swap! seen conj db) routing?)]
          (is (= expected (#'values/persisted-cache-allowed-for-current-user? 17)))
          (is (seq @seen))
          (is (every? #{17} @seen)))))))

(deftest persisted-cache-authority-errors-fail-closed-test
  (binding [api/*current-user-id* 42]
    (with-redefs [perms/sandboxed-user-for-db? (fn [_] (throw (ex-info "authority unavailable" {})))]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"authority unavailable"
                            (#'values/persisted-cache-allowed-for-current-user? 17))))))

(deftest routed-query-does-not-substitute-persisted-cache-test
  (binding [api/*current-user-id* 42]
    (with-redefs [perms/impersonation-enforced-for-db? (constantly false)]
      (let [query {:database 17
                   :destination-database/id 18
                   :stages [{:persisted-info/native "select * from full_cache"}]}
            result (persistence/substitute-persisted-query query)]
        (is (nil? (get-in result [:stages 0 :persisted-info/native])))
        (is (= 18 (:destination-database/id result)))))))
