(ns metabase.mcp.pilot-config-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [metabase.mcp.pilot-config :as config]
   [metabase.mcp.pilot-policy-test :as fixtures]
   [metabase.util.json :as json])
  (:import
   (java.nio.file Files)))

(set! *warn-on-reflection* true)

(defn- configuration! [registry path]
  (with-redefs [config/inputs (constantly {:registry registry :path path})]
    (config/current)))

(deftest absent-and-invalid-registry-test
  (is (= {:mode :off} (configuration! nil nil)))
  (doseq [registry [nil "" " " "[]" "null" "{}" "cli" "[\"*\"]"
                    "[\"cli\",\"cli\"]" "[\"cli\"] null" "[\"cli\"] garbage"
                    "[\"a\",\"b\",\"c\",\"d\",\"e\"]"]]
    (let [c (configuration! registry "/invented/missing/policy.json")]
      (is (= :invalid-registry (:mode c)))
      (is (= :unavailable (config/client-mode c "any-client"))))))

(deftest healthy-registry-survives-broken-policy-test
  (doseq [path [nil "" " " "relative.json" "/invented/missing/policy.json"]]
    (let [c (configuration! "[\"invented-cli\"]" path)]
      (is (= {:mode :invalid-policy :client-ids #{"invented-cli"}} c))
      (is (= :unavailable (config/client-mode c "invented-cli")))
      (is (= :baseline (config/client-mode c "other-client"))))))

(deftest atomic-policy-and-registry-equality-test
  (let [path (Files/createTempFile "nmcp-policy-" ".json" (make-array java.nio.file.attribute.FileAttribute 0))]
    (try
      (spit (str path) (json/encode fixtures/policy))
      (let [c (configuration! "[\"invented-cli\"]" (str path))]
        (is (= :active (:mode c)))
        (is (= fixtures/policy (:policy c)))
        (is (= :pilot (config/client-mode c "invented-cli")))
        (is (= :baseline (config/client-mode c "other-client"))))
      (testing "Registry/policy mismatch and loss never use a cached policy"
        (is (= :invalid-policy (:mode (configuration! "[\"other-client\"]" (str path)))))
        (doseq [content ["" "null" "{}" "[invalid" (str (json/encode fixtures/policy) " null")]]
          (spit (str path) content)
          (is (= :invalid-policy (:mode (configuration! "[\"invented-cli\"]" (str path))))))
        (Files/delete path)
        (is (= :invalid-policy (:mode (configuration! "[\"invented-cli\"]" (str path))))))
      (finally (Files/deleteIfExists path)))))
