(ns metabase.app-db.patch-backout-test
  (:require
   [clj-yaml.core :as yaml]
   [clojure.java.io :as io]
   [clojure.test :refer [deftest is testing]]))

(set! *warn-on-reflection* true)

(defn- resource-collection-index-changeset []
  (->> (yaml/parse-string (slurp (io/resource "migrations/065/20261006_data_app_resource_collection.yaml")))
       :databaseChangeLog
       (keep :changeSet)
       (filter #(= "v65.2026-10-06T00:00:00" (:id %)))
       first))

(deftest ^:parallel existing-resource-collection-index-backout-guard-test
  (let [changeset (resource-collection-index-changeset)]
    (testing "A patch backout must not recreate the retained PostgreSQL index"
      (is (= "postgresql" (:dbms changeset)))
      (is (= [{:onFail "MARK_RAN"}
              {:not [{:indexExists {:tableName "data_app"
                                   :indexName "idx_data_app_resource_collection_id"}}]}]
             (:preConditions changeset))))))

(deftest ^:parallel original-resource-collection-index-ddl-is-preserved-test
  (let [changeset (resource-collection-index-changeset)]
    (is (= "v65.2026-10-06T00:00:00" (:id changeset)))
    (is (= "timofei" (:author changeset)))
    (is (= [{:createIndex {:tableName "data_app"
                          :indexName "idx_data_app_resource_collection_id"
                          :columns [{:column {:name "resource_collection_id"}}]}}]
           (:changes changeset)))
    (is (= [{:dropIndex {:tableName "data_app"
                        :indexName "idx_data_app_resource_collection_id"}}]
           (:rollback changeset)))))
