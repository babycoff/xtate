#ifndef NOT_FOUND_MONGOC

#include "output-modules.h"
#include "../util-data/file-open.h"
#include "mongodb-output.h"

#include <mongoc/mongoc.h>

#include "../xconf.h"
#include "../version.h"
#include "../globals.h"

#include "../util-out/logger.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"
#include "../util-misc/misc.h"
#include "../pixie/pixie-timer.h"
#include <stdarg.h>

#define DFT_BULK_SIZE 200;

static void mongo_fail(const char *fmt, ...) {
    va_list ap;
    LOG_set_json_error(ERR_OUTPUT_WRITE_FAILED);
    output_mark_fatal();
    char buf[1024];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    LOG(LEVEL_ERROR, "%s", buf);
}

static void mongo_put_binary(bson_t *doc, const char *name, bson_subtype_t subtype,
                       const uint8_t *data, uint32_t len) {
    if (!BSON_APPEND_BINARY(doc, name, subtype, data, len))
        mongo_fail( "(MongodbOut) BSON binary append failed.\n");
}

static void mongo_put_int32(bson_t *doc, const char *name, int32_t v) {
    if (!BSON_APPEND_INT32(doc, name, v))
        mongo_fail( "(MongodbOut) BSON int32 append failed.\n");
}
static void mongo_put_int64(bson_t *doc, const char *name, int64_t v) {
    if (!BSON_APPEND_INT64(doc, name, v))
        mongo_fail( "(MongodbOut) BSON int64 append failed.\n");
}
static void mongo_put_double(bson_t *doc, const char *name, double v) {
    if (!BSON_APPEND_DOUBLE(doc, name, v))
        mongo_fail( "(MongodbOut) BSON double append failed.\n");
}
static void mongo_put_bool(bson_t *doc, const char *name, bool v) {
    if (!BSON_APPEND_BOOL(doc, name, v))
        mongo_fail( "(MongodbOut) BSON bool append failed.\n");
}
static void mongo_put_date(bson_t *doc, const char *name, int64_t v) {
    if (!BSON_APPEND_DATE_TIME(doc, name, v))
        mongo_fail( "(MongodbOut) BSON date append failed.\n");
}

extern Output MongodbOutput; /*for internal x-ref*/
static void mongo_put_utf8(bson_t *doc, const char *name, const char *value);

static char format_time[32];

struct MongodbConf {
    char                    *db_name;
    char                    *col_name;
    char                    *app_name;
    mongoc_uri_t            *uri;
    mongoc_client_t         *client;
    mongoc_database_t       *database;
    mongoc_collection_t     *collection;
    mongoc_bulk_operation_t *bulk;
    bson_t                  *bulk_opts;
    bson_t                  *bulk_insert_opts;
    unsigned                 bulk_idx;
    unsigned                 bulk_size;
    uint64_t                 bulk_failed;
    unsigned                 retry_count;
    unsigned                 retry_delay_ms;
    unsigned                 retry_count_set : 1;
    unsigned                 retry_delay_set : 1;
    unsigned                 is_bulk    : 1;
    unsigned                 is_compact : 1;
};

static struct MongodbConf mongodb_conf = {0};

static ConfRes SET_bulk_size(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    mongodb_conf.bulk_size = conf_parse_int(value);
    mongodb_conf.is_bulk   = 1;

    return Conf_OK;
}

static ConfRes SET_is_bulk(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    mongodb_conf.is_bulk = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_app_name(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(mongodb_conf.app_name);
    mongodb_conf.app_name = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_col_name(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(mongodb_conf.col_name);
    mongodb_conf.col_name = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_db_name(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    FREE(mongodb_conf.db_name);
    mongodb_conf.db_name = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_compact(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    mongodb_conf.is_compact = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_retry_count(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    mongodb_conf.retry_count     = conf_parse_int(value);
    mongodb_conf.retry_count_set = 1;
    return Conf_OK;
}

static ConfRes SET_retry_delay(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    mongodb_conf.retry_delay_ms  = conf_parse_int(value);
    mongodb_conf.retry_delay_set = 1;
    return Conf_OK;
}

static ConfParam mongodb_parameters[] = {
    {"database-name",
     SET_db_name,
     Type_ARG,
     {"db-name", "database", "db", 0},
     "Specifies the database name to use. Default is " XTATE_NAME "."},
    {"collection-name",
     SET_col_name,
     Type_ARG,
     {"col-name", "collection", "col", 0},
     "Specifies the collection name to store. Default is a timestamp of scan "
     "beginning."},
    {"application-name",
     SET_app_name,
     Type_ARG,
     {"app-name", "application", "app", 0},
     "Specifies the application name to register for tracking in the profile "
     "logs in MongoDB. Default is " XTATE_NAME " with version."},
    {"insert-bulk",
     SET_is_bulk,
     Type_FLAG,
     {"bulk-insert", "bulk", 0},
     "Insert results into MongoDB in bulks. This may improve the inserting "
     "performance sometimes."},
    {"bulk-size",
     SET_bulk_size,
     Type_ARG,
     {0},
     "Insert results into MongoDB in bulks and specify the bulk size. Default "
     "is 200."},
    {"compact-mode",
     SET_compact,
     Type_FLAG,
     {"compact", 0},
     "Record time, IP proto, IP addr and level field as compacted number type "
     "instead of string. This will reduce the size of the result file.\n"
     "NOTE: IPv4 addr will save as an int32 number. IPv6 addr will save as two"
     " int64 number. Level field will save to an int32 as 'information' for 0, "
     "'failure' for 1 and 'success' for 2. Time and IP proto will save as an "
     "int32 number,."},
    {"retry-count",
     SET_retry_count,
     Type_ARG,
     {"retry", 0},
     "Number of retries after a MongoDB write fails (default 3). A value of 0 "
     "disables retries."},
    {"retry-delay",
     SET_retry_delay,
     Type_ARG,
     {"retry-delay-ms", 0},
     "Delay in milliseconds between MongoDB write retries (default 1000)."},
    {0}};

static bool _init_and_test_db(const char *uri_name, const char *db_name,
                              const char *col_name, const char *app_name) {
    char         tm_buf[80];
    bool         retval;
    bson_error_t error;
    bson_t      *test_ping;
    bson_t      *test_insert;
    bson_t      *test_remove;
    bson_t       reply;
    bson_oid_t   oid;
    const char  *final_db_name;
    const char  *final_col_name;
    const char  *final_app_name;

    /*
     * Required to initialize libmongoc's internals
     */
    mongoc_init();

    /*
     * Safely create a MongoDB URI object from the given string
     */
    mongodb_conf.uri = mongoc_uri_new_with_error(uri_name, &error);
    if (!mongodb_conf.uri) {
        mongo_fail( "(MongoDB) failed to parse URI[%s]: %s\n", uri_name,
            error.message);
        return false;
    }

    /* Keep an outage bounded: without these, libmongoc can block for its
     * default 30s server-selection window, which is longer than the scan's
     * retry policy and makes failure handling unpredictable. */
    mongoc_uri_set_option_as_int32(mongodb_conf.uri,
                                   MONGOC_URI_SERVERSELECTIONTIMEOUTMS, 1000);
    mongoc_uri_set_option_as_int32(mongodb_conf.uri,
                                   MONGOC_URI_CONNECTTIMEOUTMS, 1000);
    mongoc_uri_set_option_as_int32(mongodb_conf.uri,
                                   MONGOC_URI_SOCKETTIMEOUTMS, 2000);
    mongoc_uri_set_option_as_bool(mongodb_conf.uri, MONGOC_URI_RETRYWRITES,
                                  false);
    mongoc_uri_set_option_as_bool(mongodb_conf.uri, MONGOC_URI_RETRYREADS,
                                  false);
    mongoc_uri_set_option_as_bool(mongodb_conf.uri,
                                  MONGOC_URI_SERVERSELECTIONTRYONCE, true);


    /*
     * Create a new client instance
     */
    mongodb_conf.client = mongoc_client_new_from_uri(mongodb_conf.uri);
    if (!mongodb_conf.client) {
        mongo_fail( "(MongoDB) failed to create a new client instance.\n");
        return false;
    }

    /*
     * Register the application name so we can track it in the profile logs
     * on the server. This can also be done from the URI.
     */
    if (app_name && app_name[0]) {
        final_app_name = app_name;
    } else {
        final_app_name = XTATE_WITH_VERSION;
    }
    if (!mongoc_client_set_appname(mongodb_conf.client, final_app_name)) {
        mongo_fail( "(MongoDB) failed to set appname: %s\n",
            final_app_name);
        return false;
    }

    /*
     * Get a handle on the database "db_name" and collection "coll_name"
     */
    if (db_name && db_name[0]) {
        final_db_name = db_name;
    } else {
        final_db_name = XTATE_NAME;
    }
    mongodb_conf.database =
        mongoc_client_get_database(mongodb_conf.client, final_db_name);
    if (col_name && col_name[0]) {
        final_col_name = col_name;
    } else {
        struct tm *timeinfo;
        time_t     now = global_get_time();
        timeinfo       = localtime(&now);
        strftime(tm_buf, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
        final_col_name = tm_buf;
    }
    mongodb_conf.collection = mongoc_client_get_collection(
        mongodb_conf.client, final_db_name, final_col_name);

    /*
     * Test server alive by pinging the database
     */
    test_ping = BCON_NEW("ping", BCON_INT32(1));
    retval    = mongoc_client_command_simple(mongodb_conf.client, "admin",
                                             test_ping, NULL, &reply, &error);
    if (!retval) {
        mongo_fail( "(MongoDB ping test) %s(%u)\n", error.message,
            error.code);
        return false;
    }
    bson_destroy(&reply);

    /*
     * Test data inserting
     */
    bson_oid_init(&oid, NULL);
    test_insert = bson_new();
    mongo_put_utf8(test_insert, "hello", XTATE_NAME);
    BSON_APPEND_OID(test_insert, "_id", &oid);
    if (!mongoc_collection_insert_one(mongodb_conf.collection, test_insert,
                                      NULL, NULL, &error)) {
        mongo_fail( "(MongoDB insert test) %s(%u)\n", error.message,
            error.code);
        return false;
    }

    /*
     * Test data removing by the way
     */
    test_remove = bson_new();
    BSON_APPEND_OID(test_remove, "_id", &oid);
    if (!mongoc_collection_delete_one(mongodb_conf.collection, test_remove,
                                      NULL, &reply, &error)) {
        mongo_fail( "(MongoDB remove test) %s(%u)\n", error.message,
            error.code);
        return false;
    }

    /*
     * prepare for bulk inserting
     */
    if (mongodb_conf.is_bulk) {
        mongodb_conf.bulk_opts = bson_new();
        mongo_put_bool(mongodb_conf.bulk_opts, "ordered", false);
        mongodb_conf.bulk = mongoc_collection_create_bulk_operation_with_opts(
            mongodb_conf.collection, mongodb_conf.bulk_opts);

        if (!mongodb_conf.bulk_size)
            mongodb_conf.bulk_size = DFT_BULK_SIZE;

        mongodb_conf.bulk_insert_opts = bson_new();
        mongo_put_bool(mongodb_conf.bulk_insert_opts, "validate", false);
    }

    bson_destroy(test_ping);
    bson_destroy(test_insert);
    bson_destroy(test_remove);
    bson_destroy(&reply);

    return true;
}

static void _close_and_clean_db() {
    if (mongodb_conf.bulk_failed)
        mongo_fail( "(MongodbOut) %" PRIu64
                         " documents were not stored\n",
            mongodb_conf.bulk_failed);
    if (mongodb_conf.bulk) {
        if (mongodb_conf.is_bulk && mongodb_conf.bulk_idx) {
            bson_error_t error;
            bool         ret =
                mongoc_bulk_operation_execute(mongodb_conf.bulk, NULL, &error);
            if (!ret) {
                mongodb_conf.bulk_failed += mongodb_conf.bulk_idx;
                mongo_fail( "(MongoDB %s) %s\n", __func__, error.message);
            }
        }
        mongoc_bulk_operation_destroy(mongodb_conf.bulk);
        mongodb_conf.bulk     = NULL;
        mongodb_conf.bulk_idx = 0;
    }
    if (mongodb_conf.bulk_opts) {
        bson_destroy(mongodb_conf.bulk_opts);
        mongodb_conf.bulk_opts = NULL;
    }
    if (mongodb_conf.bulk_insert_opts) {
        bson_destroy(mongodb_conf.bulk_insert_opts);
        mongodb_conf.bulk_insert_opts = NULL;
    }
    if (mongodb_conf.collection) {
        mongoc_collection_destroy(mongodb_conf.collection);
        mongodb_conf.collection = NULL;
    }
    if (mongodb_conf.database) {
        mongoc_database_destroy(mongodb_conf.database);
        mongodb_conf.database = NULL;
    }
    if (mongodb_conf.uri) {
        mongoc_uri_destroy(mongodb_conf.uri);
        mongodb_conf.uri = NULL;
    }
    if (mongodb_conf.client) {
        mongoc_client_destroy(mongodb_conf.client);
        mongodb_conf.client = NULL;
    }
    mongoc_cleanup();
}

static bool mongodbout_init(const XConf *xconf, const OutConf *out) {
    if (!mongodb_conf.retry_count_set)
        mongodb_conf.retry_count = 3;
    if (!mongodb_conf.retry_delay_set)
        mongodb_conf.retry_delay_ms = 1000;

    if (!_init_and_test_db(out->output_filename, mongodb_conf.db_name,
                           mongodb_conf.col_name, mongodb_conf.app_name)) {
        _close_and_clean_db();
        return false;
    }

    return true;
}

static void _mongo_retry_sleep(unsigned delay_ms) {
    if (delay_ms)
        pixie_usleep(delay_ms * 1000U);
}

/*
 * mongoc_bulk_operation_execute() may only be called once per bulk operation:
 * the driver marks the operation as executed, so a second call on the same
 * handle can never succeed. Retrying a *failed* bulk execute is therefore
 * pointless -- re-running it would only hide the first error. Report the
 * failure explicitly and mark the sink fatal so the scan stops and the exit
 * status is non-zero. (Single-document inserts above are retried because the
 * driver permits repeating them.)
 */
static bool _mongo_bulk_execute_with_retry(void) {
    bson_error_t error;

    if (mongoc_bulk_operation_execute(mongodb_conf.bulk, NULL, &error))
        return true;

    mongo_fail("(MongodbOut execute) %s; a failed bulk operation cannot be "
               "retried because libmongoc marks the bulk operation as "
               "executed. Queued results were not stored.\n",
               error.message);
    output_mark_fatal();
    return false;
}

static bool _mongo_insert_one_with_retry(const bson_t *doc) {
    bson_error_t error;
    unsigned     attempts = mongodb_conf.retry_count + 1;

    for (unsigned attempt = 0; attempt < attempts; attempt++) {
        if (mongoc_collection_insert_one(mongodb_conf.collection, doc, NULL,
                                         NULL, &error))
            return true;

        mongo_fail( "(MongodbOut insert) attempt %u/%u: %s: %u\n",
            attempt + 1, attempts, error.message, error.code);
        if (attempt + 1 < attempts)
            _mongo_retry_sleep(mongodb_conf.retry_delay_ms);
    }

    mongo_fail(
        "(MongodbOut insert) retries exhausted; output is incomplete\n");
    output_mark_fatal();
    return false;
}

static void mongo_put_utf8(bson_t *doc, const char *name, const char *value) {
    if (!BSON_APPEND_UTF8(doc, name, value))
        mongo_fail( "(MongodbOut) could not append UTF-8 field %s.\n", name);
}

static void mongodbout_result(OutItem *item) {
    /* Once the sink is marked fatal, do not spend another retry window on each
     * queued result while the scan is shutting down. */
    if (output_has_fatal_error())
        return;

    DataLink    *pre;
    bool         ret;
    bson_error_t error;
    bson_t       scan_report_doc;
    bson_t       probe_report_doc;
    bson_t       output_report_doc;
    bson_t      *res_doc = bson_new();
    if (!res_doc) {
        mongo_fail( "(MongodbOut) could not allocate result document.\n");
        return;
    }

    /**
     * Add _id at first.
     * Or let MongoDB add it automatically.
     * */
    // bson_oid_t   oid;
    // bson_oid_init(&oid, NULL);
    // BSON_APPEND_OID(res_doc, "_id", &oid);

    if (mongodb_conf.is_compact) {
        mongo_put_date(res_doc, "time",
                              (uint64_t)item->timestamp * 1000);
        mongo_put_int32(res_doc, "level", item->level);
        mongo_put_int32(res_doc, "ip_proto", item->target.ip_proto);
        if (item->target.ip_them.version == 4) {
            mongo_put_int32(res_doc, "ip_them", item->target.ip_them.ipv4);
            mongo_put_int32(res_doc, "ip_me", item->target.ip_me.ipv4);
        } else {
            mongo_put_int64(res_doc, "ip_them_hi",
                              item->target.ip_them.ipv6.hi);
            mongo_put_int64(res_doc, "ip_them_lo",
                              item->target.ip_them.ipv6.lo);
            mongo_put_int64(res_doc, "ip_me_hi", item->target.ip_me.ipv6.hi);
            mongo_put_int64(res_doc, "ip_me_lo", item->target.ip_me.ipv6.lo);
        }
    } else {
        safe_iso8601_time(format_time, sizeof(format_time), &item->timestamp);
        mongo_put_utf8(res_doc, "time", format_time);
        mongo_put_utf8(res_doc, "level", output_level_to_string(item->level));
        mongo_put_utf8(res_doc, "ip_proto",
                         ip_proto_to_string(item->target.ip_proto));
        ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->target.ip_them);
        ipaddress_formatted_t ip_me_fmt   = ipaddress_fmt(item->target.ip_me);
        mongo_put_utf8(res_doc, "ip_them", ip_them_fmt.string);
        mongo_put_utf8(res_doc, "ip_me", ip_me_fmt.string);
    }

    if (!item->no_port) {
        mongo_put_int32(res_doc, "port_them", item->target.port_them);
        mongo_put_int32(res_doc, "port_me", item->target.port_me);
    }

    if (item->classification[0]) {
        mongo_put_utf8(res_doc, "classification", item->classification);
    }

    if (item->reason[0]) {
        mongo_put_utf8(res_doc, "reason", item->reason);
    }

    pre = item->scan_report.link;
    if (pre->next) {
        bson_append_document_begin(res_doc, "scan report", -1,
                                   &scan_report_doc);
        while (pre->next) {
            if (pre->next->link_type == LinkType_String) {
                mongo_put_utf8(&scan_report_doc, pre->next->name,
                                 (char *)pre->next->value_data);
            } else if (pre->next->link_type == LinkType_Int) {
                mongo_put_int64(&scan_report_doc, pre->next->name,
                                  pre->next->value_int);
            } else if (pre->next->link_type == LinkType_Double) {
                mongo_put_double(&scan_report_doc, pre->next->name,
                                   pre->next->value_double);
            } else if (pre->next->link_type == LinkType_Bool) {
                mongo_put_bool(&scan_report_doc, pre->next->name,
                                 pre->next->value_bool);
            } else if (pre->next->link_type == LinkType_Binary) {
                mongo_put_binary(&scan_report_doc, pre->next->name,
                                   BSON_SUBTYPE_BINARY, pre->next->value_data,
                                   pre->next->data_len);
            }

            pre = pre->next;
        }
        bson_append_document_end(res_doc, &scan_report_doc);
        bson_destroy(&scan_report_doc);
    }

    pre = item->probe_report.link;
    if (pre->next) {
        bson_append_document_begin(res_doc, "probe report", -1,
                                   &probe_report_doc);
        while (pre->next) {
            if (pre->next->link_type == LinkType_String) {
                mongo_put_utf8(&probe_report_doc, pre->next->name,
                                 (char *)pre->next->value_data);
            } else if (pre->next->link_type == LinkType_Int) {
                mongo_put_int64(&probe_report_doc, pre->next->name,
                                  pre->next->value_int);
            } else if (pre->next->link_type == LinkType_Double) {
                mongo_put_double(&probe_report_doc, pre->next->name,
                                   pre->next->value_double);
            } else if (pre->next->link_type == LinkType_Bool) {
                mongo_put_bool(&probe_report_doc, pre->next->name,
                                 pre->next->value_bool);
            } else if (pre->next->link_type == LinkType_Binary) {
                mongo_put_binary(&probe_report_doc, pre->next->name,
                                   BSON_SUBTYPE_BINARY, pre->next->value_data,
                                   pre->next->data_len);
            }

            pre = pre->next;
        }
        bson_append_document_end(res_doc, &probe_report_doc);
        bson_destroy(&probe_report_doc);
    }

    pre = item->output_report.link;
    if (pre->next) {
        bson_append_document_begin(res_doc, "output report", -1,
                                   &output_report_doc);
        while (pre->next) {
            if (pre->next->link_type == LinkType_String) {
                mongo_put_utf8(&output_report_doc, pre->next->name,
                                 (char *)pre->next->value_data);
            } else if (pre->next->link_type == LinkType_Int) {
                mongo_put_int64(&output_report_doc, pre->next->name,
                                  pre->next->value_int);
            } else if (pre->next->link_type == LinkType_Double) {
                mongo_put_double(&output_report_doc, pre->next->name,
                                   pre->next->value_double);
            } else if (pre->next->link_type == LinkType_Bool) {
                mongo_put_bool(&output_report_doc, pre->next->name,
                                 pre->next->value_bool);
            } else if (pre->next->link_type == LinkType_Binary) {
                mongo_put_binary(&output_report_doc, pre->next->name,
                                   BSON_SUBTYPE_BINARY, pre->next->value_data,
                                   pre->next->data_len);
            }

            pre = pre->next;
        }
        bson_append_document_end(res_doc, &output_report_doc);
        bson_destroy(&output_report_doc);
    }

    /**
     * Insert the documantation in bulks or one by one.
     * */
    if (mongodb_conf.is_bulk) {
        /*flush if bulk is full*/
        if (mongodb_conf.bulk_idx >= mongodb_conf.bulk_size) {
            if (!_mongo_bulk_execute_with_retry())
                mongodb_conf.bulk_failed += mongodb_conf.bulk_idx;
            mongoc_bulk_operation_destroy(mongodb_conf.bulk);
            mongodb_conf.bulk =
                mongoc_collection_create_bulk_operation_with_opts(
                    mongodb_conf.collection, mongodb_conf.bulk_opts);
            mongodb_conf.bulk_idx = 0;
        }
        /*then add new result*/
        ret = mongoc_bulk_operation_insert_with_opts(
            mongodb_conf.bulk, res_doc, mongodb_conf.bulk_insert_opts, &error);
        if (!ret) {
            mongodb_conf.bulk_failed++;
            mongo_fail( "(MongodbOut bulk insert) %s\n", error.message);
        } else {
            mongodb_conf.bulk_idx++;
        }
    } else {
        _mongo_insert_one_with_retry(res_doc);
    }

    bson_destroy(res_doc);

    return;
}

static void mongodbout_close(const OutConf *out) { _close_and_clean_db(); }

Output MongodbOutput = {
    .name       = "mongodb",
    .need_file  = true,
    .params     = mongodb_parameters,
    .short_desc = "Save results to MongoDB.",
    .desc = "MongodbOutput save results in MongoDB. MongoDB is a popular, "
            "open-source NoSQL database that uses a document-oriented data "
            "model. It is known for its high performance, high availability, "
            "and easy scalability. MongoDB stores data in flexible, BSON "
            "documents(JSON-like), which makes it easy and suitable to store "
            "results from " XTATE_NAME_TITLE_CASE "."
            "NOTE1: MongodbOutput saves all results as a series of BSON "
            "documents to MongoDB.\n"
            "NOTE2: MongodbOutput could save complete binary type fields in "
            "results.\n"
            "NOTE3: " XTATE_NAME_TITLE_CASE
            " could decode result file from BsonOutput to MongoDB with "
            "`--store-bson` parameter.\n"
            "Dependencies: libmongoc.",

    .init_cb   = &mongodbout_init,
    .result_cb = &mongodbout_result,
    .close_cb  = &mongodbout_close,
};

/**
 * @return is stored successful.
 */
static bool _store_bson_to_db(const uint8_t *bson_data, size_t bson_len) {
    bson_t       bson_doc;
    bson_error_t error;
    bool         is_success = true;

    if (!bson_init_static(&bson_doc, bson_data, bson_len)) {
        mongo_fail( "(StoreBson) Failed to initialize BSON document.\n");
        is_success = false;
        goto bson_to_db_err1;
    }

    /*Insert the documantation*/
    if (!mongoc_collection_insert_one(mongodb_conf.collection, &bson_doc, NULL,
                                      NULL, &error)) {
        mongo_fail( "(StoreBson insert) %s: %u\n", error.message,
            error.code);
        is_success = false;
    }

    bson_destroy(&bson_doc);

bson_to_db_err1:
    return is_success;
}

void store_bson_file(const char *filename, const char *uri_name,
                     const char *db_name, const char *col_name,
                     const char *app_name) {

    FILE *bsonfile = file_open_utf8_mode(filename, "rb");
    if (bsonfile == NULL) {
        mongo_fail( "(StoreBson) could not open BSON file %s.\n",
            filename);
        LOGPERROR(filename);
        return;
    }

    if (!_init_and_test_db(uri_name, db_name, col_name, app_name)) {
        _close_and_clean_db();
        return;
    }

    LOG(LEVEL_HINT, "(StoreBson) start inserting result data...\n");

    uint64_t store_count = 0;
    while (true) {
        /*read the first 4 bytes as length of a BSON doc*/
        uint32_t doc_length = 0;
        size_t   read_size  = fread(&doc_length, 1, 4, bsonfile);
        if (read_size == 0) {
            /*EOF*/
            break;
        } else if (read_size < 4) {
            mongo_fail(
                "(StoreBson) Incomplete length field. Corrupted file?\n");
            break;
        }

        /*get real doc len*/
        doc_length = BSON_UINT32_FROM_LE(doc_length);

        /*the shortest doc len; cap to avoid a corrupt 4GB allocation*/
        if (doc_length < 5 || doc_length > 16 * 1024 * 1024) {
            mongo_fail( "(StoreBson) Invalid BSON document length: %u\n",
                doc_length);
            break;
        }

        // read remaining doc data
        size_t   remaining = doc_length - 4;
        uint8_t *bson_data = MALLOC(doc_length);
        if (!bson_data) {
            mongo_fail( "(StoreBson) out of memory for BSON document\n");
            break;
        }

        // contains the len field
        ((uint32_t *)bson_data)[0] = BSON_UINT32_TO_LE(doc_length);

        read_size = fread(bson_data + 4, 1, remaining, bsonfile);
        if (read_size < remaining) {
            mongo_fail(
                "(StoreBson) Incomplete BSON document. Expected %zu bytes, got "
                "%zu bytes.\n",
                remaining, read_size);
            FREE(bson_data);
            break;
        }

        // print BSON as JSON
        if (_store_bson_to_db(bson_data, doc_length))
            store_count++;

        FREE(bson_data);
    }

    LOG(LEVEL_HINT, "(StoreBson) %" PRIu64 " results insertion is complete!\n",
        store_count);

    _close_and_clean_db();
    if (fclose(bsonfile) != 0)
        mongo_fail("(StoreBson) could not close BSON file.\n");
}

/**
 * @return is stored successful.
 */
static bool _store_json_to_db(const char *json_string) {
    bson_t      *bson_doc;
    bson_error_t error;
    bool         is_success = true;

    bson_doc = bson_new_from_json((const uint8_t *)json_string, -1, &error);
    if (!bson_doc) {
        mongo_fail( "(StoreJson transform) %s\n", error.message);
        is_success = false;
        goto json_to_db_err1;
    }

    /*Insert the documantation*/
    if (!mongoc_collection_insert_one(mongodb_conf.collection, bson_doc, NULL,
                                      NULL, &error)) {
        mongo_fail( "(StoreJson insert) %s: %u\n", error.message,
            error.code);
    }

    bson_destroy(bson_doc);

json_to_db_err1:
    return is_success;
}

void store_json_file(const char *filename, const char *uri_name,
                     const char *db_name, const char *col_name,
                     const char *app_name) {

    FILE *jsonfile = file_open_utf8_mode(filename, "rb");
    if (jsonfile == NULL) {
        mongo_fail( "(StoreJson) could not open NDJSON file %s.\n",
            filename);
        LOGPERROR(filename);
        return;
    }

    if (!_init_and_test_db(uri_name, db_name, col_name, app_name)) {
        _close_and_clean_db();
        return;
    }

    LOG(LEVEL_HINT, "(StoreJson) start inserting result data...\n");

    /*the result size can be large if it contains banner data*/
    uint64_t store_count = 0;
    char     line[65536 * 4];
    while (true) {
        char *s = fgets(line, sizeof(line), jsonfile);

        if (s == NULL) {
            if (ferror(jsonfile))
                LOG(LEVEL_DEBUG, "(StoreJson) error of file.\n");
            else if (feof(jsonfile))
                LOG(LEVEL_DEBUG, "(StoreJson) EOF of file.\n");
            break;
        }

        /*absolute null line or the last line*/
        if (s[0] == '\n' || s[0] == '\r') {
            continue;
        }

        if (_store_json_to_db(s))
            store_count++;
    }

    LOG(LEVEL_HINT, "(StoreJson) %" PRIu64 " results insertion is complete!\n",
        store_count);

    _close_and_clean_db();
    if (fclose(jsonfile) != 0)
        mongo_fail("(StoreJson) could not close NDJSON file.\n");
}

#endif