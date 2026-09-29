#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "goose_publisher.h"
#include "goose_receiver.h"
#include "goose_subscriber.h"
#include "mms_value.h"

#define LAB_APP_ID_DEFAULT 0x3e14U
#define LAB_GOCB_REF_DEFAULT "labBus14/LLN0$GO$Bus14Gen"
#define LAB_DATASET_REF_DEFAULT "labBus14/LLN0$Bus14GenDS"
#define LAB_GO_ID_DEFAULT "labBus14Bus1Gen"
#define LAB_MAC_DEFAULT "01:0c:cd:01:01:14"
#define LAB_MAC_TEXT_SIZE 18U
#define LAB_REFERENCE_MAX 129U
#define BUS1_PG_MW 232.4F
#define BUS1_QG_MVAR (-16.9F)
#define BUS1_VG_PU 1.06F
#define TEST_PG_MW 232.5F
#define DEFAULT_INTERVAL_MS 1000U
#define MIN_INTERVAL_MS 100U
#define MAX_INTERVAL_MS 60000U

static volatile sig_atomic_t stop_requested;
static atomic_uint_fast64_t observed_count = ATOMIC_VAR_INIT(0U);
static atomic_uint_fast64_t received_count = ATOMIC_VAR_INIT(0U);

typedef struct
{
    const char* mode;
    const char* interface_name;
    const char* go_cb_ref;
    const char* dataset_ref;
    const char* go_id;
    uint16_t app_id;
    uint8_t destination_mac[6];
    uint64_t count;
    uint32_t interval_ms;
    bool test_mode;
    bool interval_specified;
} app_options_t;

static void request_stop(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static bool install_signal_handlers(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = request_stop;
    if (sigemptyset(&action.sa_mask) != 0)
    {
        return false;
    }

    return (sigaction(SIGINT, &action, NULL) == 0) &&
           (sigaction(SIGTERM, &action, NULL) == 0);
}

static void print_usage(FILE* stream, const char* program_name)
{
    fprintf(
        stream,
        "Usage:\n"
        "  %s pub --interface IFACE [options]\n"
        "  %s sub --interface IFACE [options]\n\n"
        "Shared options (use the same values in pub and sub):\n"
        "  --app-id HEX          default 0x%04x (lab GOOSE range)\n"
        "  --dst-mac MAC         default %s\n"
        "  --gocb-ref REF        default %s\n"
        "  --dataset-ref REF     default %s\n"
        "  --go-id ID            default %s\n"
        "  --count N             stop after N messages; 0 means until signal\n"
        "Publisher options:\n"
        "  --interval-ms N       repeat interval, %u..%u (default %u)\n"
        "  --test                change Pg once after first publish\n",
        program_name, program_name, LAB_APP_ID_DEFAULT, LAB_MAC_DEFAULT,
        LAB_GOCB_REF_DEFAULT, LAB_DATASET_REF_DEFAULT, LAB_GO_ID_DEFAULT,
        MIN_INTERVAL_MS, MAX_INTERVAL_MS, DEFAULT_INTERVAL_MS);
}

static bool parse_unsigned(const char* text, int base, uint64_t maximum,
                           uint64_t* value)
{
    char* end = NULL;
    unsigned long long parsed;

    if ((text == NULL) || (text[0] == '\0') || (text[0] == '-'))
    {
        return false;
    }

    errno = 0;
    parsed = strtoull(text, &end, base);
    if ((errno != 0) || (end == text) || (*end != '\0') ||
        ((uint64_t)parsed > maximum))
    {
        return false;
    }

    *value = (uint64_t)parsed;
    return true;
}

static int hex_digit_value(char digit)
{
    if ((digit >= '0') && (digit <= '9'))
    {
        return digit - '0';
    }

    if ((digit >= 'a') && (digit <= 'f'))
    {
        return digit - 'a' + 10;
    }

    if ((digit >= 'A') && (digit <= 'F'))
    {
        return digit - 'A' + 10;
    }

    return -1;
}

static bool parse_mac_address(const char* text, uint8_t address[6])
{
    if ((text == NULL) || (strlen(text) != (LAB_MAC_TEXT_SIZE - 1U)))
    {
        return false;
    }

    for (size_t index = 0U; index < 6U; index++)
    {
        size_t offset = index * 3U;
        int high = hex_digit_value(text[offset]);
        int low = hex_digit_value(text[offset + 1U]);

        if ((high < 0) || (low < 0) ||
            ((index < 5U) && (text[offset + 2U] != ':')))
        {
            return false;
        }

        address[index] =
            (uint8_t)(((unsigned int)high << 4U) | (unsigned int)low);
    }

    return (address[0] & 0x01U) != 0U;
}

static bool parse_options(int argc, char** argv, app_options_t* options)
{
    if ((argc < 2) ||
        ((strcmp(argv[1], "pub") != 0) && (strcmp(argv[1], "sub") != 0)))
    {
        return false;
    }

    options->mode = argv[1];
    options->interface_name = NULL;
    options->go_cb_ref = LAB_GOCB_REF_DEFAULT;
    options->dataset_ref = LAB_DATASET_REF_DEFAULT;
    options->go_id = LAB_GO_ID_DEFAULT;
    options->app_id = LAB_APP_ID_DEFAULT;
    options->count = 0U;
    options->interval_ms = DEFAULT_INTERVAL_MS;
    options->test_mode = false;
    options->interval_specified = false;

    if (!parse_mac_address(LAB_MAC_DEFAULT, options->destination_mac))
    {
        return false;
    }

    for (int index = 2; index < argc; index++)
    {
        const char* option = argv[index];
        const char* value = NULL;
        uint64_t parsed = 0U;

        if (strcmp(option, "--test") == 0)
        {
            options->test_mode = true;
            continue;
        }

        if ((index + 1) >= argc)
        {
            return false;
        }
        value = argv[++index];

        if (strcmp(option, "--interface") == 0)
        {
            options->interface_name = value;
        }
        else if (strcmp(option, "--app-id") == 0)
        {
            if (!parse_unsigned(value, 0, 0x3fffU, &parsed))
            {
                return false;
            }
            options->app_id = (uint16_t)parsed;
        }
        else if (strcmp(option, "--dst-mac") == 0)
        {
            if (!parse_mac_address(value, options->destination_mac))
            {
                return false;
            }
        }
        else if (strcmp(option, "--gocb-ref") == 0)
        {
            options->go_cb_ref = value;
        }
        else if (strcmp(option, "--dataset-ref") == 0)
        {
            options->dataset_ref = value;
        }
        else if (strcmp(option, "--go-id") == 0)
        {
            options->go_id = value;
        }
        else if (strcmp(option, "--count") == 0)
        {
            if (!parse_unsigned(value, 10, UINT64_MAX, &options->count))
            {
                return false;
            }
        }
        else if (strcmp(option, "--interval-ms") == 0)
        {
            if (!parse_unsigned(value, 10, MAX_INTERVAL_MS, &parsed) ||
                (parsed < MIN_INTERVAL_MS))
            {
                return false;
            }
            options->interval_ms = (uint32_t)parsed;
            options->interval_specified = true;
        }
        else
        {
            return false;
        }
    }

    if ((options->interface_name == NULL) ||
        (options->interface_name[0] == '\0') ||
        (strlen(options->interface_name) >= IF_NAMESIZE) ||
        (options->go_cb_ref[0] == '\0') || (options->dataset_ref[0] == '\0') ||
        (options->go_id[0] == '\0') ||
        (strlen(options->go_cb_ref) > LAB_REFERENCE_MAX) ||
        (strlen(options->dataset_ref) > LAB_REFERENCE_MAX) ||
        (strlen(options->go_id) > LAB_REFERENCE_MAX))
    {
        return false;
    }

    if ((strcmp(options->mode, "sub") == 0) && options->test_mode)
    {
        return false;
    }

    if ((strcmp(options->mode, "sub") == 0) && options->interval_specified)
    {
        return false;
    }

    return true;
}

static void print_mac_address(const uint8_t address[6])
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x", address[0], address[1], address[2],
           address[3], address[4], address[5]);
}

static bool sleep_interval(uint32_t interval_ms)
{
    struct timespec remaining = {
        .tv_sec = (time_t)(interval_ms / 1000U),
        .tv_nsec = (long)(interval_ms % 1000U) * 1000000L,
    };

    while (!stop_requested && (nanosleep(&remaining, &remaining) != 0))
    {
        if (errno != EINTR)
        {
            return false;
        }
    }

    return true;
}

static void destroy_dataset(LinkedList dataset)
{
    if (dataset != NULL)
    {
        LinkedList_destroyDeep(dataset,
                               (LinkedListValueDeleteFunction)MmsValue_delete);
    }
}

static int run_publisher(const app_options_t* options)
{
    CommParameters communication = {0};
    LinkedList dataset = NULL;
    MmsValue* bus_number = NULL;
    MmsValue* pg_mw = NULL;
    MmsValue* qg_mvar = NULL;
    MmsValue* vg_pu = NULL;
    GoosePublisher publisher = NULL;
    bool test_value_sent = false;
    uint64_t published = 0U;
    int exit_code = EXIT_FAILURE;

    communication.appId = options->app_id;
    memcpy(communication.dstAddress, options->destination_mac,
           sizeof(communication.dstAddress));
    communication.vlanId = 0U;
    communication.vlanPriority = 0U;

    bus_number = MmsValue_newIntegerFromInt32(1);
    pg_mw = MmsValue_newFloat(BUS1_PG_MW);
    qg_mvar = MmsValue_newFloat(BUS1_QG_MVAR);
    vg_pu = MmsValue_newFloat(BUS1_VG_PU);
    if ((bus_number == NULL) || (pg_mw == NULL) || (qg_mvar == NULL) ||
        (vg_pu == NULL))
    {
        fprintf(stderr, "error: failed to allocate GOOSE dataset values\n");
        goto cleanup_values;
    }

    dataset = LinkedList_create();
    if (dataset == NULL)
    {
        fprintf(stderr, "error: failed to allocate GOOSE dataset list\n");
        goto cleanup_values;
    }
    LinkedList_add(dataset, bus_number);
    LinkedList_add(dataset, pg_mw);
    LinkedList_add(dataset, qg_mvar);
    LinkedList_add(dataset, vg_pu);

    publisher =
        GoosePublisher_createEx(&communication, options->interface_name, false);
    if (publisher == NULL)
    {
        fprintf(stderr,
                "error: publisher creation failed on interface '%s'; "
                "check interface name and raw-socket privileges\n",
                options->interface_name);
        goto cleanup_dataset;
    }

    GoosePublisher_setGoCbRef(publisher, (char*)options->go_cb_ref);
    GoosePublisher_setDataSetRef(publisher, (char*)options->dataset_ref);
    GoosePublisher_setGoID(publisher, (char*)options->go_id);
    GoosePublisher_setConfRev(publisher, 1U);
    GoosePublisher_setTimeAllowedToLive(publisher, options->interval_ms * 2U);
    GoosePublisher_setSimulation(publisher, true);
    GoosePublisher_setNeedsCommission(publisher, true);
    GoosePublisher_reset(publisher);

    printf("mode=pub interface=%s app_id=0x%04x dst_mac=",
           options->interface_name, options->app_id);
    print_mac_address(options->destination_mac);
    printf("\nGoCB=%s dataset=%s GoID=%s vlan=disabled simulation=true "
           "ndsCom=true lab_only=true\n",
           options->go_cb_ref, options->dataset_ref, options->go_id);
    printf("dataset_order: Bus1 (integer), Pg (MW), Qg (MVAr), "
           "Vg (p.u.)\n");
    printf("data_source: MATPOWER case14 generator input values; "
           "not live telemetry or solved power-flow output\n");
    printf("initial_values: Bus1=1 Pg=%.1f MW Qg=%.1f MVAr Vg=%.2f p.u.\n",
           (double)BUS1_PG_MW, (double)BUS1_QG_MVAR, (double)BUS1_VG_PU);

    exit_code = EXIT_SUCCESS;
    while (!stop_requested &&
           ((options->count == 0U) || (published < options->count)))
    {
        if (options->test_mode && !test_value_sent && (published >= 1U))
        {
            MmsValue_setFloat(pg_mw, TEST_PG_MW);
            (void)GoosePublisher_increaseStNum(publisher);
            test_value_sent = true;
            printf("test_change: Pg=%.1f MW; library advanced stNum and "
                   "reset sqNum\n",
                   (double)TEST_PG_MW);
        }

        if (GoosePublisher_publish(publisher, dataset) < 0)
        {
            fprintf(stderr, "error: GOOSE publish failed\n");
            exit_code = EXIT_FAILURE;
            break;
        }

        published++;
        printf("published=%" PRIu64 "\n", published);
        (void)fflush(stdout);

        if ((options->count != 0U) && (published >= options->count))
        {
            break;
        }
        if (!sleep_interval(options->interval_ms))
        {
            fprintf(stderr, "error: publish interval sleep failed: %s\n",
                    strerror(errno));
            exit_code = EXIT_FAILURE;
            break;
        }
    }

cleanup_dataset:
    if (publisher != NULL)
    {
        GoosePublisher_destroy(publisher);
    }
    destroy_dataset(dataset);
    return exit_code;

cleanup_values:
    MmsValue_delete(bus_number);
    MmsValue_delete(pg_mw);
    MmsValue_delete(qg_mvar);
    MmsValue_delete(vg_pu);
    return exit_code;
}

typedef struct
{
    const char* expected_go_cb_ref;
    const char* expected_dataset_ref;
    const char* expected_go_id;
} subscriber_context_t;

static bool dataset_has_expected_types(const MmsValue* values)
{
    if ((values == NULL) || (MmsValue_getType(values) != MMS_ARRAY) ||
        (MmsValue_getArraySize(values) != 4U))
    {
        return false;
    }

    MmsValue* bus = MmsValue_getElement(values, 0);
    MmsValue* pg = MmsValue_getElement(values, 1);
    MmsValue* qg = MmsValue_getElement(values, 2);
    MmsValue* vg = MmsValue_getElement(values, 3);

    return (bus != NULL) && (pg != NULL) && (qg != NULL) && (vg != NULL) &&
           (MmsValue_getType(bus) == MMS_INTEGER) &&
           (MmsValue_getType(pg) == MMS_FLOAT) &&
           (MmsValue_getType(qg) == MMS_FLOAT) &&
           (MmsValue_getType(vg) == MMS_FLOAT);
}

static const char* printable_string(const char* value)
{
    return (value == NULL) ? "(null)" : value;
}

static void goose_listener(GooseSubscriber subscriber, void* parameter)
{
    subscriber_context_t* context = (subscriber_context_t*)parameter;
    uint_fast64_t event_number =
        atomic_fetch_add_explicit(&observed_count, 1U, memory_order_relaxed) +
        1U;
    bool state_valid = GooseSubscriber_isValid(subscriber);
    uint32_t st_num = GooseSubscriber_getStNum(subscriber);
    uint32_t sq_num = GooseSubscriber_getSqNum(subscriber);
    uint32_t ttl_ms = GooseSubscriber_getTimeAllowedToLive(subscriber);
    MmsValue* values = GooseSubscriber_getDataSetValues(subscriber);
    const char* actual_go_cb_ref = GooseSubscriber_getGoCbRef(subscriber);
    const char* actual_dataset = GooseSubscriber_getDataSet(subscriber);
    const char* actual_go_id = GooseSubscriber_getGoId(subscriber);
    bool references_match =
        (actual_go_cb_ref != NULL) && (actual_dataset != NULL) &&
        (actual_go_id != NULL) &&
        (strcmp(actual_go_cb_ref, context->expected_go_cb_ref) == 0) &&
        (strcmp(actual_dataset, context->expected_dataset_ref) == 0) &&
        (strcmp(actual_go_id, context->expected_go_id) == 0);
    bool types_match = dataset_has_expected_types(values);
    bool lab_match = state_valid && references_match && types_match;
    bool test_flag = GooseSubscriber_isTest(subscriber);
    bool needs_commission = GooseSubscriber_needsCommission(subscriber);
    bool operational_flags_clear = lab_match && !test_flag && !needs_commission;

    if (lab_match)
    {
        (void)atomic_fetch_add_explicit(&received_count, 1U,
                                        memory_order_relaxed);
    }

    printf("event=%" PRIuFAST64 " lab_match=%s operational_flags_clear=%s "
           "valid=%s stNum=%" PRIu32 " sqNum=%" PRIu32 " ttl_ms=%" PRIu32
           " test=%s "
           "ndsCom=%s\n",
           event_number, lab_match ? "true" : "false",
           operational_flags_clear ? "true" : "false",
           state_valid ? "true" : "false", st_num, sq_num, ttl_ms,
           test_flag ? "true" : "false", needs_commission ? "true" : "false");
    printf("  references_match=%s GoCB=%s dataset=%s GoID=%s\n",
           references_match ? "true" : "false",
           printable_string(actual_go_cb_ref), printable_string(actual_dataset),
           printable_string(actual_go_id));

    if (!references_match)
    {
        printf("  values=not_interpreted; lab references did not match\n");
    }
    else if (!state_valid)
    {
        printf("  values=not_interpreted; subscriber state is invalid\n");
    }
    else if (!types_match)
    {
        printf("  dataset=wrong_shape_or_type; expected "
               "ARRAY[INTEGER,FLOAT,FLOAT,FLOAT]\n");
    }
    else if (lab_match)
    {
        MmsValue* bus = MmsValue_getElement(values, 0);
        MmsValue* pg = MmsValue_getElement(values, 1);
        MmsValue* qg = MmsValue_getElement(values, 2);
        MmsValue* vg = MmsValue_getElement(values, 3);

        printf("  dataset_order: Bus1 (integer), Pg (MW), Qg (MVAr), "
               "Vg (p.u.)\n");
        printf("  Bus1=%" PRId32 " Pg=%.1f MW Qg=%.1f MVAr Vg=%.2f p.u.\n",
               MmsValue_toInt32(bus), (double)MmsValue_toFloat(pg),
               (double)MmsValue_toFloat(qg), (double)MmsValue_toFloat(vg));
    }
    else
    {
        printf("  values=not_interpreted; message did not pass state "
               "validation\n");
    }
    (void)fflush(stdout);
}

static int run_subscriber(const app_options_t* options)
{
    GooseReceiver receiver = GooseReceiver_create();
    GooseSubscriber subscriber = NULL;
    bool subscriber_added = false;
    int exit_code = EXIT_FAILURE;
    subscriber_context_t context = {
        .expected_go_cb_ref = options->go_cb_ref,
        .expected_dataset_ref = options->dataset_ref,
        .expected_go_id = options->go_id,
    };

    if (receiver == NULL)
    {
        fprintf(stderr, "error: failed to create GOOSE receiver\n");
        return EXIT_FAILURE;
    }

    GooseReceiver_setInterfaceId(receiver, options->interface_name);
    subscriber = GooseSubscriber_create((char*)options->go_cb_ref, NULL);
    if (subscriber == NULL)
    {
        fprintf(stderr, "error: failed to create GOOSE subscriber\n");
        goto cleanup;
    }
    GooseSubscriber_setDstMac(subscriber, (uint8_t*)options->destination_mac);
    GooseSubscriber_setAppId(subscriber, options->app_id);
    GooseSubscriber_setListener(subscriber, goose_listener, &context);
    GooseReceiver_addSubscriber(receiver, subscriber);
    subscriber_added = true;

    printf("mode=sub interface=%s app_id=0x%04x dst_mac=",
           options->interface_name, options->app_id);
    print_mac_address(options->destination_mac);
    printf("\nGoCB=%s dataset=%s GoID=%s lab_only=true\n", options->go_cb_ref,
           options->dataset_ref, options->go_id);
    printf("subscriber awaits lab GOOSE; count=%" PRIu64
           " (0 means until signal)\n",
           options->count);

    GooseReceiver_start(receiver);
    if (!GooseReceiver_isRunning(receiver))
    {
        fprintf(stderr,
                "error: receiver start failed on interface '%s'; "
                "check interface name and raw-socket privileges\n",
                options->interface_name);
        goto cleanup;
    }

    exit_code = EXIT_SUCCESS;
    while (!stop_requested &&
           ((options->count == 0U) ||
            (atomic_load_explicit(&received_count, memory_order_relaxed) <
             options->count)))
    {
        const struct timespec poll_delay = {.tv_sec = 0, .tv_nsec = 100000000L};
        (void)nanosleep(&poll_delay, NULL);
    }

cleanup:
    if (receiver != NULL)
    {
        if (GooseReceiver_isRunning(receiver))
        {
            GooseReceiver_stop(receiver);
        }
        GooseReceiver_destroy(receiver);
    }
    if (!subscriber_added && (subscriber != NULL))
    {
        GooseSubscriber_destroy(subscriber);
    }
    return exit_code;
}

int main(int argc, char** argv)
{
    app_options_t options;

    if (!parse_options(argc, argv, &options))
    {
        print_usage(stderr, argv[0]);
        return EXIT_FAILURE;
    }

    if (!install_signal_handlers())
    {
        fprintf(stderr, "error: cannot install signal handlers: %s\n",
                strerror(errno));
        return EXIT_FAILURE;
    }

    if (strcmp(options.mode, "pub") == 0)
    {
        return run_publisher(&options);
    }

    return run_subscriber(&options);
}
