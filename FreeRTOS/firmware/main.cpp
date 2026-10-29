#include "generated_models.h"

#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace
{

constexpr std::size_t kMaximumFeatures = 8;
constexpr std::size_t kLineCapacity = 320;
constexpr unsigned int kClass1ButtonPin = 20;
constexpr unsigned int kClass2ButtonPin = 21;

// Synthetic, high-confidence self-test vectors. These exercise the classifiers;
// they are not substitutes for the original live feature-engineering pipeline.
constexpr float kSvClass1[8] = {
    -13384.0f,     13384.0f,      1.0f,         14943.9951171875f,
    0.0184345227f, 0.0103930822f, 0.849107683f, 1.0f,
};
constexpr float kGooseClass1[6] = {
    0.293903857f, 0.0979992896f, 0.604218543f, 49.9999962f, 2.25f, 1.0f,
};
constexpr float kSvClass2[8] = {
    17.0f,        17.0f,        0.0f,        1442.947265625f,
    0.512513876f, 0.281821936f, 1.94223154f, 14.0f,
};
constexpr float kGooseClass2[6] = {
    0.153180122f, 0.110468984f, 0.49475342f, 0.766478419f, -0.50000006f, 0.0f,
};

void set_led(bool on)
{
    cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, on);
}

void print_prediction(const char* model, pico_ml::Prediction prediction)
{
    const unsigned int display_class = prediction.label == 1 ? 1 : 2;
    std::printf(
        "model=%s,class=%u,original_label=%u,probability_label_1=%.9g\r\n",
        model, display_class, static_cast<unsigned>(prediction.label),
        static_cast<double>(prediction.probability));
}

void print_feature_list(const char* name, const char* const* features,
                        std::size_t count)
{
    std::printf("%s", name);
    for (std::size_t index = 0; index < count; ++index)
    {
        std::printf("%s%s", index == 0 ? ": " : ", ", features[index]);
    }
    std::printf("\r\n");
}

void print_help()
{
    std::printf("\r\nCommands (comma-separated):\r\n");
    std::printf("  rf_sv,<8 values>\r\n");
    std::printf("  xgb_sv,<8 values>\r\n");
    std::printf("  xgb_goose,<6 values>\r\n");
    std::printf("  help\r\n\r\n");
    std::printf("Buttons:\r\n");
    std::printf("  GP20: run built-in Class 1 examples "
                "(original label 1, LED on)\r\n");
    std::printf("  GP21: run built-in Class 2 examples "
                "(original label 0, LED off)\r\n\r\n");
    print_feature_list("rf_sv / xgb_sv", pico_ml::rf_sv_feature_names, 8);
    print_feature_list("xgb_goose", pico_ml::xgb_goose_feature_names, 6);
}

bool parse_values(char* context, float* values, std::size_t expected)
{
    for (std::size_t index = 0; index < expected; ++index)
    {
        char* token = ::strtok_r(nullptr, ", \t", &context);
        if (token == nullptr)
        {
            std::printf("error: expected %u feature values\r\n",
                        static_cast<unsigned>(expected));
            return false;
        }
        errno = 0;
        char* end = nullptr;
        const float value = std::strtof(token, &end);
        if (errno == ERANGE || end == token || *end != '\0' ||
            !std::isfinite(value))
        {
            std::printf("error: invalid number at feature %u: %s\r\n",
                        static_cast<unsigned>(index), token);
            return false;
        }
        values[index] = value;
    }
    if (::strtok_r(nullptr, ", \t", &context) != nullptr)
    {
        std::printf("error: too many feature values\r\n");
        return false;
    }
    return true;
}

void process_line(char* line)
{
    char* context = nullptr;
    char* command = ::strtok_r(line, ", \t", &context);
    if (command == nullptr)
    {
        return;
    }
    if (std::strcmp(command, "help") == 0)
    {
        print_help();
        return;
    }

    float features[kMaximumFeatures] = {};
    pico_ml::Prediction prediction{};
    if (std::strcmp(command, "rf_sv") == 0)
    {
        if (!parse_values(context, features, 8))
        {
            return;
        }
        prediction = pico_ml::predict_rf_sv(features);
    }
    else if (std::strcmp(command, "xgb_sv") == 0)
    {
        if (!parse_values(context, features, 8))
        {
            return;
        }
        prediction = pico_ml::predict_xgb_sv(features);
    }
    else if (std::strcmp(command, "xgb_goose") == 0)
    {
        if (!parse_values(context, features, 6))
        {
            return;
        }
        prediction = pico_ml::predict_xgb_goose(features);
    }
    else
    {
        std::printf("error: unknown command '%s'; type help\r\n", command);
        return;
    }

    set_led(prediction.label == 1);
    print_prediction(command, prediction);
    std::printf("led=%s\r\n", prediction.label == 1 ? "on" : "off");
}

void run_button_example(bool target_class_1)
{
    const float* sv = target_class_1 ? kSvClass1 : kSvClass2;
    const float* goose = target_class_1 ? kGooseClass1 : kGooseClass2;
    const std::uint8_t expected_label = target_class_1 ? 1 : 0;
    const unsigned int display_class = target_class_1 ? 1 : 2;

    const pico_ml::Prediction rf = pico_ml::predict_rf_sv(sv);
    const pico_ml::Prediction xgb_sv = pico_ml::predict_xgb_sv(sv);
    const pico_ml::Prediction xgb_goose = pico_ml::predict_xgb_goose(goose);
    const bool all_expected = rf.label == expected_label &&
                              xgb_sv.label == expected_label &&
                              xgb_goose.label == expected_label;
    const bool all_class_1 =
        rf.label == 1 && xgb_sv.label == 1 && xgb_goose.label == 1;

    std::printf("\r\nbutton=GP%u,target_class=%u\r\n",
                target_class_1 ? kClass1ButtonPin : kClass2ButtonPin,
                display_class);
    print_prediction("rf_sv", rf);
    print_prediction("xgb_sv", xgb_sv);
    print_prediction("xgb_goose", xgb_goose);
    set_led(all_class_1);
    std::printf("all_expected=%s,led=%s\r\n", all_expected ? "yes" : "no",
                all_class_1 ? "on" : "off");
}

} // namespace

int main()
{
    stdio_init_all();
    if (cyw43_arch_init() != 0)
    {
        std::printf("error: failed to initialize Pico W wireless chip/LED\r\n");
        return 1;
    }
    set_led(false);

    gpio_init(kClass1ButtonPin);
    gpio_set_dir(kClass1ButtonPin, GPIO_IN);
    gpio_pull_up(kClass1ButtonPin);
    gpio_init(kClass2ButtonPin);
    gpio_set_dir(kClass2ButtonPin, GPIO_IN);
    gpio_pull_up(kClass2ButtonPin);

    sleep_ms(1500);
    std::printf("Pico embedded classifiers ready. Type help.\r\n");

    char line[kLineCapacity] = {};
    std::size_t length = 0;
    bool previous_class_1_button = gpio_get(kClass1ButtonPin);
    bool previous_class_2_button = gpio_get(kClass2ButtonPin);
    while (true)
    {
        const bool class_1_button = gpio_get(kClass1ButtonPin);
        const bool class_2_button = gpio_get(kClass2ButtonPin);
        if (previous_class_1_button && !class_1_button)
        {
            sleep_ms(20);
            if (!gpio_get(kClass1ButtonPin))
            {
                run_button_example(true);
            }
        }
        if (previous_class_2_button && !class_2_button)
        {
            sleep_ms(20);
            if (!gpio_get(kClass2ButtonPin))
            {
                run_button_example(false);
            }
        }
        previous_class_1_button = class_1_button;
        previous_class_2_button = class_2_button;

        const int character = getchar_timeout_us(1000);
        if (character == PICO_ERROR_TIMEOUT)
        {
            tight_loop_contents();
            continue;
        }
        if (character == '\r' || character == '\n')
        {
            if (length != 0)
            {
                line[length] = '\0';
                process_line(line);
                length = 0;
            }
        }
        else if (character == '\b' || character == 0x7f)
        {
            if (length != 0)
            {
                --length;
            }
        }
        else if (length + 1 < kLineCapacity)
        {
            line[length++] = static_cast<char>(character);
        }
        else
        {
            length = 0;
            std::printf("error: input line too long\r\n");
        }
    }
}
