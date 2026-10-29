#include "generated_models.h"

#include <cmath>
#include <cstdio>

namespace {

bool close_enough(float actual, float expected, float tolerance = 1.0e-6f) {
    if (std::fabs(actual - expected) <= tolerance) return true;
    std::printf("expected %.9g, got %.9g\n", static_cast<double>(expected), static_cast<double>(actual));
    return false;
}

}  // namespace

int main() {
    const float sv[8] = {};
    const float goose[6] = {};

    const auto rf = pico_ml::predict_rf_sv(sv);
    const auto xgb_goose = pico_ml::predict_xgb_goose(goose);
    const auto xgb_sv = pico_ml::predict_xgb_sv(sv);

    bool valid = true;
    valid &= rf.label == 1 && close_enough(rf.probability, 0.51f);
    valid &= xgb_goose.label == 0 && close_enough(xgb_goose.probability, 0.00278928294f);
    valid &= xgb_sv.label == 0 && close_enough(xgb_sv.probability, 0.00435416168f);

    std::printf(
        "rf_sv=%.9g xgb_goose=%.9g xgb_sv=%.9g\n",
        static_cast<double>(rf.probability),
        static_cast<double>(xgb_goose.probability),
        static_cast<double>(xgb_sv.probability));
    return valid ? 0 : 1;
}
