/*
 * app_config.h
 * IS18 Edge Substation Watch: one place for pins, priorities, cores and
 * kernel object sizes of the µT-Kernel 3 SMP build (Tribunal 1 decision).
 *
 * µT-Kernel numbering: priority 1 is the highest. Processor 1 is RP2040
 * core 0, processor 2 is core 1 (TP_PRC1 / TP_PRC2).
 */
#ifndef APP_CONFIG_H
#define APP_CONFIG_H

/* ---------------------------------------------------------------- pins */
#define IS18_RMII_RXD0_PIN        (6u)   /* RXD1 must be RXD0 + 1 (GP7) */
#define IS18_RMII_CRS_DV_PIN      (13u)
#define IS18_RMII_MDIO_PIN        (4u)
#define IS18_RMII_MDC_PIN         (5u)
/* No RMII transmit pins are configured: the monitor is receive only. */

/* -------------------------------------------------------- task priorities */
#define IS18_PRI_CAPTURE          (1)    /* alone on processor 2 */
#define IS18_PRI_HEALTH           (2)
#define IS18_PRI_INCIDENT         (5)    /* 4 is the port's CYW43 service task */
#define IS18_PRI_ANALYSIS         (6)
#define IS18_PRI_SD_WRITER        (10)
#define IS18_PRI_NETWORK          (12)
#define IS18_PRI_LOGGER           (14)

/* ------------------------------------------------------------ stack sizes */
/* The SMP kernel runs global scheduling on the caller's stack, so the port
 * recommends at least 4 kB for any task that makes blocking kernel calls. */
#define IS18_STACK_CAPTURE        (4096)
#define IS18_STACK_ANALYSIS       (6144) /* BER parsing + medians + forests */

/* ---------------------------------------------------- capture frame pool */
#define IS18_FRAME_POOL_BLOCKS    (8u)   /* replaces the old 8 slot ring */
#define IS18_FRAME_DATA_BYTES     (1518u + 4u) /* frame plus FCS bytes */

/* ------------------------------------------------- prediction events mbf */
#define IS18_PRED_EVENTS          (16u)

/* ------------------------------------------------------- evidence pool */
#define IS18_EVIDENCE_BLOCKS      (4u)

/* ---------------------------------------------------------- timing */
#define IS18_CAPTURE_IDLE_MS      (100)  /* wake to poll PHY link when idle */
#define IS18_ANALYSIS_IDLE_MS     (500)  /* heartbeat even without traffic */
#define IS18_FRAME_BUDGET_US      (7692u) /* 1 s / 130 frames */
/* Capture Overload Warning (FR8): more than this many lost frames in 1 s. */
#define IS18_OVERLOAD_FRAMES      (10u)
#define IS18_OVERLOAD_WINDOW_US   (1000000u)

/* CRS_DV interrupt level on core 1 (1 = highest external level). */
#define IS18_CRS_DV_INT_LEVEL     (1)

#endif /* APP_CONFIG_H */
