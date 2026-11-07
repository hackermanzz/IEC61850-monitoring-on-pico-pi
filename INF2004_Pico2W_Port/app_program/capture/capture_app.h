/** @file capture_app.h
 * @brief v0.5 capture-profile kernel entry.
 */
#ifndef CAPTURE_APP_H
#define CAPTURE_APP_H

#if PORT_CAPTURE
#include "tk/tkernel.h" /* Kernel task entry ABI. */
void capture_app_task(INT start_code, void * p_exinf);
#endif

#endif /* CAPTURE_APP_H */

/*** end of file ***/
