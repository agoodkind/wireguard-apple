/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2023 WireGuard LLC. All Rights Reserved.
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

typedef void(*logger_fn_t)(void *context, int level, const char *msg);
extern void wgSetLogger(void *context, logger_fn_t logger_fn);
extern int wgTurnOn(const char *settings, int32_t tun_fd);
extern void wgTurnOff(int handle);
extern int64_t wgSetConfig(int handle, const char *settings);
extern char *wgGetConfig(int handle);
extern void wgBumpSockets(int handle);
extern void wgDisableSomeRoamingForBrokenMobileSemantics(int handle);
extern const char *wgVersion();

typedef void (*wg_relay_send_callback_t)(void *context,
                                         const uint8_t *endpoint,
                                         size_t endpoint_len,
                                         const uint8_t *data,
                                         size_t data_len);
extern int32_t wgTurnOnWithRelayBind(const char *settings,
                                     int32_t tun_fd,
                                     wg_relay_send_callback_t send_cb,
                                     void *send_ctx);
extern void wgRelayBindInjectReceive(int32_t handle,
                                     const char *endpoint,
                                     size_t endpoint_len,
                                     const uint8_t *data,
                                     size_t data_len);
extern void wgRelayBindUnregister(int32_t handle);

#endif
