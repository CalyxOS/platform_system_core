/*
 * Copyright (C) 2006 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cutils/misc.h>           // FIRST_APPLICATION_UID
#include <cutils/sockets.h>

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(_WIN32)

int socket_local_client(const char *name, int namespaceId, int type)
{
    errno = ENOSYS;
    return -1;
}

#else /* !_WIN32 */

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/types.h>

#include "socket_local_unix.h"

#define LISTEN_BACKLOG 4

/* Documented in header file. */
int socket_make_sockaddr_un(const char *name, int namespaceId, 
        struct sockaddr_un *p_addr, socklen_t *alen)
{
    memset (p_addr, 0, sizeof (*p_addr));
    size_t namelen;
    uid_t uid = getuid();
    char* socket_name_prefix;
    int socket_name_prefix_len;

    switch (namespaceId) {
        case ANDROID_SOCKET_NAMESPACE_ABSTRACT:
            // Functionally isolate non-system app namespace by prefixing socket names with uid
            if (uid >= FIRST_APPLICATION_UID) {
                socket_name_prefix_len = ABSTRACT_SOCKET_NAME_PREFIX_LEN;
                socket_name_prefix = (char*) calloc(socket_name_prefix_len + 1, sizeof(char));
                snprintf(socket_name_prefix, sizeof(socket_name_prefix),
                    ABSTRACT_SOCKET_NAME_PREFIX_FMT, uid);
            } else {
                // All system apps share a functional namespace
                // Minimize potential impact by only reducing usable name length by 1
                socket_name_prefix_len = 1;
                socket_name_prefix =
                        (char*) calloc(socket_name_prefix_len + 1, sizeof(char));
                *socket_name_prefix = ABSTRACT_SOCKET_NAME_SYSTEM_PREFIX;
            }
#if defined(__linux__)
            namelen  = strlen(name);

            // Test with length +1 for the *initial* '\0'.
            if ((namelen + 1 + socket_name_prefix_len) > sizeof(p_addr->sun_path)) {
                free(socket_name_prefix);
                goto error;
            }

            /*
             * Note: The path in this case is *not* supposed to be
             * '\0'-terminated. ("man 7 unix" for the gory details.)
             */
            
            p_addr->sun_path[0] = 0;

            memcpy(p_addr->sun_path + 1, socket_name_prefix, socket_name_prefix_len);

            memcpy(p_addr->sun_path + 1 + socket_name_prefix_len, name, namelen);
#else
            /* this OS doesn't have the Linux abstract namespace */

            namelen = strlen(name) + strlen(FILESYSTEM_SOCKET_PREFIX);
            /* unix_path_max appears to be missing on linux */
            if ((namelen + socket_name_prefix_len) > sizeof(*p_addr)
                    - offsetof(struct sockaddr_un, sun_path) - 1) {
                free(socket_name_prefix);
                goto error;
            }

            strcpy(p_addr->sun_path, FILESYSTEM_SOCKET_PREFIX);

            strcat(p_addr->sun_path, socket_name_prefix);

            strcat(p_addr->sun_path, name);
#endif
            namelen += socket_name_prefix_len;
            free(socket_name_prefix);
        break;

        case ANDROID_SOCKET_NAMESPACE_RESERVED:
            namelen = strlen(name) + strlen(ANDROID_RESERVED_SOCKET_PREFIX);
            /* unix_path_max appears to be missing on linux */
            if (namelen > sizeof(*p_addr) 
                    - offsetof(struct sockaddr_un, sun_path) - 1) {
                goto error;
            }

            strcpy(p_addr->sun_path, ANDROID_RESERVED_SOCKET_PREFIX);
            strcat(p_addr->sun_path, name);
        break;

        case ANDROID_SOCKET_NAMESPACE_FILESYSTEM:
            namelen = strlen(name);
            /* unix_path_max appears to be missing on linux */
            if (namelen > sizeof(*p_addr) 
                    - offsetof(struct sockaddr_un, sun_path) - 1) {
                goto error;
            }

            strcpy(p_addr->sun_path, name);
        break;
        default:
            // invalid namespace id
            return -1;
    }

    p_addr->sun_family = AF_LOCAL;
    *alen = namelen + offsetof(struct sockaddr_un, sun_path) + 1;
    return 0;
error:
    return -1;
}

/**
 * connect to peer named "name" on fd
 * returns same fd or -1 on error.
 * fd is not closed on error. that's your job.
 * 
 * Used by AndroidSocketImpl
 */
int socket_local_client_connect(int fd, const char* name, int namespaceId, int /*type*/) {
    struct sockaddr_un addr;
    socklen_t alen;
    int err;

    err = socket_make_sockaddr_un(name, namespaceId, &addr, &alen);

    if (err < 0) {
        goto error;
    }

    if(connect(fd, (struct sockaddr *) &addr, alen) < 0) {
        goto error;
    }

    return fd;

error:
    return -1;
}

/** 
 * connect to peer named "name"
 * returns fd or -1 on error
 */
int socket_local_client(const char *name, int namespaceId, int type)
{
    int s;

    s = socket(AF_LOCAL, type, 0);
    if(s < 0) return -1;

    if ( 0 > socket_local_client_connect(s, name, namespaceId, type)) {
        close(s);
        return -1;
    }

    return s;
}

#endif /* !_WIN32 */
