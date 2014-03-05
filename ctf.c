/*
 * ctf.c | CTF Library (Source File)
 *
 * Copyright (c) 2012-2014 Alexander Taylor <ajtaylor@fuzyll.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "ctf.h"


/*
 * Binds the service to a port and begins listening.
 * Returns the file descriptor of the socket that's been bound.
 * Exits completely on failure.
 */
int ctf_listen(const unsigned short port, const int proto)
{
    int sd;
    int optval = 1;
#ifndef _IPV6
    const int domain = AF_INET;
    struct sockaddr_in addr;
#else
    const int domain = AF_INET6;
    struct sockaddr_in6 addr;
#endif

    /*
     * Rather than set up the sockaddr_in struct here, DDTEK does getifaddrs()
     * on an ifaddrs struct, finds an entry matching a given interface like
     * "eth0" or "em1" and a given protocol version (AF_INET or AF_INET6), and
     * passes that struct to bind instead.
     *
     * I have not done this, which means you cannot bind two services to the
     * same port on different interfaces ("lo" and "eth0", for example). This
     * is interesting functionality, but I currently don't have a use for it.
     */

    // populate socket structure
#ifndef _IPV6
    addr.sin_family = domain;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
#else
    addr.sin6_family = domain;
    addr.sin6_port = htons(port);
    addr.sin6_addr = in6addr_any;
#endif

    // ignore children so they disappear instead of becoming zombies
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
#ifdef _DEBUG
        errx(-1, "Unable to set SIGCHLD handler");
#else
        exit(-1);
#endif
    }

    // create socket
    if (proto == IPPROTO_RAW) {
        sd = socket(domain, SOCK_RAW, proto);
    } else if (proto == IPPROTO_SCTP) {
        sd = socket(domain, SOCK_SEQPACKET, proto);
    } else if (proto == IPPROTO_UDP) {
        sd = socket(domain, SOCK_DGRAM, proto);
    } else {
        sd = socket(domain, SOCK_STREAM, proto);
    }
    if (sd == -1) {
#ifdef _DEBUG
        errx(-1, "Unable to create socket");
#else
        exit(-1);
#endif
    }

    // set socket reuse option
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) == -1) {
#ifdef _DEBUG
        errx(-1, "Unable to set socket reuse option");
#else
        exit(-1);
#endif
    }

    // bind to socket
#ifndef _IPV6
    if (bind(sd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) {
#else
    if (bind(sd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_in6)) == -1) {
#endif
#ifdef _DEBUG
        errx(-1, "Unable to bind socket");
#else
        exit(-1);
#endif
    }

    // listen for new connections
    if (proto != IPPROTO_UDP && proto != IPPROTO_RAW && listen(sd, 16) == -1) {
#ifdef _DEBUG
        errx(-1, "Unable to listen on socket");
#else
        exit(-1);
#endif
    }

    return sd;
}


/*
 * Accepts connections and forks off child processes to handle them.
 * Loops indefinitely and should never return.
 */
void ctf_server(int sd, const char *user, int (*handler)(int))
{
#ifdef _DEBUG
    (void)user;
#endif
    int client;
    int status;
    pid_t pid;

    // seed the random number generator
#ifndef _NORAND
    srand(time(0));
#endif

    // start the connection loop
    while (true) {
        // accept a client connection
        client = accept(sd, NULL, NULL);
        if (client == -1) {
            continue;
        }

        // randomize socket descriptor
        /*
         * We randomize the socket descriptor here to make shellcoders
         * unable to hardcode it. This makes for more interesting exploits.
         */
#if !defined(_DEBUG) && !defined(_NORAND)
        client = ctf_randfd(client);
#endif

        // fork child process off to handle connection
        /*
         * We fork here before dropping privileges to the service's
         * user to prevent people from modifying the parent process in memory.
         */
        pid = fork();
        if (pid == -1) {
            continue;
        }

        // if we got a PID, we're the parent
        if (pid) {
            close(client);
        } else {
            /*
             * We only drop privileges and alarm the child process if we're
             * not compiled for debugging. In practice, these things typically
             * got patched out by service developers and testers in a hex editor
             * anyway, so this should save time.
             */
#ifndef _DEBUG
            ctf_privdrop(user);
            alarm(16);
#endif
            close(sd);
            status = handler(client);
            close(client);
            exit(status);
        }
   }
}


/*
 * Drops privileges from an administrative user to one specific to the service.
 * Exits completely on failure.
 */
void ctf_privdrop(const char *user)
{
    struct passwd *pwentry;

    // get passwd structure for the user
    pwentry = getpwnam(user);
    if (!pwentry) {
#ifdef _DEBUG
        errx(-1, "Unable to find user");
#else
        exit(-1);
#endif
    }

    /*
     * Unless someone mucks with their environment, these checks should prevent
     * payloads from being able to do nasty stuff to system files and temporary
     * files (or just straight-up escalating privileges).
     */

    // remove all extra groups (prevents escalation via group associations)
    if (setgroups(0, NULL) < 0) {
#ifdef _DEBUG
        errx(-1, "Unable to remove extra groups");
#else
        exit(-1);
#endif
    }

    // set real, effective, and saved GID to that of the unprivileged user
    if (setgid(pwentry->pw_gid) < 0) {
#ifdef _DEBUG
        errx(-1, "Unable to change GID");
#else
        exit(-1);
#endif
    }

    // set real, effective, and saved UID to that of the unprivileged user
    if (setuid(pwentry->pw_uid) < 0) {
#ifdef _DEBUG
        errx(-1, "Unable to change UID");
#else
        exit(-1);
#endif
    }

    // change directory (optionally chroot into the unprivileged user's home directory)
#ifdef _CHROOT
    if (chroot(pwentry->pw_dir) < 0 || chdir("/") < 0) {
#else
    if (chdir(pwentry->pw_dir) < 0) {
#endif
#ifdef _DEBUG
        errx(-1, "Unable to change current directory");
#else
        exit(-1);
#endif
    }
}


/*
 * Randomizes a given file descriptor.
 * Returns the newly randomized file descriptor.
 * Can never fail (falls back to rand() or the original file descriptor).
 */
int ctf_randfd(int old)
{
    int max = getdtablesize();  // stay within operating system limits
    int fd = open("/dev/urandom", O_RDONLY);
    int new = 0;

    // randomize new file descriptor
    if (fd < 0) {
        while (new < old) {
            new = rand() % max;  // fall back to rand() if fd was invalid
        }
    } else {
        while (new < old) {
            read(fd, &new, 2);
            new %= max;
        }
        close(fd);
    }

    // duplicate the old file descriptor to the new one
    if (dup2(old, new) == -1) {
        new = old;  // if we failed, fall back to using the un-randomized fd
    } else {
        close(old);  // if we were successful, close the old fd
    }

    return new;
}


/*
 * Receives from a socket until given length is reached.
 * Returns number of bytes received.
 */
int ctf_recv(int sd, char *msg, unsigned int len)
{
    int prev = 0;  // previous amount of bytes we received
    unsigned int i = 0;

    if (msg && len) {
        // keep reading bytes until we've got the whole message
        for (i = 0; i < len; i += prev) {
            prev = read(sd, msg + i, len - i);
            if (prev <= 0) {
#ifdef _DEBUG
                warnx("Unable to receive entire message");
#endif
                break;
            }
        }
    }

    return i;
}


/*
 * Receives data from a socket until sentinel value or maximum length is reached.
 * Returns number of bytes received.
 */
int ctf_recvuntil(int sd, char *msg, unsigned int len, const char stop)
{
    char buf;  // temporary buffer to hold each received character
    int prev = 0;  // previous amount of bytes we received
    unsigned int i = 0;

    if (msg && len) {
        // receive a char at a time until we hit sentinel or max length
        for (i = 0; i < len; i += prev) {
            // receive character
            prev = read(sd, &buf, 1);
            if (prev <= 0) {
#ifdef _DEBUG
                warnx("Unable to receive entire message");
#endif
                break;
            }

            // add character to our received message
            msg[i] = buf;

            // break loop if it was our sentinel
            if (buf == stop) {
                break;
            }
        }
    }

    return i;
}


/*
 * Wrapper for ctf_sendn that does strlen() for you.
 * Returns number of bytes send (or <= 0 for failure).
 */
int ctf_send(int sd, const char *msg)
{
    return ctf_sendn(sd, msg, strlen(msg));
}


/*
 * Sends a given message through a given socket.
 * Returns number of bytes sent (or <= 0 for failure).
 */
int ctf_sendn(int sd, const char *msg, unsigned int len)
{
    int prev = 0;  // previous amount of bytes we sent
    unsigned int i = 0;

    // send entire message (in chunks if we have to)
    for (i = 0; i < len; i += prev) {
        prev = write(sd, msg + i, len - i);
        if (prev <= 0) {
#ifdef _DEBUG
            warnx("Unable to send entire message");
#endif
            return prev;
        }
    }

    return i;
}


/*
 * Wrapper for ctf_send() to allow for formatted messages.
 */
int ctf_sendf(int sd, const char *format, ...)
{
    va_list list;
    char *buf = NULL;  // temporary buffer to hold formatted string
    int status = 0;

    // format message and place it in our buffer
    va_start(list, format);
    status = vasprintf(&buf, format, list);
    va_end(list);
    if (status < 0) {
        goto end;
    }

    // send our message
    status = ctf_sendn(sd, buf, strlen(buf));

end:
    free(buf);
    return status;
}
