#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <errno.h>

#include <gssapi/gssapi.h>

/*
 * mech_pqauth: GSS-API mechanism skeleton backed by PQ-Auth.
 *
 * Non-negotiable constraints for this mechanism:
 * - Do NOT invent new network authentication protocols.
 * - Do NOT modify NFS or SMB wire formats.
 * - Do NOT fork Samba or the Linux kernel.
 * - Follow Kerberos / GSS-API semantics.
 * - PQ-Auth acts as a Kerberos-like security mechanism.
 *
 * This file intentionally implements only a minimal, non-cryptographic
 * context/credential skeleton. Real ticket validation, crypto, and
 * PQ-Auth daemon integration are added in later phases.
 */

/*
 * Temporary OID for mech_pqauth.
 *
 * OID: 1.2.3.4.5.6.7.8 (experimental / placeholder)
 * DER encoding: 0x2A 03 04 05 06 07 08
 *
 * Replace this with a properly assigned enterprise OID before any
 * production deployment.
 */
static gss_OID_desc mech_pqauth_oid_desc = {
    7,                         /* length */
    (void *)"\x2A\x03\x04\x05\x06\x07\x08" /* elements */
};

const gss_OID GSS_MECH_PQAUTH = &mech_pqauth_oid_desc;

/*
 * Internal representations for PQ-Auth credentials and contexts.
 * For now these are opaque placeholders carried through the API.
 */
typedef struct pqauth_cred_desc {
    int placeholder; /* future: service principal, key handles, etc. */
} pqauth_cred_desc, *pqauth_cred_t;

typedef struct pqauth_ctx_desc {
    int established;         /* non-zero once context is fully established */
    OM_uint32 lifetime;      /* seconds until expiry (0 = unspecified) */

    /*
     * Opaque PQ-Auth service ticket bound to this context.
     * In later phases this will be the Phase 2/3 crypto-sealed service
     * ticket issued by pq-authd's TGS, potentially plus additional
     * channel-binding state.
     */
    char *service_ticket;
} pqauth_ctx_desc, *pqauth_ctx_t;

static void pqauth_free_buffer(gss_buffer_t buffer)
{
    if (!buffer || buffer->value == NULL)
        return;
    free(buffer->value);
    buffer->value = NULL;
    buffer->length = 0;
}

/*
 * Simple AF_UNIX client that asks the local pq-authd daemon to validate
 * a PQ-Auth service ticket. This uses the existing JSON-over-UNIX-socket
 * API and a new kind "VALIDATE", without changing any NFS/SMB on-the-wire
 * behavior.
 *
 * Request:
 *   {"kind":"VALIDATE","ticket":"<ticket>"}\n
 * Response (on success):
 *   {"kind":"VALIDATE","status":"OK","valid":true,
 *    "code":"Ok","expires_at":<unix>,"auth_mode":"hybrid"}
 */
static OM_uint32
pqauth_validate_ticket_via_daemon(const char *ticket,
                                  OM_uint32 *lifetime_out,
                                  OM_uint32 *minor_status)
{
    if (minor_status)
        *minor_status = 0;
    if (lifetime_out)
        *lifetime_out = 0;

    if (!ticket || ticket[0] == '\0') {
        return GSS_S_DEFECTIVE_TOKEN;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        if (minor_status)
            *minor_status = errno;
        return GSS_S_FAILURE;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    /* Default pq-authd socket path; must match policy/config defaults. */
    const char *sock_path = "/run/pq-authd.sock";
    if (strlen(sock_path) >= sizeof(addr.sun_path)) {
        close(fd);
        if (minor_status)
            *minor_status = EINVAL;
        return GSS_S_FAILURE;
    }
    strcpy(addr.sun_path, sock_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int err = errno;
        close(fd);
        if (minor_status)
            *minor_status = err;
        return GSS_S_FAILURE;
    }

    /* Build request JSON. */
    const char *prefix = "{\"kind\":\"VALIDATE\",\"ticket\":\"";
    const char *suffix = "\"}\n";
    size_t len = strlen(prefix) + strlen(ticket) + strlen(suffix);
    char *req = malloc(len + 1);
    if (!req) {
        close(fd);
        if (minor_status)
            *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    strcpy(req, prefix);
    strcat(req, ticket);
    strcat(req, suffix);

    ssize_t written = write(fd, req, strlen(req));
    free(req);
    if (written <= 0) {
        int err = errno;
        close(fd);
        if (minor_status)
            *minor_status = err;
        return GSS_S_FAILURE;
    }

    /* Read a single line JSON response. */
    char buf[1024];
    size_t used = 0;
    while (1) {
        ssize_t n = read(fd, buf + used, sizeof(buf) - used - 1);
        if (n <= 0)
            break;
        used += (size_t)n;
        if (used >= sizeof(buf) - 1)
            break;
        /* Stop once we see a newline. */
        if (memchr(buf, '\n', used) != NULL)
            break;
    }
    close(fd);
    buf[used] = '\0';

    /* Crude JSON parsing: check for "valid":true and pull expires_at. */
    if (strstr(buf, "\"valid\":true") == NULL) {
        return GSS_S_BAD_SIG; /* treated as invalid ticket for now */
    }

    const char *exp = strstr(buf, "\"expires_at\":");
    if (exp && lifetime_out) {
        exp += strlen("\"expires_at\":");
        long long expires_at = 0;
        if (sscanf(exp, "%lld", &expires_at) == 1 && expires_at > 0) {
            /*
             * GSS-API time_rec is a duration in seconds. We conservatively
             * treat it as an absolute expiry hint here; callers may clamp
             * or recompute as needed.
             */
            if (expires_at > 0 && expires_at < (long long)UINT32_MAX) {
                *lifetime_out = (OM_uint32)expires_at;
            }
        }
    }

    return GSS_S_COMPLETE;
}

OM_uint32
pqauth_gss_acquire_cred(OM_uint32 *minor_status,
                        const gss_name_t desired_name,
                        OM_uint32 time_req,
                        const gss_OID_set desired_mechs,
                        gss_cred_usage_t cred_usage,
                        gss_cred_id_t *output_cred_handle,
                        gss_OID_set *actual_mechs,
                        OM_uint32 *time_rec)
{
    (void)desired_name;
    (void)time_req;
    (void)desired_mechs;
    (void)cred_usage;

    if (minor_status)
        *minor_status = 0;

    if (!output_cred_handle)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    pqauth_cred_t cred = calloc(1, sizeof(*cred));
    if (!cred) {
        if (minor_status)
            *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }

    *output_cred_handle = (gss_cred_id_t)cred;

    if (actual_mechs)
        *actual_mechs = GSS_C_NO_OID_SET; /* filled in later phases */

    if (time_rec)
        *time_rec = 0; /* "indefinite" until we bind to real tickets */

    return GSS_S_COMPLETE;
}

OM_uint32
pqauth_gss_release_cred(OM_uint32 *minor_status,
                        gss_cred_id_t *cred_handle)
{
    if (minor_status)
        *minor_status = 0;

    if (!cred_handle || *cred_handle == GSS_C_NO_CREDENTIAL)
        return GSS_S_COMPLETE;

    pqauth_cred_t cred = (pqauth_cred_t)*cred_handle;
    free(cred);
    *cred_handle = GSS_C_NO_CREDENTIAL;

    return GSS_S_COMPLETE;
}

OM_uint32
pqauth_gss_init_sec_context(OM_uint32 *minor_status,
                            const gss_cred_id_t initiator_cred_handle,
                            gss_ctx_id_t *context_handle,
                            const gss_name_t target_name,
                            const gss_OID mech_type,
                            OM_uint32 req_flags,
                            OM_uint32 time_req,
                            const gss_channel_bindings_t input_chan_bindings,
                            const gss_buffer_t input_token,
                            gss_OID *actual_mech_type,
                            gss_buffer_t output_token,
                            OM_uint32 *ret_flags,
                            OM_uint32 *time_rec)
{
    (void)initiator_cred_handle;
    (void)target_name;
    (void)mech_type;
    (void)req_flags;
    (void)time_req;
    (void)input_chan_bindings;
    (void)input_token;

    if (minor_status)
        *minor_status = 0;

    if (!context_handle || !output_token)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    if (*context_handle == GSS_C_NO_CONTEXT) {
        pqauth_ctx_t ctx = calloc(1, sizeof(*ctx));
        if (!ctx) {
            if (minor_status)
                *minor_status = ENOMEM;
            return GSS_S_FAILURE;
        }
        *context_handle = (gss_ctx_id_t)ctx;
    }

    if (actual_mech_type)
        *actual_mech_type = (gss_OID)&mech_pqauth_oid_desc;

    /* No real negotiation yet; output token is empty. */
    output_token->value = NULL;
    output_token->length = 0;

    if (ret_flags)
        *ret_flags = 0;

    if (time_rec)
        *time_rec = time_req;

    /*
     * We model this as a one-shot context establishment for now.
     * Later phases may return GSS_S_CONTINUE_NEEDED while exchanging
     * PQ-Auth tickets.
     */
    return GSS_S_COMPLETE;
}

/*
 * Minimal helper: bind an incoming PQ-Auth service ticket (opaque string)
 * to a context object. In this phase we do not yet perform cryptographic
 * validation or call pq-authd; we only record the association so that
 * higher layers can treat the context as carrying a PQ-Auth ticket.
 *
 * Later phases will replace this with a call over the AF_UNIX socket to
 * pq-authd to validate the ticket (expiry, signatures, service binding)
 * before marking the context as established.
 */
static OM_uint32
pqauth_bind_service_ticket(pqauth_ctx_t ctx,
                           const gss_buffer_t input_token_buffer,
                           OM_uint32 *minor_status)
{
    if (minor_status)
        *minor_status = 0;

    if (!input_token_buffer || input_token_buffer->value == NULL ||
        input_token_buffer->length == 0) {
        return GSS_S_DEFECTIVE_TOKEN;
    }

    /*
     * Treat the input token as an opaque, non-NUL-terminated blob. For now
     * we assume it is a textual PQ-Auth service_ticket as issued by TGS;
     * we copy it into a NUL-terminated buffer owned by the context.
     */
    char *buf = malloc(input_token_buffer->length + 1);
    if (!buf) {
        if (minor_status)
            *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    memcpy(buf, input_token_buffer->value, input_token_buffer->length);
    buf[input_token_buffer->length] = '\0';

    /* Replace any existing ticket binding. */
    if (ctx->service_ticket) {
        free(ctx->service_ticket);
    }
    ctx->service_ticket = buf;

    /* In this phase, lifetime is unknown; it will be filled from pq-authd
     * once validation is wired in. */
    ctx->lifetime = 0;
    ctx->established = 1;

    return GSS_S_COMPLETE;
}

OM_uint32
pqauth_gss_accept_sec_context(OM_uint32 *minor_status,
                              gss_ctx_id_t *context_handle,
                              const gss_cred_id_t acceptor_cred_handle,
                              const gss_buffer_t input_token_buffer,
                              const gss_channel_bindings_t input_chan_bindings,
                              gss_name_t *src_name,
                              gss_OID *mech_type,
                              gss_buffer_t output_token,
                              OM_uint32 *ret_flags,
                              OM_uint32 *time_rec,
                              gss_cred_id_t *delegated_cred_handle)
{
    (void)acceptor_cred_handle;
    (void)input_chan_bindings;
    (void)src_name;
    (void)delegated_cred_handle;

    if (minor_status)
        *minor_status = 0;

    if (!context_handle || !output_token)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    if (*context_handle == GSS_C_NO_CONTEXT) {
        pqauth_ctx_t ctx = calloc(1, sizeof(*ctx));
        if (!ctx) {
            if (minor_status)
                *minor_status = ENOMEM;
            return GSS_S_FAILURE;
        }
        *context_handle = (gss_ctx_id_t)ctx;
    }

    pqauth_ctx_t ctx = (pqauth_ctx_t)*context_handle;

    OM_uint32 maj = pqauth_bind_service_ticket(ctx, input_token_buffer, minor_status);
    if (maj != GSS_S_COMPLETE) {
        return maj;
    }

    /* Ask pq-authd to validate the bound ticket and obtain lifetime
     * information. This keeps cryptographic validation inside the
     * daemon and avoids duplicating ticket logic in the GSS module.
     */
    OM_uint32 lifetime_hint = 0;
    maj = pqauth_validate_ticket_via_daemon(ctx->service_ticket, &lifetime_hint, minor_status);
    if (maj != GSS_S_COMPLETE) {
        ctx->established = 0;
        return maj;
    }
    ctx->lifetime = lifetime_hint;

    if (mech_type)
        *mech_type = (gss_OID)&mech_pqauth_oid_desc;

    /* No response token yet; purely local accept for now. */
    output_token->value = NULL;
    output_token->length = 0;

    if (ret_flags)
        *ret_flags = 0;

    if (time_rec)
        *time_rec = ctx->lifetime;

    return GSS_S_COMPLETE;
}

/*
 * Helper to release a PQ-Auth security context.
 * This mirrors gss_delete_sec_context semantics but is kept local
 * until we wire into a concrete GSS implementation.
 */
OM_uint32
pqauth_gss_delete_sec_context(OM_uint32 *minor_status,
                              gss_ctx_id_t *context_handle,
                              gss_buffer_t output_token)
{
    if (minor_status)
        *minor_status = 0;

    if (output_token)
        pqauth_free_buffer(output_token);

    if (!context_handle || *context_handle == GSS_C_NO_CONTEXT)
        return GSS_S_COMPLETE;

    pqauth_ctx_t ctx = (pqauth_ctx_t)*context_handle;
    if (ctx->service_ticket) {
        free(ctx->service_ticket);
        ctx->service_ticket = NULL;
    }
    free(ctx);
    *context_handle = GSS_C_NO_CONTEXT;

    return GSS_S_COMPLETE;
}
