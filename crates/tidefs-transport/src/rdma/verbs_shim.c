#include <stdint.h>

#if defined(__has_include)
#if __has_include(<infiniband/verbs.h>)
#define TIDEFS_HAVE_VERBS_H 1
#include <infiniband/verbs.h>
#endif
#endif

#ifndef TIDEFS_HAVE_VERBS_H
struct ibv_context;
struct ibv_pd;
struct ibv_qp;
struct ibv_cq;
struct ibv_mr;
struct ibv_send_wr;
struct ibv_recv_wr;
struct ibv_wc;

struct ibv_context_ops {
    int (*query_device)(void *context, void *device_attr);
    int (*query_port)(void *context, uint8_t port_num, void *port_attr);
    void *(*alloc_pd)(void *context);
    int (*dealloc_pd)(void *pd);
    void *(*reg_mr)(void *pd, void *addr, uintptr_t length, int access);
    void *(*rereg_mr)(void *mr, int flags, void *pd, void *addr,
                      uintptr_t length, int access);
    int (*dereg_mr)(void *mr);
    void *(*alloc_mw)(void *pd, int type);
    int (*bind_mw)(struct ibv_qp *qp, void *mw, void *mw_bind);
    int (*dealloc_mw)(void *mw);
    void *(*create_cq)(struct ibv_context *context, int cqe, void *channel,
                       int comp_vector);
    int (*poll_cq)(struct ibv_cq *cq, int num_entries, struct ibv_wc *wc);
    int (*req_notify_cq)(struct ibv_cq *cq, int solicited_only);
    void (*cq_event)(struct ibv_cq *cq);
    int (*resize_cq)(struct ibv_cq *cq, int cqe);
    int (*destroy_cq)(struct ibv_cq *cq);
    void *(*create_srq)(void *pd, void *srq_init_attr);
    int (*modify_srq)(void *srq, void *srq_attr, int srq_attr_mask);
    int (*query_srq)(void *srq, void *srq_attr);
    int (*destroy_srq)(void *srq);
    int (*post_srq_recv)(void *srq, struct ibv_recv_wr *recv_wr,
                         struct ibv_recv_wr **bad_recv_wr);
    struct ibv_qp *(*create_qp)(void *pd, void *attr);
    int (*query_qp)(struct ibv_qp *qp, void *attr, int attr_mask,
                    void *init_attr);
    int (*modify_qp)(struct ibv_qp *qp, void *attr, int attr_mask);
    int (*destroy_qp)(struct ibv_qp *qp);
    int (*post_send)(struct ibv_qp *qp, struct ibv_send_wr *wr,
                     struct ibv_send_wr **bad_wr);
    int (*post_recv)(struct ibv_qp *qp, struct ibv_recv_wr *wr,
                     struct ibv_recv_wr **bad_wr);
};

struct ibv_context {
    void *device;
    struct ibv_context_ops ops;
};

struct ibv_mr {
    struct ibv_context *context;
    struct ibv_pd *pd;
    void *addr;
    uintptr_t length;
    uint32_t handle;
    uint32_t lkey;
    uint32_t rkey;
};

struct ibv_qp {
    struct ibv_context *context;
    void *qp_context;
    void *pd;
    struct ibv_cq *send_cq;
    struct ibv_cq *recv_cq;
    void *srq;
    uint32_t handle;
    uint32_t qp_num;
};

struct ibv_cq {
    struct ibv_context *context;
};
#endif

uint32_t tidefs_ibv_mr_lkey(struct ibv_mr *mr) {
    return mr->lkey;
}

uint32_t tidefs_ibv_qp_num(struct ibv_qp *qp) {
    return qp->qp_num;
}

int tidefs_ibv_post_send(struct ibv_qp *qp, struct ibv_send_wr *wr,
                         struct ibv_send_wr **bad_wr) {
#ifdef TIDEFS_HAVE_VERBS_H
    return ibv_post_send(qp, wr, bad_wr);
#else
    return qp->context->ops.post_send(qp, wr, bad_wr);
#endif
}

int tidefs_ibv_post_recv(struct ibv_qp *qp, struct ibv_recv_wr *wr,
                         struct ibv_recv_wr **bad_wr) {
#ifdef TIDEFS_HAVE_VERBS_H
    return ibv_post_recv(qp, wr, bad_wr);
#else
    return qp->context->ops.post_recv(qp, wr, bad_wr);
#endif
}

int tidefs_ibv_poll_cq(struct ibv_cq *cq, int num_entries, struct ibv_wc *wc) {
#ifdef TIDEFS_HAVE_VERBS_H
    return ibv_poll_cq(cq, num_entries, wc);
#else
    return cq->context->ops.poll_cq(cq, num_entries, wc);
#endif
}
