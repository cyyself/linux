// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver
 *
 * Copyright (C) 2014-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

/* File aq_ring.c: Definition of functions for Rx/Tx rings. */

#include "aq_nic.h"
#include "aq_hw.h"
#include "aq_hw_utils.h"
#include "aq_ptp.h"
#include "aq_vec.h"
#include "aq_main.h"

#include <net/xdp.h>
#include <net/page_pool/helpers.h>
#include <linux/filter.h>
#include <linux/bpf_trace.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/device.h>

static inline unsigned int aq_ring_rx_alloc_size(const struct aq_ring_s *ring)
{
	return ring->frame_max + ring->tail_size + ring->page_offset;
}

static int aq_ring_create_page_pool(struct aq_ring_s *ring)
{
	struct aq_nic_s *aq_nic = ring->aq_nic;
	struct device *dev = aq_nic_get_dev(aq_nic);
	struct page_pool_params pp_params = {
		.fast = {
			.order = ring->page_order,
			.pool_size = ring->size,
			.nid = dev_to_node(dev),
			.dev = dev,
			.napi = NULL,
			.dma_dir = READ_ONCE(ring->xdp_prog) ?
					DMA_BIDIRECTIONAL : DMA_FROM_DEVICE,
			.max_len = aq_ring_rx_alloc_size(ring),
			.offset = ring->page_offset,
		},
		.slow = {
			.netdev = aq_nic->ndev,
			.queue_idx = ring->idx,
			.flags = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
		},
	};

	ring->page_pool = page_pool_create(&pp_params);
	if (IS_ERR(ring->page_pool)) {
		int err = PTR_ERR(ring->page_pool);

		ring->page_pool = NULL;
		return err;
	}

	return 0;
}

static void aq_get_rxpages_xdp(struct aq_ring_buff_s *buff,
			       struct xdp_buff *xdp)
{
	struct skb_shared_info *sinfo;
	int i;

	if (xdp_buff_has_frags(xdp)) {
		sinfo = xdp_get_shared_info_from_buff(xdp);

		for (i = 0; i < sinfo->nr_frags; i++)
			page_pool_ref_page(skb_frag_page(&sinfo->frags[i]));
	}

	page_pool_ref_page(buff->rxdata.page);
}

static int aq_ring_buf_alloc(struct aq_ring_s *ring,
			      struct aq_ring_buff_s *buff)
{
	struct page_pool *pp = ring->page_pool;
	unsigned int alloc_size = aq_ring_rx_alloc_size(ring);
	unsigned int offset = 0;
	struct page *page;

	if (unlikely(!pp))
		return -ENOMEM;

	page = page_pool_dev_alloc_frag(pp, &offset, alloc_size);
	if (unlikely(!page))
		return -ENOMEM;

	buff->rxdata.page = page;
	buff->rxdata.daddr = page_pool_get_dma_addr(page);
	buff->rxdata.order = ring->page_order;
	buff->rxdata.pg_off = offset + ring->page_offset;
	buff->flags = 0U;
	buff->len = ring->frame_max;
	buff->is_cleaned = 0;
	buff->pa = buff->rxdata.daddr + buff->rxdata.pg_off;

	return 0;
}

static void aq_ring_put_rxpage(struct aq_ring_s *ring,
			     struct aq_ring_buff_s *buff,
			     unsigned int sync_len,
			     bool allow_direct)
{
	if (!ring->page_pool || !buff->rxdata.page)
		return;

	page_pool_put_page(ring->page_pool, buff->rxdata.page,
				 sync_len, allow_direct);
	buff->rxdata.page = NULL;
}

static void aq_ring_release_rx_chain(struct aq_ring_s *ring,
				       struct aq_ring_buff_s *buff,
				       bool allow_direct)
{
	struct aq_ring_buff_s *cur = buff;

	while (cur) {
		aq_ring_put_rxpage(ring, cur,
				     aq_ring_rx_alloc_size(ring),
				     allow_direct);
		cur->is_cleaned = true;

		if (cur->is_eop)
			break;
		if (cur->next >= ring->size)
			break;
		cur = &ring->buff_ring[cur->next];
	}
}

static int aq_ring_alloc(struct aq_ring_s *self,
			 struct aq_nic_s *aq_nic)
{
	int err = 0;

	self->buff_ring =
		kcalloc(self->size, sizeof(struct aq_ring_buff_s), GFP_KERNEL);

	if (!self->buff_ring) {
		err = -ENOMEM;
		goto err_exit;
	}

	self->dx_ring = dma_alloc_coherent(aq_nic_get_dev(aq_nic),
					   self->size * self->dx_size,
					   &self->dx_ring_pa, GFP_KERNEL);
	if (!self->dx_ring) {
		err = -ENOMEM;
		goto err_exit;
	}

err_exit:
	if (err < 0) {
		aq_ring_free(self);
	}

	return err;
}

int aq_ring_tx_alloc(struct aq_ring_s *self,
		     struct aq_nic_s *aq_nic,
		     unsigned int idx,
		     struct aq_nic_cfg_s *aq_nic_cfg)
{
	self->aq_nic = aq_nic;
	self->idx = idx;
	self->size = aq_nic_cfg->txds;
	self->dx_size = aq_nic_cfg->aq_hw_caps->txd_size;

	return aq_ring_alloc(self, aq_nic);
}

int aq_ring_rx_alloc(struct aq_ring_s *self,
		     struct aq_nic_s *aq_nic,
		     unsigned int idx,
		     struct aq_nic_cfg_s *aq_nic_cfg)
{
	int err;

	self->aq_nic = aq_nic;
	self->idx = idx;
	self->size = aq_nic_cfg->rxds;
	self->dx_size = aq_nic_cfg->aq_hw_caps->rxd_size;
	self->xdp_prog = aq_nic->xdp_prog;
	self->frame_max = AQ_CFG_RX_FRAME_MAX;
	self->page_pool = NULL;

	/* Only order-2 is allowed if XDP is enabled */
	if (READ_ONCE(self->xdp_prog)) {
		self->page_offset = AQ_XDP_HEADROOM;
		self->page_order = AQ_CFG_XDP_PAGEORDER;
		self->tail_size = AQ_XDP_TAILROOM;
	} else {
		self->page_offset = 0;
		self->page_order = fls(self->frame_max / PAGE_SIZE +
				       (self->frame_max % PAGE_SIZE ? 1 : 0)) - 1;
		if (aq_nic_cfg->rxpageorder > self->page_order)
			self->page_order = aq_nic_cfg->rxpageorder;
		self->tail_size = 0;
	}

	err = aq_ring_alloc(self, aq_nic);
	if (err)
		return err;

	err = aq_ring_create_page_pool(self);
	if (err) {
		aq_ring_free(self);
		return err;
	}

	return 0;
}

int
aq_ring_hwts_rx_alloc(struct aq_ring_s *self, struct aq_nic_s *aq_nic,
		      unsigned int idx, unsigned int size, unsigned int dx_size)
{
	struct device *dev = aq_nic_get_dev(aq_nic);
	size_t sz = size * dx_size + AQ_CFG_RXDS_DEF;

	memset(self, 0, sizeof(*self));

	self->aq_nic = aq_nic;
	self->idx = idx;
	self->size = size;
	self->dx_size = dx_size;

	self->dx_ring = dma_alloc_coherent(dev, sz, &self->dx_ring_pa,
					   GFP_KERNEL);
	if (!self->dx_ring) {
		aq_ring_free(self);
		return -ENOMEM;
	}

	return 0;
}

int aq_ring_init(struct aq_ring_s *self, const enum atl_ring_type ring_type)
{
	self->hw_head = 0;
	self->sw_head = 0;
	self->sw_tail = 0;
	self->ring_type = ring_type;

	if (self->ring_type == ATL_RING_RX)
		u64_stats_init(&self->stats.rx.syncp);
	else
		u64_stats_init(&self->stats.tx.syncp);

	return 0;
}

static inline bool aq_ring_dx_in_range(unsigned int h, unsigned int i,
				       unsigned int t)
{
	return (h < t) ? ((h < i) && (i < t)) : ((h < i) || (i < t));
}

void aq_ring_update_queue_state(struct aq_ring_s *ring)
{
	if (aq_ring_avail_dx(ring) <= AQ_CFG_SKB_FRAGS_MAX)
		aq_ring_queue_stop(ring);
	else if (aq_ring_avail_dx(ring) > AQ_CFG_RESTART_DESC_THRES)
		aq_ring_queue_wake(ring);
}

void aq_ring_queue_wake(struct aq_ring_s *ring)
{
	struct net_device *ndev = aq_nic_get_ndev(ring->aq_nic);

	if (__netif_subqueue_stopped(ndev,
				     AQ_NIC_RING2QMAP(ring->aq_nic,
						      ring->idx))) {
		netif_wake_subqueue(ndev,
				    AQ_NIC_RING2QMAP(ring->aq_nic, ring->idx));
		u64_stats_update_begin(&ring->stats.tx.syncp);
		ring->stats.tx.queue_restarts++;
		u64_stats_update_end(&ring->stats.tx.syncp);
	}
}

void aq_ring_queue_stop(struct aq_ring_s *ring)
{
	struct net_device *ndev = aq_nic_get_ndev(ring->aq_nic);

	if (!__netif_subqueue_stopped(ndev,
				      AQ_NIC_RING2QMAP(ring->aq_nic,
						       ring->idx)))
		netif_stop_subqueue(ndev,
				    AQ_NIC_RING2QMAP(ring->aq_nic, ring->idx));
}

bool aq_ring_tx_clean(struct aq_ring_s *self)
{
	struct device *dev = aq_nic_get_dev(self->aq_nic);
	unsigned int budget;

	for (budget = AQ_CFG_TX_CLEAN_BUDGET;
	     budget && self->sw_head != self->hw_head; budget--) {
		struct aq_ring_buff_s *buff = &self->buff_ring[self->sw_head];

		if (likely(buff->is_mapped)) {
			if (unlikely(buff->is_sop)) {
				if (!buff->is_eop &&
				    buff->eop_index != 0xffffU &&
				    (!aq_ring_dx_in_range(self->sw_head,
						buff->eop_index,
						self->hw_head)))
					break;

				dma_unmap_single(dev, buff->pa, buff->len,
						 DMA_TO_DEVICE);
			} else {
				dma_unmap_page(dev, buff->pa, buff->len,
					       DMA_TO_DEVICE);
			}
		}

		if (likely(!buff->is_eop))
			goto out;

		if (buff->skb) {
			u64_stats_update_begin(&self->stats.tx.syncp);
			++self->stats.tx.packets;
			self->stats.tx.bytes += buff->skb->len;
			u64_stats_update_end(&self->stats.tx.syncp);
			dev_kfree_skb_any(buff->skb);
		} else if (buff->xdpf) {
			u64_stats_update_begin(&self->stats.tx.syncp);
			++self->stats.tx.packets;
			self->stats.tx.bytes += xdp_get_frame_len(buff->xdpf);
			u64_stats_update_end(&self->stats.tx.syncp);
			xdp_return_frame_rx_napi(buff->xdpf);
		}

out:
		buff->skb = NULL;
		buff->xdpf = NULL;
		buff->pa = 0U;
		buff->eop_index = 0xffffU;
		self->sw_head = aq_ring_next_dx(self, self->sw_head);
	}

	return !!budget;
}

static void aq_rx_checksum(struct aq_ring_s *self,
			   struct aq_ring_buff_s *buff,
			   struct sk_buff *skb)
{
	if (!(self->aq_nic->ndev->features & NETIF_F_RXCSUM))
		return;

	if (unlikely(buff->is_cso_err)) {
		u64_stats_update_begin(&self->stats.rx.syncp);
		++self->stats.rx.errors;
		u64_stats_update_end(&self->stats.rx.syncp);
		skb->ip_summed = CHECKSUM_NONE;
		return;
	}
	if (buff->is_ip_cso) {
		__skb_incr_checksum_unnecessary(skb);
	} else {
		skb->ip_summed = CHECKSUM_NONE;
	}

	if (buff->is_udp_cso || buff->is_tcp_cso)
		__skb_incr_checksum_unnecessary(skb);
}

int aq_xdp_xmit(struct net_device *dev, int num_frames,
		struct xdp_frame **frames, u32 flags)
{
	struct aq_nic_s *aq_nic = netdev_priv(dev);
	unsigned int vec, i, drop = 0;
	int cpu = smp_processor_id();
	struct aq_nic_cfg_s *aq_cfg;
	struct aq_ring_s *ring;

	aq_cfg = aq_nic_get_cfg(aq_nic);
	vec = cpu % aq_cfg->vecs;
	ring = aq_nic->aq_ring_tx[AQ_NIC_CFG_TCVEC2RING(aq_cfg, 0, vec)];

	for (i = 0; i < num_frames; i++) {
		struct xdp_frame *xdpf = frames[i];

		if (aq_nic_xmit_xdpf(aq_nic, ring, xdpf) == NETDEV_TX_BUSY)
			drop++;
	}

	return num_frames - drop;
}

static struct sk_buff *aq_xdp_build_skb(struct xdp_buff *xdp,
					struct net_device *dev,
					struct aq_ring_buff_s *buff)
{
	struct xdp_frame *xdpf;
	struct sk_buff *skb;

	xdpf = xdp_convert_buff_to_frame(xdp);
	if (unlikely(!xdpf))
		return NULL;

	skb = xdp_build_skb_from_frame(xdpf, dev);
	if (!skb)
		return NULL;

	skb_mark_for_recycle(skb);
	aq_get_rxpages_xdp(buff, xdp);
	return skb;
}

static struct sk_buff *aq_xdp_run_prog(struct aq_nic_s *aq_nic,
				       struct xdp_buff *xdp,
				       struct aq_ring_s *rx_ring,
				       struct aq_ring_buff_s *buff)
{
	int result = NETDEV_TX_BUSY;
	struct aq_ring_s *tx_ring;
	struct xdp_frame *xdpf;
	struct bpf_prog *prog;
	u32 act = XDP_ABORTED;
	struct sk_buff *skb;

	u64_stats_update_begin(&rx_ring->stats.rx.syncp);
	++rx_ring->stats.rx.packets;
	rx_ring->stats.rx.bytes += xdp_get_buff_len(xdp);
	u64_stats_update_end(&rx_ring->stats.rx.syncp);

	prog = READ_ONCE(rx_ring->xdp_prog);
	if (!prog)
		return aq_xdp_build_skb(xdp, aq_nic->ndev, buff);

	prefetchw(xdp->data_hard_start); /* xdp_frame write */

	/* single buffer XDP program, but packet is multi buffer, aborted */
	if (xdp_buff_has_frags(xdp) && !prog->aux->xdp_has_frags)
		goto out_aborted;

	act = bpf_prog_run_xdp(prog, xdp);
	switch (act) {
	case XDP_PASS:
		skb = aq_xdp_build_skb(xdp, aq_nic->ndev, buff);
		if (!skb)
			goto out_aborted;
		u64_stats_update_begin(&rx_ring->stats.rx.syncp);
		++rx_ring->stats.rx.xdp_pass;
		u64_stats_update_end(&rx_ring->stats.rx.syncp);
		return skb;
	case XDP_TX:
		xdpf = xdp_convert_buff_to_frame(xdp);
		if (unlikely(!xdpf))
			goto out_aborted;
		tx_ring = aq_nic->aq_ring_tx[rx_ring->idx];
		result = aq_nic_xmit_xdpf(aq_nic, tx_ring, xdpf);
		if (result == NETDEV_TX_BUSY)
			goto out_aborted;
		u64_stats_update_begin(&rx_ring->stats.rx.syncp);
		++rx_ring->stats.rx.xdp_tx;
		u64_stats_update_end(&rx_ring->stats.rx.syncp);
		aq_get_rxpages_xdp(buff, xdp);
		break;
	case XDP_REDIRECT:
		if (xdp_do_redirect(aq_nic->ndev, xdp, prog) < 0)
			goto out_aborted;
		xdp_do_flush();
		u64_stats_update_begin(&rx_ring->stats.rx.syncp);
		++rx_ring->stats.rx.xdp_redirect;
		u64_stats_update_end(&rx_ring->stats.rx.syncp);
		aq_get_rxpages_xdp(buff, xdp);
		break;
	default:
		fallthrough;
	case XDP_ABORTED:
out_aborted:
		u64_stats_update_begin(&rx_ring->stats.rx.syncp);
		++rx_ring->stats.rx.xdp_aborted;
		u64_stats_update_end(&rx_ring->stats.rx.syncp);
		trace_xdp_exception(aq_nic->ndev, prog, act);
		bpf_warn_invalid_xdp_action(aq_nic->ndev, prog, act);
		break;
	case XDP_DROP:
		u64_stats_update_begin(&rx_ring->stats.rx.syncp);
		++rx_ring->stats.rx.xdp_drop;
		u64_stats_update_end(&rx_ring->stats.rx.syncp);
		break;
	}

	return ERR_PTR(-result);
}

static bool aq_add_rx_fragment(struct aq_ring_s *ring,
			       struct aq_ring_buff_s *buff,
			       struct xdp_buff *xdp)
{
	struct skb_shared_info *sinfo = xdp_get_shared_info_from_buff(xdp);
	struct aq_ring_buff_s *buff_ = buff;

	memset(sinfo, 0, sizeof(*sinfo));
	do {
		skb_frag_t *frag;

		if (unlikely(sinfo->nr_frags >= MAX_SKB_FRAGS))
			return true;

		frag = &sinfo->frags[sinfo->nr_frags++];
		buff_ = &ring->buff_ring[buff_->next];
		page_pool_dma_sync_for_cpu(ring->page_pool,
					    buff_->rxdata.page,
					    buff_->rxdata.pg_off,
					    buff_->len);
		sinfo->xdp_frags_size += buff_->len;
		skb_frag_fill_page_desc(frag, buff_->rxdata.page,
					buff_->rxdata.pg_off,
					buff_->len);
		page_pool_ref_page(buff_->rxdata.page);

		buff_->is_cleaned = 1;

		buff->is_ip_cso &= buff_->is_ip_cso;
		buff->is_udp_cso &= buff_->is_udp_cso;
		buff->is_tcp_cso &= buff_->is_tcp_cso;
		buff->is_cso_err |= buff_->is_cso_err;

		if (page_is_pfmemalloc(buff_->rxdata.page))
			xdp_buff_set_frag_pfmemalloc(xdp);

	} while (!buff_->is_eop);

	xdp_buff_set_frags_flag(xdp);

	return false;
}

static int __aq_ring_rx_clean(struct aq_ring_s *self, struct napi_struct *napi,
			      int *work_done, int budget)
{
	struct net_device *ndev = aq_nic_get_ndev(self->aq_nic);
	int err = 0;

	for (; (self->sw_head != self->hw_head) && budget;
		self->sw_head = aq_ring_next_dx(self, self->sw_head),
		--budget, ++(*work_done)) {
		struct aq_ring_buff_s *buff = &self->buff_ring[self->sw_head];
		bool is_ptp_ring = aq_ptp_ring(self->aq_nic, self);
		struct aq_ring_buff_s *buff_ = NULL;
		struct sk_buff *skb = NULL;
		unsigned int next_ = 0U;
		unsigned int i = 0U;
		u16 hdr_len;

		if (buff->is_cleaned)
			continue;

		if (!buff->is_eop) {
			unsigned int frag_cnt = 0U;
			buff_ = buff;
			do {
				bool is_rsc_completed = true;

				if (buff_->next >= self->size) {
					err = -EIO;
					goto err_exit;
				}

				frag_cnt++;
				next_ = buff_->next;
				buff_ = &self->buff_ring[next_];
				is_rsc_completed =
					aq_ring_dx_in_range(self->sw_head,
							    next_,
							    self->hw_head);

				if (unlikely(!is_rsc_completed) ||
						frag_cnt > MAX_SKB_FRAGS) {
					err = 0;
					goto err_exit;
				}

				buff->is_error |= buff_->is_error;
				buff->is_cso_err |= buff_->is_cso_err;

			} while (!buff_->is_eop);

			if (buff->is_error ||
			    (buff->is_lro && buff->is_cso_err)) {
				u64_stats_update_begin(&self->stats.rx.syncp);
				++self->stats.rx.errors;
				u64_stats_update_end(&self->stats.rx.syncp);
				aq_ring_release_rx_chain(self, buff, true);
				continue;
			}
		}

		if (buff->is_error) {
			u64_stats_update_begin(&self->stats.rx.syncp);
			++self->stats.rx.errors;
			u64_stats_update_end(&self->stats.rx.syncp);
			aq_ring_release_rx_chain(self, buff, true);
			continue;
		}

		page_pool_dma_sync_for_cpu(self->page_pool,
					 buff->rxdata.page,
					 buff->rxdata.pg_off,
					 buff->len);

		skb = napi_alloc_skb(napi, AQ_CFG_RX_HDR_SIZE);
		if (unlikely(!skb)) {
			u64_stats_update_begin(&self->stats.rx.syncp);
			self->stats.rx.skb_alloc_fails++;
			u64_stats_update_end(&self->stats.rx.syncp);
			err = -ENOMEM;
			goto err_exit;
		}
		skb_mark_for_recycle(skb);
		if (is_ptp_ring)
			buff->len -=
				aq_ptp_extract_ts(self->aq_nic, skb_hwtstamps(skb),
						  aq_buf_vaddr(&buff->rxdata),
						  buff->len);

		hdr_len = buff->len;
		if (hdr_len > AQ_CFG_RX_HDR_SIZE)
			hdr_len = eth_get_headlen(skb->dev,
						  aq_buf_vaddr(&buff->rxdata),
						  AQ_CFG_RX_HDR_SIZE);

		memcpy(__skb_put(skb, hdr_len), aq_buf_vaddr(&buff->rxdata),
		       ALIGN(hdr_len, sizeof(long)));

		if (buff->len - hdr_len > 0) {
			skb_add_rx_frag(skb, i++, buff->rxdata.page,
					buff->rxdata.pg_off + hdr_len,
					buff->len - hdr_len,
					self->frame_max);
			page_pool_ref_page(buff->rxdata.page);
		}

		if (!buff->is_eop) {
			buff_ = buff;
			do {
				next_ = buff_->next;
				buff_ = &self->buff_ring[next_];

			page_pool_dma_sync_for_cpu(self->page_pool,
						    buff_->rxdata.page,
						    buff_->rxdata.pg_off,
						    buff_->len);
				skb_add_rx_frag(skb, i++,
						buff_->rxdata.page,
						buff_->rxdata.pg_off,
						buff_->len,
						self->frame_max);
				page_pool_ref_page(buff_->rxdata.page);
				buff_->is_cleaned = 1;

				buff->is_ip_cso &= buff_->is_ip_cso;
				buff->is_udp_cso &= buff_->is_udp_cso;
				buff->is_tcp_cso &= buff_->is_tcp_cso;
				buff->is_cso_err |= buff_->is_cso_err;

			} while (!buff_->is_eop);
		}

		if (buff->is_vlan)
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
					       buff->vlan_rx_tag);

		skb->protocol = eth_type_trans(skb, ndev);

		aq_rx_checksum(self, buff, skb);

		skb_set_hash(skb, buff->rss_hash,
			     buff->is_hash_l4 ? PKT_HASH_TYPE_L4 :
			     PKT_HASH_TYPE_NONE);
		/* Send all PTP traffic to 0 queue */
		skb_record_rx_queue(skb,
				    is_ptp_ring ? 0
						: AQ_NIC_RING2QMAP(self->aq_nic,
								   self->idx));

		u64_stats_update_begin(&self->stats.rx.syncp);
		++self->stats.rx.packets;
		self->stats.rx.bytes += skb->len;
		u64_stats_update_end(&self->stats.rx.syncp);

		napi_gro_receive(napi, skb);

		aq_ring_release_rx_chain(self, buff, true);
	}

err_exit:
	return err;
}

static int __aq_ring_xdp_clean(struct aq_ring_s *rx_ring,
			       struct napi_struct *napi, int *work_done,
			       int budget)
{
	int frame_sz = rx_ring->page_offset + rx_ring->frame_max +
		       rx_ring->tail_size;
	struct aq_nic_s *aq_nic = rx_ring->aq_nic;
	bool is_rsc_completed = true;
	int err = 0;
	for (; (rx_ring->sw_head != rx_ring->hw_head) && budget;
		rx_ring->sw_head = aq_ring_next_dx(rx_ring, rx_ring->sw_head),
		--budget, ++(*work_done)) {
		struct aq_ring_buff_s *buff = &rx_ring->buff_ring[rx_ring->sw_head];
		bool is_ptp_ring = aq_ptp_ring(rx_ring->aq_nic, rx_ring);
		struct aq_ring_buff_s *buff_ = NULL;
		u16 ptp_hwtstamp_len = 0;
		struct skb_shared_hwtstamps shhwtstamps;
		struct sk_buff *skb = NULL;
		unsigned int next_ = 0U;
		struct xdp_buff xdp;
		void *hard_start;

		if (buff->is_cleaned)
			continue;

		if (!buff->is_eop) {
			buff_ = buff;
			do {
				if (buff_->next >= rx_ring->size) {
					err = -EIO;
					goto err_exit;
				}
				next_ = buff_->next;
				buff_ = &rx_ring->buff_ring[next_];
				is_rsc_completed =
					aq_ring_dx_in_range(rx_ring->sw_head,
							    next_,
							    rx_ring->hw_head);

				if (unlikely(!is_rsc_completed))
					break;

				buff->is_error |= buff_->is_error;
				buff->is_cso_err |= buff_->is_cso_err;
			} while (!buff_->is_eop);

			if (!is_rsc_completed) {
				err = 0;
				goto err_exit;
			}
			if (buff->is_error ||
			    (buff->is_lro && buff->is_cso_err)) {
				u64_stats_update_begin(&rx_ring->stats.rx.syncp);
				++rx_ring->stats.rx.errors;
				u64_stats_update_end(&rx_ring->stats.rx.syncp);
				aq_ring_release_rx_chain(rx_ring, buff, true);
				continue;
			}
		}

		if (buff->is_error) {
			u64_stats_update_begin(&rx_ring->stats.rx.syncp);
			++rx_ring->stats.rx.errors;
			u64_stats_update_end(&rx_ring->stats.rx.syncp);
			aq_ring_release_rx_chain(rx_ring, buff, true);
			continue;
		}

		page_pool_dma_sync_for_cpu(rx_ring->page_pool,
					  buff->rxdata.page,
					  buff->rxdata.pg_off,
					  buff->len);
		hard_start = page_address(buff->rxdata.page) +
			     buff->rxdata.pg_off - rx_ring->page_offset;

		if (is_ptp_ring) {
			ptp_hwtstamp_len = aq_ptp_extract_ts(rx_ring->aq_nic, &shhwtstamps,
							     aq_buf_vaddr(&buff->rxdata),
							     buff->len);
			buff->len -= ptp_hwtstamp_len;
		}

		xdp_init_buff(&xdp, frame_sz, &rx_ring->xdp_rxq);
		xdp_prepare_buff(&xdp, hard_start, rx_ring->page_offset,
				 buff->len, false);
		if (!buff->is_eop) {
			if (aq_add_rx_fragment(rx_ring, buff, &xdp)) {
				u64_stats_update_begin(&rx_ring->stats.rx.syncp);
				++rx_ring->stats.rx.packets;
				rx_ring->stats.rx.bytes += xdp_get_buff_len(&xdp);
				++rx_ring->stats.rx.xdp_aborted;
				u64_stats_update_end(&rx_ring->stats.rx.syncp);
				aq_ring_release_rx_chain(rx_ring, buff, true);
				continue;
			}
		}

		skb = aq_xdp_run_prog(aq_nic, &xdp, rx_ring, buff);
		if (IS_ERR(skb) || !skb) {
			aq_ring_release_rx_chain(rx_ring, buff, true);
			continue;
		}

		if (ptp_hwtstamp_len > 0)
			*skb_hwtstamps(skb) = shhwtstamps;

		if (buff->is_vlan)
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
					       buff->vlan_rx_tag);

		aq_rx_checksum(rx_ring, buff, skb);

		skb_set_hash(skb, buff->rss_hash,
			     buff->is_hash_l4 ? PKT_HASH_TYPE_L4 :
			     PKT_HASH_TYPE_NONE);
		/* Send all PTP traffic to 0 queue */
		skb_record_rx_queue(skb,
				    is_ptp_ring ? 0
						: AQ_NIC_RING2QMAP(rx_ring->aq_nic,
								   rx_ring->idx));

		napi_gro_receive(napi, skb);
		aq_ring_release_rx_chain(rx_ring, buff, true);
	}

err_exit:
	return err;
}

int aq_ring_rx_clean(struct aq_ring_s *self,
		     struct napi_struct *napi,
		     int *work_done,
		     int budget)
{
	if (static_branch_unlikely(&aq_xdp_locking_key))
		return __aq_ring_xdp_clean(self, napi, work_done, budget);
	else
		return __aq_ring_rx_clean(self, napi, work_done, budget);
}

void aq_ring_hwts_rx_clean(struct aq_ring_s *self, struct aq_nic_s *aq_nic)
{
#if IS_REACHABLE(CONFIG_PTP_1588_CLOCK)
	while (self->sw_head != self->hw_head) {
		u64 ns;

		aq_nic->aq_hw_ops->extract_hwts(aq_nic->aq_hw,
						self->dx_ring +
						(self->sw_head * self->dx_size),
						self->dx_size, &ns);
		aq_ptp_tx_hwtstamp(aq_nic, ns);

		self->sw_head = aq_ring_next_dx(self, self->sw_head);
	}
#endif
}

int aq_ring_rx_fill(struct aq_ring_s *self)
{
	struct aq_ring_buff_s *buff = NULL;
	int err = 0;
	int i = 0;

	if (aq_ring_avail_dx(self) < min_t(unsigned int, AQ_CFG_RX_REFILL_THRES,
					   self->size / 2))
		return err;

	for (i = aq_ring_avail_dx(self); i--;
		self->sw_tail = aq_ring_next_dx(self, self->sw_tail)) {
		buff = &self->buff_ring[self->sw_tail];

		if (buff->rxdata.page)
			aq_ring_put_rxpage(self, buff, self->frame_max, true);

		err = aq_ring_buf_alloc(self, buff);
		if (err) {
			u64_stats_update_begin(&self->stats.rx.syncp);
			self->stats.rx.alloc_fails++;
			u64_stats_update_end(&self->stats.rx.syncp);
			goto err_exit;
		}
	}

err_exit:
	return err;
}

void aq_ring_rx_deinit(struct aq_ring_s *self)
{
	if (!self)
		return;

	for (; self->sw_head != self->sw_tail;
		self->sw_head = aq_ring_next_dx(self, self->sw_head)) {
		struct aq_ring_buff_s *buff = &self->buff_ring[self->sw_head];

		aq_ring_put_rxpage(self, buff, aq_ring_rx_alloc_size(self), false);
	}
}

void aq_ring_free(struct aq_ring_s *self)
{
	if (!self)
		return;

	if (self->page_pool) {
		page_pool_destroy(self->page_pool);
		self->page_pool = NULL;
	}

	kfree(self->buff_ring);
	self->buff_ring = NULL;

	if (self->dx_ring) {
		dma_free_coherent(aq_nic_get_dev(self->aq_nic),
				  self->size * self->dx_size, self->dx_ring,
				  self->dx_ring_pa);
		self->dx_ring = NULL;
	}
}

void aq_ring_hwts_rx_free(struct aq_ring_s *self)
{
	if (!self)
		return;

	if (self->dx_ring) {
		dma_free_coherent(aq_nic_get_dev(self->aq_nic),
				  self->size * self->dx_size + AQ_CFG_RXDS_DEF,
				  self->dx_ring, self->dx_ring_pa);
		self->dx_ring = NULL;
	}
}

unsigned int aq_ring_fill_stats_data(struct aq_ring_s *self, u64 *data)
{
	unsigned int count;
	unsigned int start;

	if (self->ring_type == ATL_RING_RX) {
		/* This data should mimic aq_ethtool_queue_rx_stat_names structure */
		do {
			count = 0;
			start = u64_stats_fetch_begin(&self->stats.rx.syncp);
			data[count] = self->stats.rx.packets;
			data[++count] = self->stats.rx.jumbo_packets;
			data[++count] = self->stats.rx.lro_packets;
			data[++count] = self->stats.rx.errors;
			data[++count] = self->stats.rx.alloc_fails;
			data[++count] = self->stats.rx.skb_alloc_fails;
			data[++count] = self->stats.rx.polls;
			data[++count] = self->stats.rx.pg_flips;
			data[++count] = self->stats.rx.pg_reuses;
			data[++count] = self->stats.rx.pg_losts;
			data[++count] = self->stats.rx.xdp_aborted;
			data[++count] = self->stats.rx.xdp_drop;
			data[++count] = self->stats.rx.xdp_pass;
			data[++count] = self->stats.rx.xdp_tx;
			data[++count] = self->stats.rx.xdp_invalid;
			data[++count] = self->stats.rx.xdp_redirect;
		} while (u64_stats_fetch_retry(&self->stats.rx.syncp, start));
	} else {
		/* This data should mimic aq_ethtool_queue_tx_stat_names structure */
		do {
			count = 0;
			start = u64_stats_fetch_begin(&self->stats.tx.syncp);
			data[count] = self->stats.tx.packets;
			data[++count] = self->stats.tx.queue_restarts;
		} while (u64_stats_fetch_retry(&self->stats.tx.syncp, start));
	}

	return ++count;
}
