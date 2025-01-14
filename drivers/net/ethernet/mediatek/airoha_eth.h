/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2024 AIROHA Inc
 * Author: Lorenzo Bianconi <lorenzo@kernel.org>
 */

#ifndef AIROHA_ETH_H
#define AIROHA_ETH_H

#include <linux/etherdevice.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/of_net.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/reset.h>

#define AIROHA_NPU_NUM_CORES		8
#define AIROHA_MAX_NUM_GDM_PORTS	1
#define AIROHA_MAX_NUM_QDMA		2
#define AIROHA_MAX_NUM_RSTS		3
#define AIROHA_MAX_NUM_XSI_RSTS		5
#define AIROHA_MAX_MTU			2000
#define AIROHA_MAX_PACKET_SIZE		2048
#define AIROHA_NUM_QOS_CHANNELS		4
#define AIROHA_NUM_QOS_QUEUES		8
#define AIROHA_NUM_TX_RING		32
#define AIROHA_NUM_RX_RING		32
#define AIROHA_NUM_NETDEV_TX_RINGS	(AIROHA_NUM_TX_RING + \
					 AIROHA_NUM_QOS_CHANNELS)
#define AIROHA_FE_MC_MAX_VLAN_TABLE	64
#define AIROHA_FE_MC_MAX_VLAN_PORT	16
#define AIROHA_NUM_TX_IRQ		2
#define HW_DSCP_NUM			2048
#define IRQ_QUEUE_LEN(_n)		((_n) ? 1024 : 2048)
#define TX_DSCP_NUM			1024
#define RX_DSCP_NUM(_n)			\
	((_n) ==  2 ? 128 :		\
	 (_n) == 11 ? 128 :		\
	 (_n) == 15 ? 128 :		\
	 (_n) ==  0 ? 1024 : 16)

#define PSE_RSV_PAGES			128
#define PSE_QUEUE_RSV_PAGES		64

#define QDMA_METER_IDX(_n)		((_n) & 0xff)
#define QDMA_METER_GROUP(_n)		(((_n) >> 8) & 0x3)

#define PPE_SRAM_NUM_ENTRIES		(16 * 1024)
#define PPE_DRAM_NUM_ENTRIES		(16 * 1024)
#define PPE_NUM_ENTRIES			(PPE_SRAM_NUM_ENTRIES + PPE_DRAM_NUM_ENTRIES)
#define PPE_EN7581_ENTRY_SIZE		80
#define PPE_EN7581_DRAM_OFFSET		(PPE_EN7581_ENTRY_SIZE * PPE_SRAM_NUM_ENTRIES)

enum {
	QDMA_INT_REG_IDX0,
	QDMA_INT_REG_IDX1,
	QDMA_INT_REG_IDX2,
	QDMA_INT_REG_IDX3,
	QDMA_INT_REG_IDX4,
	QDMA_INT_REG_MAX
};

enum {
	XSI_PCIE0_PORT,
	XSI_PCIE1_PORT,
	XSI_USB_PORT,
	XSI_AE_PORT,
	XSI_ETH_PORT,
};

enum {
	XSI_PCIE0_VIP_PORT_MASK	= BIT(22),
	XSI_PCIE1_VIP_PORT_MASK	= BIT(23),
	XSI_USB_VIP_PORT_MASK	= BIT(25),
	XSI_ETH_VIP_PORT_MASK	= BIT(24),
};

enum {
	DEV_STATE_INITIALIZED,
};

enum {
	CDM_CRSN_QSEL_Q1 = 1,
	CDM_CRSN_QSEL_Q5 = 5,
	CDM_CRSN_QSEL_Q6 = 6,
	CDM_CRSN_QSEL_Q15 = 15,
};

enum {
	CRSN_08 = 0x8,
	CRSN_21 = 0x15, /* KA */
	CRSN_22 = 0x16, /* hit bind and force route to CPU */
	CRSN_24 = 0x18,
	CRSN_25 = 0x19,
};

enum {
	FE_PSE_PORT_CDM1,
	FE_PSE_PORT_GDM1,
	FE_PSE_PORT_GDM2,
	FE_PSE_PORT_GDM3,
	FE_PSE_PORT_PPE1,
	FE_PSE_PORT_CDM2,
	FE_PSE_PORT_CDM3,
	FE_PSE_PORT_CDM4,
	FE_PSE_PORT_PPE2,
	FE_PSE_PORT_GDM4,
	FE_PSE_PORT_CDM5,
	FE_PSE_PORT_DROP = 0xf,
};

enum tx_sched_mode {
	TC_SCH_WRR8,
	TC_SCH_SP,
	TC_SCH_WRR7,
	TC_SCH_WRR6,
	TC_SCH_WRR5,
	TC_SCH_WRR4,
	TC_SCH_WRR3,
	TC_SCH_WRR2,
};

enum trtcm_param_type {
	TRTCM_MISC_MODE, /* meter_en, pps_mode, tick_sel */
	TRTCM_TOKEN_RATE_MODE,
	TRTCM_BUCKETSIZE_SHIFT_MODE,
	TRTCM_BUCKET_COUNTER_MODE,
};

enum trtcm_mode_type {
	TRTCM_COMMIT_MODE,
	TRTCM_PEAK_MODE,
};

enum trtcm_param {
	TRTCM_TICK_SEL = BIT(0),
	TRTCM_PKT_MODE = BIT(1),
	TRTCM_METER_MODE = BIT(2),
};

enum {
	NPU_OP_SET = 1,
	NPU_OP_SET_NO_WAIT,
	NPU_OP_GET,
	NPU_OP_GET_NO_WAIT,
};

enum {
	NPU_FUNC_WIFI,
	NPU_FUNC_TUNNEL,
	NPU_FUNC_NOTIFY,
	NPU_FUNC_DBA,
	NPU_FUNC_TR471,
	NPU_FUNC_PPE,
};

enum {
	NPU_MBOX_ERROR,
	NPU_MBOX_SUCCESS,
};

enum {
	PPE_FUNC_SET_WAIT,
	PPE_FUNC_SET_WAIT_HWNAT_INIT,
	PPE_FUNC_SET_WAIT_HWNAT_DEINIT,
	PPE_FUNC_SET_WAIT_API,
};

enum {
	PPE2_SRAM_SET_ENTRY,
	PPE_SRAM_SET_ENTRY,
	PPE_SRAM_SET_VAL,
	PPE_SRAM_RESET_VAL,
};

enum {
	QDMA_WAN_ETHER = 1,
	QDMA_WAN_PON_XDSL,
};

#define MIN_TOKEN_SIZE				4096
#define MAX_TOKEN_SIZE_OFFSET			17
#define TRTCM_TOKEN_RATE_MASK			GENMASK(23, 6)
#define TRTCM_TOKEN_RATE_FRACTION_MASK		GENMASK(5, 0)

struct airoha_queue_entry {
	union {
		void *buf;
		struct sk_buff *skb;
	};
	dma_addr_t dma_addr;
	u16 dma_len;
};

struct airoha_queue {
	struct airoha_qdma *qdma;

	/* protect concurrent queue accesses */
	spinlock_t lock;
	struct airoha_queue_entry *entry;
	struct airoha_qdma_desc *desc;
	u16 head;
	u16 tail;

	int queued;
	int ndesc;
	int free_thr;
	int buf_size;

	struct napi_struct napi;
	struct page_pool *page_pool;
};

struct airoha_tx_irq_queue {
	struct airoha_qdma *qdma;

	struct napi_struct napi;

	int size;
	u32 *q;
};

struct airoha_hw_stats {
	/* protect concurrent hw_stats accesses */
	spinlock_t lock;
	struct u64_stats_sync syncp;

	/* get_stats64 */
	u64 rx_ok_pkts;
	u64 tx_ok_pkts;
	u64 rx_ok_bytes;
	u64 tx_ok_bytes;
	u64 rx_multicast;
	u64 rx_errors;
	u64 rx_drops;
	u64 tx_drops;
	u64 rx_crc_error;
	u64 rx_over_errors;
	/* ethtool stats */
	u64 tx_broadcast;
	u64 tx_multicast;
	u64 tx_len[7];
	u64 rx_broadcast;
	u64 rx_fragment;
	u64 rx_jabber;
	u64 rx_len[7];
};

struct npu_mbox_metadata {
	union {
		struct {
			u16 wait_rsp:1;
			u16 done:1;
			u16 status:3;
			u16 static_buf:1;
			u16 rsv:5;
			u16 func_id:4;
		};
		u16 data;
	};
};

#define PPE_TYPE_L2B_IPV4	2
#define PPE_TYPE_L2B_IPV4_IPV6	3

struct ppe_mbox_data {
	u32 func_type;
	u32 func_id;
	union {
		struct {
			u8 cds;
			u8 xpon_hal_api;
			u8 wan_xsi;
			u8 ct_joyme4;
			int ppe_type;
			int wan_mode;
			int wan_sel;
		} init_info;
		struct {
			int func_id;
			u32 size;
			u32 data;
		} set_info;
	};
};

struct airoha_qdma {
	struct airoha_eth *eth;
	void __iomem *regs;

	/* protect concurrent irqmask accesses */
	spinlock_t irq_lock;
	u32 irqmask[QDMA_INT_REG_MAX];
	int irq;

	struct airoha_tx_irq_queue q_tx_irq[AIROHA_NUM_TX_IRQ];

	struct airoha_queue q_tx[AIROHA_NUM_TX_RING];
	struct airoha_queue q_rx[AIROHA_NUM_RX_RING];

	/* descriptor and packet buffers for qdma hw forward */
	struct {
		void *desc;
		void *q;
	} hfwd;
};

struct airoha_gdm_port {
	struct airoha_qdma *qdma;
	struct net_device *dev;
	int id;

	struct airoha_hw_stats stats;

	DECLARE_BITMAP(qos_sq_bmap, AIROHA_NUM_QOS_CHANNELS);

	/* qos stats counters */
	u64 cpu_tx_packets;
	u64 fwd_tx_packets;
};

struct airoha_npu {
	struct platform_device *pdev;
	struct device_node *np;

	void __iomem *base;

	struct airoha_npu_core {
		struct airoha_npu *npu;
		struct mutex mbox_mutex;
		struct work_struct wdt_work;
	} cores[AIROHA_NPU_NUM_CORES];
};

struct airoha_ppe {
	struct airoha_eth *eth;

	void *foe;
	dma_addr_t foe_dma;
};

struct airoha_eth {
	struct device *dev;

	unsigned long state;
	void __iomem *fe_regs;

	struct airoha_npu *npu;
	struct airoha_ppe *ppe;

	struct reset_control_bulk_data rsts[AIROHA_MAX_NUM_RSTS];
	struct reset_control_bulk_data xsi_rsts[AIROHA_MAX_NUM_XSI_RSTS];

	struct net_device *napi_dev;

	struct airoha_qdma qdma[AIROHA_MAX_NUM_QDMA];
	struct airoha_gdm_port *ports[AIROHA_MAX_NUM_GDM_PORTS];
};

u32 airoha_rr(void __iomem *base, u32 offset);
void airoha_wr(void __iomem *base, u32 offset, u32 val);
u32 airoha_rmw(void __iomem *base, u32 offset, u32 mask, u32 val);

#define airoha_fe_rr(eth, offset)				\
	airoha_rr((eth)->fe_regs, (offset))
#define airoha_fe_wr(eth, offset, val)				\
	airoha_wr((eth)->fe_regs, (offset), (val))
#define airoha_fe_rmw(eth, offset, mask, val)			\
	airoha_rmw((eth)->fe_regs, (offset), (mask), (val))
#define airoha_fe_set(eth, offset, val)				\
	airoha_rmw((eth)->fe_regs, (offset), 0, (val))
#define airoha_fe_clear(eth, offset, val)			\
	airoha_rmw((eth)->fe_regs, (offset), (val), 0)

#define airoha_qdma_rr(qdma, offset)				\
	airoha_rr((qdma)->regs, (offset))
#define airoha_qdma_wr(qdma, offset, val)			\
	airoha_wr((qdma)->regs, (offset), (val))
#define airoha_qdma_rmw(qdma, offset, mask, val)		\
	airoha_rmw((qdma)->regs, (offset), (mask), (val))
#define airoha_qdma_set(qdma, offset, val)			\
	airoha_rmw((qdma)->regs, (offset), 0, (val))
#define airoha_qdma_clear(qdma, offset, val)			\
	airoha_rmw((qdma)->regs, (offset), (val), 0)

int airoha_ppe_init(struct airoha_eth *eth);
void airoha_ppe_deinit(struct airoha_eth *eth);

#endif /* AIROHA_ETH_H */
