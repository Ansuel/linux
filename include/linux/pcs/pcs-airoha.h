/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LINUX_PCS_AIROHA_H
#define __LINUX_PCS_AIROHA_H

/* XFI_MAC */
#define AIROHA_PCS_XFI_MAC_XFI_GIB_CFG		0x0
#define   AIROHA_PCS_XFI_TX_FC_EN		BIT(5)
#define   AIROHA_PCS_XFI_RX_FC_EN		BIT(4)

struct phylink_pcs *airoha_pcs_create(struct device *dev);
void airoha_pcs_destroy(struct phylink_pcs *pcs);

#endif /* __LINUX_PCS_AIROHA_H */
