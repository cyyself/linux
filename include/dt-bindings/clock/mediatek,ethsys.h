/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * Copyright (c) 2021 MediaTek Inc.
 * Author: Sam Shih <sam.shih@mediatek.com>
 */

#ifndef _DT_BINDINGS_CLK_MEDIATEK_ETHSYS_H
#define _DT_BINDINGS_CLK_MEDIATEK_ETHSYS_H

/* SGMIISYS_0 */

#define CLK_SGMII0_TX250M_EN		0
#define CLK_SGMII0_RX250M_EN		1
#define CLK_SGMII0_CDR_REF		2
#define CLK_SGMII0_CDR_FB		3

/* SGMIISYS_1 */

#define CLK_SGMII1_TX250M_EN		0
#define CLK_SGMII1_RX250M_EN		1
#define CLK_SGMII1_CDR_REF		2
#define CLK_SGMII1_CDR_FB		3

/* ETHSYS */

#define CLK_ETH_FE_EN			0
#define CLK_ETH_GP2_EN			1
#define CLK_ETH_GP1_EN			2
#define CLK_ETH_WOCPU1_EN		3
#define CLK_ETH_WOCPU0_EN		4

#endif
