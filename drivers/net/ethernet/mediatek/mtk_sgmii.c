// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018-2019 MediaTek Inc.

/* A library for MediaTek SGMII circuit
 *
 * Author: Sean Wang <sean.wang@mediatek.com>
 *
 */

#include <linux/mfd/syscon.h>
#include <linux/of.h>
#include <linux/phylink.h>
#include <linux/pcs/pcs-mtk-lynxi.h>
#include <linux/regmap.h>

#include "mtk_eth_soc.h"

int mtk_sgmii_init(struct mtk_sgmii *ss, struct device *dev,
		   struct device_node *r, u32 ana_rgc3)
{
	struct device_node *np;
	struct regmap *regmap;
	u32 flags;
	int i;

	for (i = 0; i < MTK_MAX_DEVS; i++) {
		np = of_parse_phandle(r, "mediatek,sgmiisys", i);
		if (!np)
			break;

		regmap = syscon_node_to_regmap(np);
		flags = 0;
		if (of_property_read_bool(np, "mediatek,pnswap"))
			flags |= MTK_SGMII_FLAG_PN_SWAP;

		of_node_put(np);

		if (IS_ERR(regmap))
			return PTR_ERR(regmap);

		ss->pcs[i] = mtk_pcs_lynxi_create(dev, regmap, ana_rgc3, flags);
	}

	return 0;
}

struct phylink_pcs *mtk_sgmii_select_pcs(struct mtk_sgmii *ss, int id)
{
	return ss->pcs[id];
}

void mtk_sgmii_destroy(struct mtk_sgmii *ss)
{
	int i;

	if (!ss)
		return;

	for (i = 0; i < MTK_MAX_DEVS; i++)
		mtk_pcs_lynxi_destroy(ss->pcs[i]);
}
