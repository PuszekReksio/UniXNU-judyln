// SPDX-License-Identifier: BSD-2-Clause-Patent
// SDM845 GCC registers used by UFS, transcribed from the public Linux
// gcc-sdm845.c clock driver (enable/halt register of each branch). judyln port
// of the sheng SM8550 header; no write is performed by NativeUfs yet.
#ifndef NATIVE_UFS_GCC_UFS_H
#define NATIVE_UFS_GCC_UFS_H

// Physical windows from the SDM845 DT (clock-controller@100000, ufshc@1d84000 reg 0x2500).
#define GCC_BASE                      0x00100000ULL
#define UFS_HC_BASE                   0x01d84000ULL
#define UFS_HC_SIZE                   0x2500ULL

#define GCC_UFS_PHY_GDSCR             0x77004

#define GCC_UFS_PHY_AXI_ENABLE        0x7700c
#define GCC_UFS_PHY_AHB_ENABLE        0x77010
#define GCC_UFS_PHY_TX_SYMBOL0_ENABLE 0x77014
#define GCC_UFS_PHY_RX_SYMBOL0_ENABLE 0x77018
#define GCC_UFS_PHY_UNIPRO_CORE_ENABLE 0x77054
#define GCC_UFS_PHY_ICE_CORE_ENABLE   0x77058
#define GCC_UFS_PHY_PHY_AUX_ENABLE    0x7708c
#define GCC_UFS_PHY_RX_SYMBOL1_ENABLE 0x770a8
// gcc_aggre_ufs_phy_axi_clk; SDM845 has no separate UFS mem-PHY GDSC (SM8550 0x9e000)
#define GCC_AGGRE_UFS_PHY_AXI_ENABLE  0x82024

#define GCC_UFS_BRANCH_ENABLE_BIT     0x1U

// The reset and RPMh/TCSR/QMP-PHY programming are not represented here: their
// semantics are not qualified and NativeUfs must not write them speculatively.
#endif
