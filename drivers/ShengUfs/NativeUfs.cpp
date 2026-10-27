// SPDX-License-Identifier: BSD-2-Clause-Patent
// judyln (SDM845) read-only UFS probe. probe(), mapPhys() and inspect() are
// ShengUfs e2b32cc code with the SDM845 constants of GccUfs.h; the storage
// path (NativeUfsFull.cpp.txt) needs the generated storage ABI headers and is
// not built yet. Default-off: native-ufs-probe=2 reads GCC and host registers,
// 6 dumps the firmware request list, 3/4/5/9 adopt the controller and issue
// read-only SCSI commands (ShengUfs adoptAndRead). Storage is never written.
#include <IOKit/IOService.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <libkern/crypto/sha2.h>
#include <kern/thread.h>
#include <sys/param.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSSharedPtr.h>
#include <pexpert/pexpert.h>
#include <kern/debug.h>
#include "GccUfs.h"
#include "RootDiagnostics.h"
#include "SmmuTakeover.h"
#include "TransferPoll.h"

static UfsRootDiagnostics gRootDiagnostic;
static bool gRootDiagnosticEnabled;

// Probe-only build: SMMU failures are reported by the panic that follows.
static void rootDiagnosticFailure (const char *reason)
{
  (void) reason;
}

extern "C" {
volatile uint32_t native_ufs_probe_calls = 0;
volatile uint32_t native_ufs_matched = 0;
volatile uint32_t native_ufs_probe_requested = 0;
}

class NativeUfs : public IOService {
  OSDeclareDefaultStructors (NativeUfs)
  void inspect (void);
  void adoptAndRead (unsigned level);
  void dumpFirmwareList (void);
  static bool waitSet (uintptr_t base, unsigned offset, uint32_t mask, unsigned loops);
public:
  IOService *probe (IOService *provider, SInt32 *score) override;
  bool start (IOService *provider) override;
};

OSDefineMetaClassAndStructors (NativeUfs, IOService)

static uint32_t read32 (uintptr_t base, unsigned offset)
{
  return *reinterpret_cast<volatile uint32_t *> (base + offset);
}

static void write32 (uintptr_t base, unsigned offset, uint32_t value)
{
  *reinterpret_cast<volatile uint32_t *> (base + offset) = value;
}

static bool contains (const char *data, size_t length, const char *needle)
{
  size_t wanted = 0;
  while (needle[wanted]) {
    wanted++;
  }
  for (size_t at = 0; at + wanted <= length; at++) {
    size_t index = 0;
    while (index < wanted && data[at + index] == needle[index]) {
      index++;
    }
    if (index == wanted) {
      return true;
    }
  }
  return false;
}

IOService *NativeUfs::probe (IOService *provider, SInt32 *score)
{
  native_ufs_probe_calls = native_ufs_probe_calls + 1;
  if (OSDynamicCast (IOPlatformExpertDevice, provider)) {
    // Second personality (KernelConfigTables: IOMatchCategory NativeUfsRoot): attaches to the
    // root device, which starts before the platform expert publishes IOResources, so the
    // hardware probes run before the original AMFI (whose start panics without a PMGR).
    native_ufs_matched = 1;
    if (score) {
      *score = 500;
    }
    return this;
  }
  OSObject *property = provider->getProperty ("compatible");
  OSData *data = OSDynamicCast (OSData, property);
  OSString *string = OSDynamicCast (OSString, property);
  bool match = false;
  if (data) {
    const char *text = static_cast<const char *> (data->getBytesNoCopy ());
    match = text && (contains (text, data->getLength (), "qcom,sm8550-ufshc") || contains (text, data->getLength (), "qcom,sdm845-ufshc"));
  } else if (string) {
    const char *text = string->getCStringNoCopy ();
    match = text && (contains (text, string->getLength (), "qcom,sm8550-ufshc") || contains (text, string->getLength (), "qcom,sdm845-ufshc"));
  }
  if (!match) {
    return nullptr;
  }
  native_ufs_matched = 1;
  if (score) {
    *score = 1000;
  }
  return this;
}

bool NativeUfs::waitSet (uintptr_t base, unsigned offset, uint32_t mask, unsigned loops)
{
  for (unsigned index = 0; index < loops; index++) {
    if ((read32 (base, offset) & mask) == mask) {
      return true;
    }
    IODelay (1);
  }
  return false;
}

// Read-only inspection (native-ufs-probe=2): reports what firmware left behind.
static uintptr_t mapPhys (uint64_t phys, uint64_t length, OSSharedPtr<IOMemoryMap> &keep)
{
  IODeviceMemory *memory = IODeviceMemory::withRange (phys, length);
  if (!memory) {
    return 0;
  }
  keep = OSSharedPtr<IOMemoryMap> (memory->map (kIOMapAnywhere | kIOMapInhibitCache), OSNoRetain);
  memory->release ();
  return keep ? static_cast<uintptr_t> (keep->getVirtualAddress ()) : 0;
}

void NativeUfs::inspect (void)
{
  OSSharedPtr<IOMemoryMap> gccMap, memPhyMap, hcMap;
  uintptr_t gcc = mapPhys (GCC_BASE + 0x77000, 0x1000, gccMap);
  // judyln: SDM845 has no mem-PHY GDSC; report the aggre UFS AXI branch in its slot
  uintptr_t memPhy = mapPhys (GCC_BASE + (GCC_AGGRE_UFS_PHY_AXI_ENABLE & ~0xfffULL), 0x1000, memPhyMap);
  if (!gcc || !memPhy) {
    panic ("NATIVE_UFS inspect: GCC map failed gcc=%p memphy=%p", (void *) gcc, (void *) memPhy);
  }
  uint32_t gdsc = read32 (gcc, GCC_UFS_PHY_GDSCR - 0x77000);
  uint32_t axi = read32 (gcc, GCC_UFS_PHY_AXI_ENABLE - 0x77000);
  uint32_t ahb = read32 (gcc, GCC_UFS_PHY_AHB_ENABLE - 0x77000);
  uint32_t unipro = read32 (gcc, GCC_UFS_PHY_UNIPRO_CORE_ENABLE - 0x77000);
  uint32_t txs = read32 (gcc, GCC_UFS_PHY_TX_SYMBOL0_ENABLE - 0x77000);
  uint32_t rxs = read32 (gcc, GCC_UFS_PHY_RX_SYMBOL0_ENABLE - 0x77000);
  uint32_t aux = read32 (gcc, GCC_UFS_PHY_PHY_AUX_ENABLE - 0x77000);
  uint32_t memGdsc = read32 (memPhy, GCC_AGGRE_UFS_PHY_AXI_ENABLE & 0xfff);
  // GDSCR bit31 PWR_ON; CBCR bit31 CLK_OFF.
  bool powered = (gdsc & 0x80000000U) != 0;
  // Hardware 2026-10-17: AXI running, AHB enabled but CLK_OFF (bit31). With bit1 (HW gating)
  // set the branch wakes on access, so enable bits, not CLK_OFF, gate the read-only probe.
  bool busClocks = !(axi & 0x80000000U) && (ahb & 0x1U) && (axi & 0x1U);
  uint32_t cap = 0, ver = 0, hcs = 0, hce = 0, utrlba = 0, is = 0;
  unsigned readHc = 0;
  if (powered && busClocks) {
    uintptr_t hc = mapPhys (UFS_HC_BASE, UFS_HC_SIZE, hcMap);
    if (hc) {
      cap = read32 (hc, 0x00);
      ver = read32 (hc, 0x08);
      is = read32 (hc, 0x20);
      hcs = read32 (hc, 0x30);
      hce = read32 (hc, 0x34);
      utrlba = read32 (hc, 0x50);
      readHc = 1;
    }
  }
  panic ("NATIVE_UFS inspect\n"
         "gdsc=%08x aggreaxi=%08x\n"
         "axi=%08x ahb=%08x unipro=%08x\n"
         "txsym=%08x rxsym=%08x aux=%08x\n"
         "hc_read=%u cap=%08x ver=%08x\n"
         "is=%08x hcs=%08x hce=%08x utrlba=%08x",
         gdsc, memGdsc, axi, ahb, unipro, txs, rxs, aux, readHc, cap, ver, is, hcs, hce, utrlba);
}

namespace {
struct UfsResult {
  uint32_t ocs;      // UTRD overall command status; 0xf = never completed
  uint32_t response; // UPIU response byte
  uint32_t scsi;     // SCSI status byte
  uint32_t sense;    // sense key<<16 | ASC<<8 | ASCQ from the response UPIU's autosense data
  uint32_t senseLen; // sense data length reported by the device
  uint32_t seg;      // UPIU data segment length
};

static void be32 (uint8_t *at, uint32_t value)
{
  at[0] = value >> 24; at[1] = value >> 16; at[2] = value >> 8; at[3] = value;
}

static uint32_t getBe32 (const uint8_t *at)
{
  return (uint32_t (at[0]) << 24) | (uint32_t (at[1]) << 16) | (uint32_t (at[2]) << 8) | at[3];
}
}

static void cacheClean (const void *start, size_t length)
{
  uintptr_t address = reinterpret_cast<uintptr_t> (start) & ~uintptr_t (63);
  uintptr_t end = reinterpret_cast<uintptr_t> (start) + length;
  for (; address < end; address += 64) {
    __asm__ volatile ("dc cvac, %0" :: "r" (address) : "memory");
  }
  __asm__ volatile ("dsb sy" ::: "memory");
}

static void cacheCleanInvalidate (const void *start, size_t length)
{
  uintptr_t address = reinterpret_cast<uintptr_t> (start) & ~uintptr_t (63);
  uintptr_t end = reinterpret_cast<uintptr_t> (start) + length;
  for (; address < end; address += 64) {
    __asm__ volatile ("dc civac, %0" :: "r" (address) : "memory");
  }
  __asm__ volatile ("dsb sy" ::: "memory");
}

// The region is mapped as device memory: only aligned element-sized stores are allowed
// (bzero's block zeroing faulted on hardware, 2026-10-17).
static void zero32 (void *start, size_t length)
{
  volatile uint32_t *word = static_cast<volatile uint32_t *> (start);
  for (size_t index = 0; index < length / 4; index++) {
    word[index] = 0;
  }
}


// Give the UFS stream a pass-through mapping the way Linux does on this firmware.
// Hardware 2026-10-17: after hand-off apps_smmu has sCR0 = 0x002f0406 (USFCFG=1, unmatched
// streams fault), no stream-match entry for the UFS host (ID 0x60, `iommus = <&apps_smmu 0x60
// 0x0>` in the board DT), a TYPE=BYPASS S2CR reads back as FAULT, and sCR0 writes are ignored.
// Linux (drivers/iommu/arm/arm-smmu/arm-smmu-qcom.c, qcom_smmu_cfg_probe + qcom_smmu_write_s2cr,
// "bypass_quirk") meets exactly this: it reserves the LAST context bank (num_context_banks-1),
// writes SCTLR=0 (stage 1 disabled) and CBAR.TYPE=S1_TRANS_S2_BYPASS there, and maps a bypass
// stream as S2CR TYPE=TRANSLATE with CBNDX = that bank. S2CR is written before SMR
// (arm_smmu_write_sme). ARM IHI 0062D.c table 3-1 additionally requires VA64=1
// for inputs above 32 bits even with SCTLR.M=0. Storage DMA path only; this
// is physical pass-through, not a page-table or Adreno 4 KiB qualification.
static void smmuBypassStream (uint16_t stream, OSSharedPtr<IOMemoryMap> &keep, uint32_t *report,
                              uint64_t dma, uint64_t bytes)
{
  uintptr_t smmu = mapPhys (0x15000000ULL, 0xd0000, keep);
  if (!smmu) {
    panic ("NATIVE_UFS smmu: map failed");
  }
  UfsSmmuPlan plan = planUfsSmmu (stream, dma, bytes, [smmu](unsigned offset) { return read32 (smmu, offset); });
  gRootDiagnostic.smmuId1 = read32 (smmu, 0x24);
  gRootDiagnostic.smmuId2 = read32 (smmu, 0x28);
  gRootDiagnostic.smmuSlot = plan.slot;
  if (plan.error) {
    gRootDiagnostic.stage = "SMMU planning";
    gRootDiagnostic.result = static_cast<uint32_t> (kIOReturnNotReady);
    gRootDiagnostic.smr = plan.smr; gRootDiagnostic.s2cr = plan.s2cr;
    rootDiagnosticFailure (plan.error);
    panic ("NATIVE_UFS smmu: %s slot=%u smr=%x s2cr=%x", plan.error, plan.slot, plan.smr, plan.s2cr);
  }
  unsigned bank = plan.bank, index = plan.slot;
  uintptr_t cb = smmu + (plan.pages + bank) * 4096;
  const char *failure = configureUfsSmmu (plan, stream,
    [smmu](unsigned offset) { return read32 (smmu, offset); },
    [smmu](unsigned offset, uint32_t value) {
      write32 (smmu, offset, value);
      __asm__ volatile ("dsb sy" ::: "memory");
    });
  uint32_t smr = read32 (smmu, 0x800 + 4 * index), s2cr = read32 (smmu, 0xc00 + 4 * index);
  uint32_t cbar = read32 (smmu, 0x1000 + 4 * bank), sctlr = read32 (cb, 0x0);
  gRootDiagnostic.smr = smr; gRootDiagnostic.s2cr = s2cr;
  gRootDiagnostic.cbar = cbar; gRootDiagnostic.sctlr = sctlr;
  gRootDiagnostic.smmuId2 = read32 (smmu, 0x28);
  gRootDiagnostic.cba2r = read32 (smmu, 0x1800 + 4 * bank);
  if (failure) {
    gRootDiagnostic.stage = "SMMU readback";
    gRootDiagnostic.result = static_cast<uint32_t> (kIOReturnNotReady);
    rootDiagnosticFailure (failure);
    panic ("NATIVE_UFS smmu: %s idx=%u bank=%u cba2r=%x", failure, index, bank,
           gRootDiagnostic.cba2r);
  }
  report[0] = index | (bank << 16);
  report[1] = cbar;
  report[2] = sctlr;
}

void NativeUfs::adoptAndRead (unsigned level)
{
  OSSharedPtr<IOMemoryMap> hcMap;
  uintptr_t hc = mapPhys (UFS_HC_BASE, UFS_HC_SIZE, hcMap);
  if (!hc) {
    panic ("NATIVE_UFS adopt: controller map failed");
  }
  // The controller's own request list is the one region its DMA is known to reach
  // (hardware 2026-10-17: a kernel-allocated buffer at 0xf080f000 reset the system when the
  // first command was issued, and nothing below 0xc8000000 is allocatable). The firmware
  // zeroed it; use 16 KiB from UTRLBA as ordinary cached memory (the DT marks the host
  // dma-coherent). Test instrument only: the kernel may also own these pages.
  uint64_t fwList = (uint64_t (read32 (hc, 0x54)) << 32) | read32 (hc, 0x50);
  if (!fwList || (fwList & 0xfff)) {
    panic ("NATIVE_UFS adopt: no usable firmware list base=%llx", fwList);
  }
  IOMemoryDescriptor *region = IOMemoryDescriptor::withPhysicalAddress (fwList, 16384, kIODirectionInOut);
  OSSharedPtr<IOMemoryMap> regionMap;
  if (region) {
    regionMap = OSSharedPtr<IOMemoryMap> (region->map (kIOMapAnywhere), OSNoRetain);
    region->release ();
  }
  if (!regionMap) {
    panic ("NATIVE_UFS adopt: firmware list map failed base=%llx", fwList);
  }
  uint8_t *virt = reinterpret_cast<uint8_t *> (regionMap->getVirtualAddress ());
  uint64_t phys = fwList;
  zero32 (virt, 16384);
  cacheClean (virt, 16384);
  // Layout: [0,4096) request list (slot 0 used), [4096,5120) command + response UPIU +
  // PRDT, [8192,16384) data.
  const uint32_t ucdOffset = 4096, rspOffset = 512, prdtOffset = 1024, dataOffset = 8192;
  uint32_t hcsBefore = read32 (hc, 0x30);
  uint32_t doorbellBefore = read32 (hc, 0x58);
  if (doorbellBefore != 0 || read32 (hc, 0x78) != 0) {
    panic ("NATIVE_UFS adopt: firmware request outstanding doorbell=%08x hcs=%08x", doorbellBefore, hcsBefore);
  }
  OSSharedPtr<IOMemoryMap> smmuMap;
  uint32_t smmuReport[3] = { 0, 0, 0 };
  write32 (hc, 0x24, 0);            // mask interrupts
  write32 (hc, 0x60, 0);            // stop the firmware's request list
  __asm__ volatile ("dsb sy" ::: "memory");
  unsigned stopLoops = 10000;
  while ((read32 (hc, 0x60) & 1) && stopLoops--) IODelay (10);
  if (read32 (hc, 0x60) & 1) panic ("NATIVE_UFS adopt: request list did not stop");
  // judyln: UEFI's own DMA already reaches this list region through apps_smmu, so the
  // SM8550 bypass takeover stays off unless native-ufs-smmu=1 asks for it.
  unsigned smmuTakeover = 0;
  PE_parse_boot_argn ("native-ufs-smmu", &smmuTakeover, sizeof (smmuTakeover));
  if (smmuTakeover == 1) {
    smmuBypassStream (0x100, smmuMap, smmuReport, phys, 16384);   // SDM845 ufshc iommus = <&apps_smmu 0x100 0xf>
  }
  write32 (hc, 0x50, static_cast<uint32_t> (phys));
  write32 (hc, 0x54, static_cast<uint32_t> (phys >> 32));
  write32 (hc, 0x20, 0xffffffffU);  // clear stale status
  write32 (hc, 0x60, 1);
  if (!waitSet (hc, 0x30, 0x2, 100000)) {
    panic ("NATIVE_UFS adopt: request list not ready hcs=%08x", read32 (hc, 0x30));
  }
  if (level == 3) {
    panic ("NATIVE_UFS adopt: list replaced\n"
           "phys=%llx hcs=%08x->%08x\n"
           "is=%08x db=%08x rsr=%08x ba=%08x bau=%08x ie=%08x",
           phys, hcsBefore, read32 (hc, 0x30), read32 (hc, 0x20), read32 (hc, 0x58),
           read32 (hc, 0x60), read32 (hc, 0x50), read32 (hc, 0x54), read32 (hc, 0x24));
  }

  auto command = [&] (uint8_t lun, const uint8_t *cdb, unsigned cdbLength, bool toHost, uint32_t length) -> UfsResult {
    uint8_t *utrd = virt;
    uint8_t *ucd = virt + ucdOffset;
    zero32 (utrd, 32);
    zero32 (ucd, 1024 + 16);
    zero32 (virt + dataOffset, 8192);
    ucd[0] = 0x01;                  // COMMAND UPIU
    ucd[1] = toHost ? 0x40 : 0x00;  // flags: read
    ucd[2] = lun;
    ucd[3] = 0;                     // task tag
    be32 (ucd + 12, length);        // expected data transfer length
    for (unsigned index = 0; index < cdbLength; index++) {
      ucd[16 + index] = cdb[index];
    }
    uint64_t ucdPhys = phys + ucdOffset;
    uint32_t direction = length ? (toHost ? 2U : 1U) : 0U;
    *reinterpret_cast<uint32_t *> (utrd + 0) = 0x10000000U | (direction << 25);
    *reinterpret_cast<uint32_t *> (utrd + 8) = 0x0fU;     // OCS: not completed
    *reinterpret_cast<uint32_t *> (utrd + 16) = static_cast<uint32_t> (ucdPhys);
    *reinterpret_cast<uint32_t *> (utrd + 20) = static_cast<uint32_t> (ucdPhys >> 32);
    *reinterpret_cast<uint32_t *> (utrd + 24) = (512U >> 2) | ((rspOffset >> 2) << 16);   // response length | offset (dwords)
    uint32_t prdEntries = length ? 1U : 0U;
    *reinterpret_cast<uint32_t *> (utrd + 28) = prdEntries | ((prdtOffset >> 2) << 16);
    if (length) {
      uint64_t dataPhys = phys + dataOffset;
      uint8_t *prd = ucd + prdtOffset;
      *reinterpret_cast<uint32_t *> (prd + 0) = static_cast<uint32_t> (dataPhys);
      *reinterpret_cast<uint32_t *> (prd + 4) = static_cast<uint32_t> (dataPhys >> 32);
      *reinterpret_cast<uint32_t *> (prd + 12) = length - 1;
    }
    cacheClean (virt, 16384);
    write32 (hc, 0x20, 0xffffffffU);
    write32 (hc, 0x58, 1);          // ring slot 0
    UfsResult result = { 0xf, 0xff, 0xff, 0, 0, 0 };
    bool done = false;
    for (unsigned loops = 0; loops < 100000; loops++) {
      if (!(read32 (hc, 0x58) & 1)) {
        done = true;
        break;
      }
      IODelay (1);
    }
    cacheCleanInvalidate (virt, 16384);
    if (!done) {
      return result;
    }
    result.ocs = *reinterpret_cast<volatile uint32_t *> (utrd + 8) & 0xff;
    const uint8_t *rsp = ucd + rspOffset;
    result.response = rsp[6];
    result.scsi = rsp[7];
    // Response UPIU: 12-byte header, residual count, 16 reserved bytes, then the data segment
    // (2-byte sense length + sense data) at offset 32.
    result.seg = (uint32_t (rsp[10]) << 8) | rsp[11];
    result.senseLen = (uint32_t (rsp[32]) << 8) | rsp[33];
    result.sense = ((rsp[36] & 0xfU) << 16) | (uint32_t (rsp[46]) << 8) | rsp[47];
    return result;
  };

  // NOP OUT (kind 0) and Query read requests (kind 1: opcode 0x05 READ FLAG, 0x03 READ ATTRIBUTE).
  // Read-only: no data segment, no state change on the device. Returns the UPIU response byte and
  // the 32-bit value field (attributes) or flag byte via *value; ocs 0xf means no completion.
  auto query = [&] (unsigned kind, uint8_t opcode, uint8_t idn, uint32_t *value, uint32_t *respByte) -> uint32_t {
    uint8_t *utrd = virt;
    uint8_t *ucd = virt + ucdOffset;
    zero32 (utrd, 32);
    zero32 (ucd, 1024 + 16);
    if (kind == 0) {
      ucd[0] = 0x00;                // NOP OUT
    } else {
      ucd[0] = 0x16;                // QUERY REQUEST
      ucd[5] = 0x01;                // query function (header dword 1, byte 1): standard read request
      ucd[12] = opcode;
      ucd[13] = idn;
    }
    ucd[3] = 1;                     // task tag
    uint64_t ucdPhys = phys + ucdOffset;
    *reinterpret_cast<uint32_t *> (utrd + 0) = 0x10000000U;
    *reinterpret_cast<uint32_t *> (utrd + 8) = 0x0fU;
    *reinterpret_cast<uint32_t *> (utrd + 16) = static_cast<uint32_t> (ucdPhys);
    *reinterpret_cast<uint32_t *> (utrd + 20) = static_cast<uint32_t> (ucdPhys >> 32);
    *reinterpret_cast<uint32_t *> (utrd + 24) = (512U >> 2) | ((rspOffset >> 2) << 16);
    *reinterpret_cast<uint32_t *> (utrd + 28) = (prdtOffset >> 2) << 16;
    cacheClean (virt, 16384);
    write32 (hc, 0x20, 0xffffffffU);
    write32 (hc, 0x58, 1);
    bool done = false;
    for (unsigned loops = 0; loops < 100000; loops++) {
      if (!(read32 (hc, 0x58) & 1)) {
        done = true;
        break;
      }
      IODelay (1);
    }
    cacheCleanInvalidate (virt, 16384);
    if (!done) {
      return 0xf;
    }
    const uint8_t *rsp = ucd + rspOffset;
    *respByte = (uint32_t (rsp[0]) << 8) | rsp[6];     // response type << 8 | query/NOP response
    *value = getBe32 (rsp + 20);
    return *reinterpret_cast<volatile uint32_t *> (utrd + 8) & 0xff;
  };
  // Device state before waking it. Hardware 2026-10-17: NOP OUT answers, fDeviceInit = 0 (done),
  // bCurrentPowerMode = 0x33 (UFS-PowerDown) and every LU returns NOT READY. Linux resumes the
  // device with START STOP UNIT (power condition ACTIVE) to the UFS Device well-known LU 0xD0
  // (ufshcd_set_dev_pwr_mode); no user data is touched.
  uint32_t powerBefore = 0, powerAfter = 0, queryResp = 0, ignoredValue = 0;
  uint32_t wakeStatus = 0xee;
  if (level == 5 || level == 9) {
    query (1, 0x03, 0x02, &powerBefore, &queryResp);     // READ ATTRIBUTE bCurrentPowerMode
    uint8_t ssu[6] = { 0x1b, 0, 0, 0, 0x10, 0 };          // START STOP UNIT, power condition ACTIVE
    UfsResult w = command (0xd0, ssu, 6, false, 0);
    wakeStatus = (w.ocs << 16) | (w.response << 8) | w.scsi;
    for (unsigned settle = 0; settle < 50; settle++) {
      IODelay (1000);
    }
    query (1, 0x03, 0x02, &powerAfter, &queryResp);
    (void) ignoredValue;
  }
  if (level == 4) {
    uint8_t tur0[6] = { 0, 0, 0, 0, 0, 0 };
    UfsResult t = command (0, tur0, 6, false, 0);
    const uint8_t *rsp0 = virt + ucdOffset + rspOffset;
    panic ("NATIVE_UFS adopt: TEST UNIT READY lun0\n"
           "ocs=%x resp=%02x scsi=%02x\n"
           "phys=%llx hcs=%08x->%08x smmu idx/bank=%08x cbar=%08x\n"
           "is=%08x db=%08x rsr=%08x\n"
           "rsp=%08x %08x",
           t.ocs, t.response, t.scsi, phys, hcsBefore, read32 (hc, 0x30), smmuReport[0], smmuReport[1],
           read32 (hc, 0x20), read32 (hc, 0x58), read32 (hc, 0x60), getBe32 (rsp0), getBe32 (rsp0 + 4));
  }
  uint32_t hcsAfter = 0;
  const unsigned maxLun = 6;
  uint32_t status[maxLun], last[maxLun], blockSize[maxLun], senseOf[maxLun];
  for (unsigned lun = 0; lun < maxLun; lun++) {
    status[lun] = 0xee; last[lun] = 0; blockSize[lun] = 0; senseOf[lun] = 0;
    uint8_t tur[6] = { 0x00, 0, 0, 0, 0, 0 };
    UfsResult r = { 0xf, 0xff, 0xff, 0, 0, 0 };
    for (unsigned attempt = 0; attempt < 3; attempt++) {
      r = command (static_cast<uint8_t> (lun), tur, 6, false, 0);
      if (lun == 0 && attempt == 0 && r.ocs == 0xf) {
        // Never completed: stop here and report instead of waiting out every command.
        const uint8_t *rsp = virt + ucdOffset + rspOffset;
        panic ("NATIVE_UFS adopt: first command did not complete\n"
               "phys=%llx hcs=%08x->%08x\n"
               "is=%08x db=%08x rsr=%08x ba=%08x\n"
               "utrd2=%08x rsp=%08x %08x",
               phys, hcsBefore, read32 (hc, 0x30),
               read32 (hc, 0x20), read32 (hc, 0x58), read32 (hc, 0x60), read32 (hc, 0x50),
               *reinterpret_cast<volatile uint32_t *> (virt + 8), getBe32 (rsp), getBe32 (rsp + 4));
      }
      if (r.ocs == 0 && r.scsi == 0) {
        break;
      }
    }
    uint8_t cap[10] = { 0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    r = command (static_cast<uint8_t> (lun), cap, 10, true, 8);
    status[lun] = (r.ocs << 16) | (r.response << 8) | r.scsi;
    senseOf[lun] = r.sense;
    if (r.ocs == 0 && r.scsi == 0) {
      last[lun] = getBe32 (virt + dataOffset);
      blockSize[lun] = getBe32 (virt + dataOffset + 4);
    }
  }
  if (level == 9) {
    // Read-only GPT survey of LUN 0 (4096-byte blocks): header fields and CRCs for before/after
    // comparison, then every non-empty entry among the first 64. Nothing is written.
    if (blockSize[0] != 4096) {
      panic ("NATIVE_UFS gpt: unexpected LUN0 block size %08x", blockSize[0]);
    }
    uint8_t rd[10] = { 0x28, 0, 0, 0, 0, 1, 0, 0, 1, 0 };
    UfsResult h = command (0, rd, 10, true, 4096);
    if (h.ocs != 0 || h.scsi != 0) {
      panic ("NATIVE_UFS gpt: header read failed ocs=%x resp=%x scsi=%x", h.ocs, h.response, h.scsi);
    }
    const uint8_t *hdr = virt + dataOffset;
    auto le32 = [] (const uint8_t *at) -> uint32_t {
      return uint32_t (at[0]) | (uint32_t (at[1]) << 8) | (uint32_t (at[2]) << 16) | (uint32_t (at[3]) << 24);
    };
    auto le64 = [&] (const uint8_t *at) -> uint64_t {
      return uint64_t (le32 (at)) | (uint64_t (le32 (at + 4)) << 32);
    };
    uint32_t sig0 = le32 (hdr), sig1 = le32 (hdr + 4), hdrCrc = le32 (hdr + 16), entCrc = le32 (hdr + 88);
    uint64_t curLba = le64 (hdr + 24), bakLba = le64 (hdr + 32), firstUsable = le64 (hdr + 40), lastUsable = le64 (hdr + 48);
    uint64_t entLba = le64 (hdr + 72);
    uint32_t entCount = le32 (hdr + 80), entSize = le32 (hdr + 84);
    uint32_t guid0 = le32 (hdr + 56), guid1 = le32 (hdr + 60), guid2 = le32 (hdr + 64), guid3 = le32 (hdr + 68);
    if (sig0 != 0x20494645U || sig1 != 0x54524150U || entSize != 128 || entLba > 64) {
      panic ("NATIVE_UFS gpt: unexpected header sig=%08x %08x esz=%u elba=%llx", sig0, sig1, entSize, entLba);
    }
    uint32_t shown = entCount > 64 ? 64 : entCount;
    uint32_t blocks = (shown * 128 + 4095) / 4096;
    uint8_t rd2[10] = { 0x28, 0, 0, 0, 0, uint8_t (entLba), 0, 0, uint8_t (blocks), 0 };
    UfsResult e = command (0, rd2, 10, true, blocks * 4096);
    if (e.ocs != 0 || e.scsi != 0) {
      panic ("NATIVE_UFS gpt: entries read failed ocs=%x scsi=%x", e.ocs, e.scsi);
    }
    const uint8_t *ents = virt + dataOffset;
    static char text[3400];
    int used = snprintf (text, sizeof (text),
                         "NATIVE_UFS gpt LUN0 hdr crc=%08x ents crc=%08x cnt=%u\n"
                         "cur=%llx backup=%llx usable=%llx..%llx elba=%llx\n"
                         "disk guid %08x %08x %08x %08x last=%08x\n",
                         hdrCrc, entCrc, entCount, curLba, bakLba, firstUsable, lastUsable, entLba,
                         guid0, guid1, guid2, guid3, last[0]);
    unsigned column = 0, listed = 0;
    for (uint32_t index = 0; index < shown && used < int (sizeof (text)) - 80; index++) {
      const uint8_t *entry = ents + index * 128;
      bool empty = true;
      for (unsigned b = 0; b < 16; b++) {
        if (entry[b]) { empty = false; break; }
      }
      if (empty) {
        continue;
      }
      char name[14];
      for (unsigned c = 0; c < 13; c++) {
        uint8_t lo = entry[56 + 2 * c], hi = entry[57 + 2 * c];
        name[c] = (hi == 0 && lo >= 32 && lo < 127) ? char (lo) : (lo ? '?' : 0);
        if (!name[c]) { name[c] = 0; break; }
      }
      name[13] = 0;
      used += snprintf (text + used, sizeof (text) - used, "%u:%s %llx-%llx%s", index, name,
                        le64 (entry + 32), le64 (entry + 40), (++column % 3) ? "  " : "\n");
      listed++;
    }
    snprintf (text + used, sizeof (text) - used, "\nlisted=%u", listed);
    panic ("%s", text);
  }
  // INQUIRY of LUN 0: vendor/product bytes 8..23.
  uint8_t inquiry[6] = { 0x12, 0, 0, 0, 36, 0 };
  UfsResult inq = command (0, inquiry, 6, true, 36);
  uint32_t inqWord[4] = { 0, 0, 0, 0 };
  for (unsigned index = 0; index < 4; index++) {
    inqWord[index] = getBe32 (virt + dataOffset + 8 + index * 4);
  }
  // LBA 1 of LUN 0 holds the GPT header when the block size is 4096 (or 512).
  uint32_t gptStatus = 0xee, sig0 = 0, sig1 = 0;
  if (blockSize[0] >= 512 && blockSize[0] <= 4096) {
    uint8_t read10[10] = { 0x28, 0, 0, 0, 0, 1, 0, 0, 1, 0 };
    UfsResult g = command (0, read10, 10, true, blockSize[0]);
    gptStatus = (g.ocs << 16) | (g.response << 8) | g.scsi;
    if (g.ocs == 0 && g.scsi == 0) {
      sig0 = *reinterpret_cast<uint32_t *> (virt + dataOffset);
      sig1 = *reinterpret_cast<uint32_t *> (virt + dataOffset + 4);
    }
  }
  hcsAfter = read32 (hc, 0x30);
  panic ("NATIVE_UFS adopt+read\n"
         "hcs %08x->%08x pwr %08x->%08x ssu=%06x\n"
         "L0 st=%06x last=%08x bs=%08x sns=%06x\n"
         "L1 st=%06x last=%08x bs=%08x sns=%06x\n"
         "L2 st=%06x last=%08x bs=%08x sns=%06x\n"
         "L3 st=%06x last=%08x bs=%08x sns=%06x\n"
         "L4 st=%06x last=%08x bs=%08x sns=%06x\n"
         "L5 st=%06x last=%08x bs=%08x sns=%06x\n"
         "inq st=%06x %08x %08x %08x %08x\n"
         "inq sns=%06x slen=%x seg=%x\n"
         "rsp0 %08x %08x %08x %08x\n"
         "rsp8 %08x %08x %08x %08x\n"
         "gpt st=%06x sig=%08x %08x",
         hcsBefore, hcsAfter, powerBefore, powerAfter, wakeStatus,
         status[0], last[0], blockSize[0], senseOf[0], status[1], last[1], blockSize[1], senseOf[1],
         status[2], last[2], blockSize[2], senseOf[2], status[3], last[3], blockSize[3], senseOf[3],
         status[4], last[4], blockSize[4], senseOf[4], status[5], last[5], blockSize[5], senseOf[5],
         (inq.ocs << 16) | (inq.response << 8) | inq.scsi, inqWord[0], inqWord[1], inqWord[2], inqWord[3],
         inq.sense, inq.senseLen, inq.seg,
         getBe32 (virt + ucdOffset + rspOffset), getBe32 (virt + ucdOffset + rspOffset + 4),
         getBe32 (virt + ucdOffset + rspOffset + 8), getBe32 (virt + ucdOffset + rspOffset + 12),
         getBe32 (virt + ucdOffset + rspOffset + 32), getBe32 (virt + ucdOffset + rspOffset + 36),
         getBe32 (virt + ucdOffset + rspOffset + 40), getBe32 (virt + ucdOffset + rspOffset + 44),
         gptStatus, sig0, sig1);
}

// Read-only dump of the request list the firmware left (native-ufs-probe=6): shows where
// the firmware placed its descriptors, to compare with an allocation the controller's DMA
// is known to reach. Nothing is written and no register is touched except reads.
static uint32_t dumpWord (const volatile uint32_t *base, unsigned index)
{
  return base[index];
}

void NativeUfs::dumpFirmwareList (void)
{
  OSSharedPtr<IOMemoryMap> hcMap, listMap, ucdMap;
  uintptr_t hc = mapPhys (UFS_HC_BASE, UFS_HC_SIZE, hcMap);
  if (!hc) {
    panic ("NATIVE_UFS dump: controller map failed");
  }
  uint64_t listPhys = (uint64_t (read32 (hc, 0x54)) << 32) | read32 (hc, 0x50);
  uint32_t db = read32 (hc, 0x58), rsr = read32 (hc, 0x60), hcs = read32 (hc, 0x30);
  IOMemoryDescriptor *listDesc = IOMemoryDescriptor::withPhysicalAddress (listPhys, 4096, kIODirectionIn);
  if (!listDesc) {
    panic ("NATIVE_UFS dump: list descriptor failed phys=%llx", listPhys);
  }
  listMap = OSSharedPtr<IOMemoryMap> (listDesc->map (kIOMapAnywhere), OSNoRetain);
  listDesc->release ();
  if (!listMap) {
    panic ("NATIVE_UFS dump: list map failed phys=%llx", listPhys);
  }
  const volatile uint32_t *utrd = reinterpret_cast<const volatile uint32_t *> (listMap->getVirtualAddress ());
  uint64_t ucdPhys = (uint64_t (dumpWord (utrd, 5)) << 32) | dumpWord (utrd, 4);
  uint32_t ucd0 = 0, ucd1 = 0, ucd2 = 0, ucd3 = 0;
  if (ucdPhys) {
    IOMemoryDescriptor *ucdDesc = IOMemoryDescriptor::withPhysicalAddress (ucdPhys, 4096, kIODirectionIn);
    if (ucdDesc) {
      ucdMap = OSSharedPtr<IOMemoryMap> (ucdDesc->map (kIOMapAnywhere), OSNoRetain);
      ucdDesc->release ();
      if (ucdMap) {
        const volatile uint32_t *ucd = reinterpret_cast<const volatile uint32_t *> (ucdMap->getVirtualAddress ());
        ucd0 = dumpWord (ucd, 0); ucd1 = dumpWord (ucd, 1); ucd2 = dumpWord (ucd, 2); ucd3 = dumpWord (ucd, 3);
      }
    }
  }
  panic ("NATIVE_UFS dump: firmware list\n"
         "list=%llx hcs=%08x db=%08x rsr=%08x\n"
         "utrd0 %08x %08x %08x %08x\n"
         "utrd0 %08x %08x %08x %08x\n"
         "utrd1 %08x %08x %08x %08x\n"
         "ucd=%llx %08x %08x %08x %08x",
         listPhys, hcs, db, rsr,
         dumpWord (utrd, 0), dumpWord (utrd, 1), dumpWord (utrd, 2), dumpWord (utrd, 3),
         dumpWord (utrd, 4), dumpWord (utrd, 5), dumpWord (utrd, 6), dumpWord (utrd, 7),
         dumpWord (utrd, 8), dumpWord (utrd, 9), dumpWord (utrd, 10), dumpWord (utrd, 11),
         ucdPhys, ucd0, ucd1, ucd2, ucd3);
}

namespace {
#include "RootTransportLayout.h"

struct UfsHost {
  OSSharedPtr<IOMemoryMap> hcMap, smmuMap;
  uintptr_t hc;
  IOBufferMemoryDescriptor *dma;
  uint8_t *virt;
  uint64_t phys;
  IOLock *lock;
  bool ready;
  bool poisoned = false;
  uintptr_t smmu = 0, cb = 0;
};
UfsHost gHost = { OSSharedPtr<IOMemoryMap> (), OSSharedPtr<IOMemoryMap> (), 0, nullptr, nullptr, 0, nullptr, false };

static IOReturn recordTransport (IOReturn result, uint32_t ocs)
{
  gRootDiagnostic.result = static_cast<uint32_t> (result);
  gRootDiagnostic.ocs = ocs;
  if (result != kIOReturnSuccess && gRootDiagnosticEnabled) {
    // Read only the already mapped HC's status/registers used by this driver.
    gRootDiagnostic.hcs = read32 (gHost.hc, 0x30);
    gRootDiagnostic.hce = read32 (gHost.hc, 0x34);
    gRootDiagnostic.doorbell = read32 (gHost.hc, 0x58);
    gRootDiagnostic.interrupt = read32 (gHost.hc, 0x20);
    gRootDiagnostic.list = uint64_t (read32 (gHost.hc, 0x50)) |
                          (uint64_t (read32 (gHost.hc, 0x54)) << 32);
    gRootDiagnostic.runStop = read32 (gHost.hc, 0x60);
    gRootDiagnostic.ahit = read32 (gHost.hc, 0x18);
    for (unsigned i = 0; i < 5; ++i) gRootDiagnostic.uic[i] = read32 (gHost.hc, 0x38 + 4 * i);
    if (gHost.smmu && gHost.cb) {
      gRootDiagnostic.gfsr = read32 (gHost.smmu, 0x48);
      gRootDiagnostic.gsyn = read32 (gHost.smmu, 0x54);
      gRootDiagnostic.fsr = read32 (gHost.cb, 0x58);
      gRootDiagnostic.fsyn = read32 (gHost.cb, 0x68);
      gRootDiagnostic.far = uint64_t (read32 (gHost.cb, 0x60)) |
                            (uint64_t (read32 (gHost.cb, 0x64)) << 32);
    }
  }
  return result;
}

static void cacheCivac (const void *start, size_t length)
{
  uintptr_t address = reinterpret_cast<uintptr_t> (start) & ~uintptr_t (63);
  uintptr_t end = reinterpret_cast<uintptr_t> (start) + length;
  for (; address < end; address += 64) {
    __asm__ volatile ("dc civac, %0" :: "r" (address) : "memory");
  }
  __asm__ volatile ("dsb sy" ::: "memory");
}

// Device-owned cache lines must not be written back over DMA results. All
// callers use complete 64-byte lines from the dedicated page-aligned buffer.
static void cacheInvalidate (const void *start, size_t length)
{
  __asm__ volatile ("dsb sy" ::: "memory");
  uintptr_t address = reinterpret_cast<uintptr_t> (start);
  for (uintptr_t end = address + length; address < end; address += 64) {
    __asm__ volatile ("dc ivac, %0" :: "r" (address) : "memory");
  }
  __asm__ volatile ("dsb sy" ::: "memory");
}

static void hostWrite (unsigned offset, uint32_t value)
{
  __asm__ volatile ("dsb sy" ::: "memory");
  write32 (gHost.hc, offset, value);
  __asm__ volatile ("dsb sy" ::: "memory");
}

#include "RootQueue.h"

#include "RootCommands.h"

// Bring the live controller up for reading: map, SMMU pass-through for the UFS stream, take over
// the request list, wake the device from UFS-PowerDown and wait for LUN 0 to be ready.
// `why` receives a short reason on failure.
static bool hostBringUp (const char **why)
{
  if (gHost.poisoned) {
    *why = "transport quarantined";
    return false;
  }
  if (gHost.ready) {
    return true;
  }
  gRootDiagnostic.stage = "controller map";
  gHost.hc = mapPhys (UFS_HC_BASE, UFS_HC_SIZE, gHost.hcMap);
  if (!gHost.hc) {
    *why = "controller map";
    return false;
  }
  if (gRootDiagnosticEnabled) {
    gRootDiagnostic.cap = read32 (gHost.hc, 0x00);
    gRootDiagnostic.version = read32 (gHost.hc, 0x08);
    gRootDiagnostic.hcs = read32 (gHost.hc, 0x30);
    gRootDiagnostic.hce = read32 (gHost.hc, 0x34);
  }
  gRootDiagnostic.stage = "DMA allocation";
  gHost.dma = IOBufferMemoryDescriptor::inTaskWithOptions (
    kernel_task, static_cast<IOOptionBits> (kIODirectionInOut) | static_cast<IOOptionBits> (kIOMemoryPhysicallyContiguous) |
    static_cast<IOOptionBits> (kIOMemoryMapperNone),
    kDmaBytes, 4096);
  gHost.lock = IOLockAlloc ();
  if (!gHost.dma || !gHost.lock) {
    *why = "dma buffer";
    return false;
  }
  gHost.virt = static_cast<uint8_t *> (gHost.dma->getBytesNoCopy ());
  IOByteCount contiguous = 0;
  gHost.phys = gHost.dma->getPhysicalSegment (0, &contiguous, kIOMemoryMapperNone);
  gRootDiagnostic.dma = gHost.phys;
  gRootDiagnostic.contiguous = contiguous;
  if (!gHost.virt || !gHost.phys || (gHost.phys & 4095) || contiguous < kDmaBytes ||
      (!(read32 (gHost.hc, 0) & 0x01000000) && gHost.phys + kDmaBytes > 0x100000000ULL)) {
    *why = "DMA address/contiguity";
    return false;
  }
  bzero (gHost.virt, kDmaBytes);
  cacheCivac (gHost.virt, kDmaBytes);
  uint32_t report[3] = { 0, 0, 0 };
  gRootDiagnostic.stage = "SMMU and request list";
  if (!hostStopQueue (why)) return false;
  // judyln: opt-in like adoptAndRead; without it the kernel buffer relies on the apps_smmu
  // state the firmware left for stream 0x100.
  unsigned smmuTakeover = 0;
  PE_parse_boot_argn ("native-ufs-smmu", &smmuTakeover, sizeof (smmuTakeover));
  if (smmuTakeover == 1) {
    smmuBypassStream (0x100, gHost.smmuMap, report, gHost.phys, kDmaBytes);
    gHost.smmu = gHost.smmuMap->getVirtualAddress ();
    uint32_t idr1 = read32 (gHost.smmu, 0x24);
    gHost.cb = gHost.smmu + ((1U << (((idr1 >> 28) & 7) + 1)) + (report[0] >> 16)) * 4096;
  }
  if (gRootDiagnosticEnabled && gHost.smmu) {
    gRootDiagnostic.gfsrBefore = read32 (gHost.smmu, 0x48);
    gRootDiagnostic.fsrBefore = read32 (gHost.cb, 0x58);
    gRootDiagnostic.smmuId2 = read32 (gHost.smmu, 0x28);
    gRootDiagnostic.cba2r = read32 (gHost.smmu, 0x1800 + 4 * (report[0] >> 16));
  }
  if (!hostStartQueue (why)) return false;
  gRootDiagnostic.stage = "NOP OUT";
  // NOP OUT proves the transport before touching the SCSI layer.
  if (hostNop () != kIOReturnSuccess) {
    gHost.ready = false;
    *why = "NOP OUT";
    return false;
  }
  uint32_t power = 0;
  gRootDiagnostic.stage = "power mode query";
  if (hostQueryRead (0x03, 0x02, &power) != kIOReturnSuccess) {
    gHost.ready = false;
    *why = "power mode query";
    return false;
  }
  gRootDiagnostic.power = power;
  if ((power & 0xff) != 0x11) {
    gRootDiagnostic.stage = "device wake";
    // START STOP UNIT, power condition ACTIVE, to the UFS Device well-known LU (as Linux resumes).
    uint8_t ssu[6] = { 0x1b, 0, 0, 0, 0x10, 0 };
    uint32_t scsi = 0;
    if (hostScsi (0xd0, ssu, 6, false, 0, 500000, &scsi) != kIOReturnSuccess) {
      gHost.ready = false;
      *why = "wake (START STOP UNIT)";
      return false;
    }
    IOSleep (50);
  }
  gRootDiagnostic.stage = "LUN ready";
  for (unsigned attempt = 0; attempt < 20; attempt++) {
    uint8_t tur[6] = { 0, 0, 0, 0, 0, 0 };
    uint32_t scsi = 0;
    if (hostScsi (0, tur, 6, false, 0, 200000, &scsi) == kIOReturnSuccess) {
      gHost.ready = true;
      return true;
    }
    if (gHost.poisoned) break;
    IOSleep (10);
  }
  gHost.ready = false;
  *why = "LUN 0 not ready";
  return false;
}
}

namespace {
static uint32_t be32w (const uint8_t *at)
{
  return (uint32_t (at[0]) << 24) | (uint32_t (at[1]) << 16) | (uint32_t (at[2]) << 8) | at[3];
}

#include "RootLayout.h"
#include "RootWindowRead.h"
}

bool NativeUfs::start (IOService *provider)
{
  unsigned probe = 0;
  PE_parse_boot_argn ("native-ufs-probe", &probe, sizeof (probe));
  native_ufs_probe_requested = probe != 0;
  // Hardware work runs once, from the root-device personality.
  if (!probe || !OSDynamicCast (IOPlatformExpertDevice, provider)) {
    return false;
  }
  if (probe == 2) {
    inspect ();
  }
  if (probe == 6) {
    dumpFirmwareList ();
  }
  if ((probe >= 3 && probe <= 5) || probe == 9) {
    adoptAndRead (probe);
  }
  if (probe == 10) {
    // Read-only check before anything is flashed: LUN 0 GPT -> "userdata" -> its first block.
    const char *why = "";
    if (!hostBringUp (&why)) {
      panic ("NATIVE_UFS root check: bring-up failed: %s", why);
    }
    RootLayout *layout = static_cast<RootLayout *> (IOMalloc (sizeof (RootLayout)));
    if (!layout || !findRootLayout (layout, &why)) {
      panic ("NATIVE_UFS root check: %s", why);
    }
    panic ("NATIVE_UFS root check\n"
           "userdata first=%llx last=%llx\n"
           "block0 magic %08x %08x ext4magic=%04x ext4blocks=%u\n"
           "manifest status=%u windows=%u",
           layout->userdataFirst, layout->userdataLast, layout->magic0, layout->magic1,
           layout->ext4Magic, layout->ext4Blocks, layout->manifestStatus, layout->windows);
  }
  if (probe == 11) {
    // After the root image is flashed: manifest, then each window's own GPT (sector 1 of the
    // attached dmg disk image carries "EFI PART"). Read-only.
    const char *why = "";
    if (!hostBringUp (&why)) {
      panic ("NATIVE_UFS root windows: bring-up failed: %s", why);
    }
    RootLayout *layout = static_cast<RootLayout *> (IOMalloc (sizeof (RootLayout)));
    if (!layout || !findRootLayout (layout, &why)) {
      panic ("NATIVE_UFS root windows: %s", why);
    }
    uint32_t sig[4][2] = {};
    uint32_t seen[4] = {};
    for (uint32_t index = 0; index < layout->windows && index < 4; index++) {
      uint64_t absolute = layout->userdataFirst * 4096ULL + layout->window[index].offset;
      if (hostRead4k (0, absolute / 4096, 1, gScratch) == kIOReturnSuccess) {
        seen[index] = 1;
        sig[index][0] = le32 (gScratch + 512);
        sig[index][1] = le32 (gScratch + 516);
      }
    }
    panic ("NATIVE_UFS root windows\n"
           "userdata first=%llx last=%llx manifest status=%u windows=%u\n"
           "w0 %s off=%llx size=%llx gpt=%08x %08x read=%u\n"
           "w1 %s off=%llx size=%llx gpt=%08x %08x read=%u\n"
           "w0 sha %08x %08x %08x %08x\n"
           "w1 sha %08x %08x %08x %08x",
           layout->userdataFirst, layout->userdataLast, layout->manifestStatus, layout->windows,
           layout->window[0].name, layout->window[0].offset, layout->window[0].size, sig[0][0], sig[0][1], seen[0],
           layout->window[1].name, layout->window[1].offset, layout->window[1].size, sig[1][0], sig[1][1], seen[1],
           be32w (layout->window[0].sha256), be32w (layout->window[0].sha256 + 4), be32w (layout->window[0].sha256 + 8), be32w (layout->window[0].sha256 + 12),
           be32w (layout->window[1].sha256), be32w (layout->window[1].sha256 + 4), be32w (layout->window[1].sha256 + 8), be32w (layout->window[1].sha256 + 12));
  }
  return false;
}
