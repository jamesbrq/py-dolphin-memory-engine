#ifdef _WIN32

#include "WindowsDolphinProcess.h"
#include "../../Common/CommonUtils.h"
#include "../../Common/MemoryCommon.h"

#include <Psapi.h>
#ifdef UNICODE
#include <codecvt>
#endif
#include <cstdlib>
#include <string>
#include <tlhelp32.h>

namespace
{
#ifdef UNICODE
std::wstring utf8_to_wstring(const std::string& str)
{
  std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
  return myconv.from_bytes(str);
}
#endif
}  // namespace

namespace DolphinComm
{

bool WindowsDolphinProcess::findPID()
{
  PROCESSENTRY32 entry;
  entry.dwSize = sizeof(PROCESSENTRY32);

  static const char* const s_dolphinProcessName{std::getenv("DME_DOLPHIN_PROCESS_NAME")};

  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

  m_PID = -1;
  if (Process32First(snapshot, &entry) == TRUE)
  {
    do
    {
#ifdef UNICODE
      const std::wstring exeFile{entry.szExeFile};
      const bool match{s_dolphinProcessName ?
                           (exeFile == utf8_to_wstring(s_dolphinProcessName) ||
                            exeFile == utf8_to_wstring(s_dolphinProcessName) + L".exe") :
                           (exeFile == L"Dolphin.exe" || exeFile == L"DolphinQt2.exe" ||
                            exeFile == L"DolphinWx.exe")};
#else
      const std::string exeFile{entry.szExeFile};
      const bool match{s_dolphinProcessName ?
                           (exeFile == s_dolphinProcessName ||
                            exeFile == std::string(s_dolphinProcessName) + ".exe") :
                           (exeFile == "Dolphin.exe" || exeFile == "DolphinQt2.exe" ||
                            exeFile == "DolphinWx.exe")};
#endif
      if (match)
      {
        m_PID = entry.th32ProcessID;
        break;
      }
    } while (Process32Next(snapshot, &entry) == TRUE);
  }

  CloseHandle(snapshot);
  if (m_PID == -1)
    // Here, Dolphin doesn't appear to be running on the system
    return false;

  // Get the handle if Dolphin is running since it's required on Windows to read or write into the
  // RAM of the process and to query the RAM mapping information
  m_hDolphin = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ |
                               PROCESS_VM_WRITE,
                           FALSE, m_PID);
  return true;
}

bool WindowsDolphinProcess::obtainEmuRAMInformations()
{
  // Reset so a re-hook on a reused instance starts clean.
  m_emuRAMAddressStart = 0;
  m_emuARAMAdressStart = 0;
  m_MEM2Present = false;
  m_ARAMAccessible = false;

  MEMORY_BASIC_INFORMATION info;

  // Pass 1: locate MEM1. A region is a MEM1 candidate if it is MEM_MAPPED,
  // backed by physical memory (valid working set), and is a plausible MEM1
  // view size (32 MiB stock, or 64 MiB with the memory-size override). Track
  // the lowest-based 32 MiB and 64 MiB candidates separately and PREFER the
  // 32 MiB one: Wii MEM1 is always 32 MiB while its MEM2 is 64 MiB, so a
  // 64 MiB region is MEM1 only when no 32 MiB MEM1 exists (the GC override
  // case). This avoids mistaking a 64 MiB MEM1 for MEM2 (their sizes collide)
  // regardless of enumeration order.
  unsigned long long lowest32 = 0;
  unsigned long long lowest64 = 0;
  for (unsigned char* p = nullptr;
       VirtualQueryEx(m_hDolphin, p, &info, sizeof(info)) == sizeof(info); p += info.RegionSize)
  {
    if (info.Type != MEM_MAPPED || !Common::IsMEM1RegionSize(info.RegionSize))
      continue;

    PSAPI_WORKING_SET_EX_INFORMATION wsInfo;
    wsInfo.VirtualAddress = info.BaseAddress;
    if (!QueryWorkingSetEx(m_hDolphin, &wsInfo, sizeof(PSAPI_WORKING_SET_EX_INFORMATION)))
      continue;
    if (!wsInfo.VirtualAttributes.Valid)
      continue;

    unsigned long long base = 0;
    std::memcpy(&base, &(info.BaseAddress), sizeof(info.BaseAddress));
    if (info.RegionSize == 0x2000000 && (lowest32 == 0 || base < lowest32))
      lowest32 = base;
    else if (info.RegionSize == 0x4000000 && (lowest64 == 0 || base < lowest64))
      lowest64 = base;
  }

  if (lowest32 != 0)
  {
    m_emuRAMAddressStart = lowest32;
    Common::SetMEM1RealSizeFromRegion(0x2000000);
  }
  else if (lowest64 != 0)
  {
    m_emuRAMAddressStart = lowest64;
    Common::SetMEM1RealSizeFromRegion(0x4000000);
  }
  else
  {
    // Dolphin is running, but emulation hasn't started.
    return false;
  }

  // Pass 2: classify the ARAM speedhack region (a MEM1-sized region directly
  // after MEM1) and Wii MEM2 (a 64 MiB region 0x10000000 above MEM1). Uses
  // GetMEM1Size(), now reflecting the size discovered in pass 1.
  for (unsigned char* p = nullptr;
       VirtualQueryEx(m_hDolphin, p, &info, sizeof(info)) == sizeof(info); p += info.RegionSize)
  {
    if (info.Type != MEM_MAPPED)
      continue;

    PSAPI_WORKING_SET_EX_INFORMATION wsInfo;
    wsInfo.VirtualAddress = info.BaseAddress;
    if (!QueryWorkingSetEx(m_hDolphin, &wsInfo, sizeof(PSAPI_WORKING_SET_EX_INFORMATION)))
      continue;
    if (!wsInfo.VirtualAttributes.Valid)
      continue;

    unsigned long long base = 0;
    std::memcpy(&base, &(info.BaseAddress), sizeof(info.BaseAddress));

    if (base == m_emuRAMAddressStart + Common::GetMEM1Size())
    {
      m_emuARAMAdressStart = base;
      m_ARAMAccessible = true;
    }
    else if (!m_MEM2Present && info.RegionSize == Common::GetMEM2Size() &&
             base >= m_emuRAMAddressStart + 0x10000000)
    {
      m_MEM2AddressStart = base;
      m_MEM2Present = true;
    }
  }

  if (m_MEM2Present)
  {
    m_emuARAMAdressStart = 0;
    m_ARAMAccessible = false;
  }

  return true;
}

bool WindowsDolphinProcess::readFromRAM(const u32 offset, char* buffer, const size_t size,
                                        const bool withBSwap)
{
  u64 RAMAddress = 0;
  if (m_ARAMAccessible)
  {
    if (offset >= Common::ARAM_FAKESIZE)
      RAMAddress = m_emuRAMAddressStart + offset - Common::ARAM_FAKESIZE;
    else
      RAMAddress = m_emuARAMAdressStart + offset;
  }
  else if (offset >= (Common::MEM2_START - Common::MEM1_START))
  {
    RAMAddress = m_MEM2AddressStart + offset - (Common::MEM2_START - Common::MEM1_START);
  }
  else
  {
    RAMAddress = m_emuRAMAddressStart + offset;
  }

  SIZE_T nread = 0;
  bool bResult = ReadProcessMemory(m_hDolphin, (void*)RAMAddress, buffer, size, &nread);
  if (bResult && nread == size)
  {
    if (withBSwap)
    {
      switch (size)
      {
      case 2:
      {
        u16 halfword = 0;
        std::memcpy(&halfword, buffer, sizeof(u16));
        halfword = Common::bSwap16(halfword);
        std::memcpy(buffer, &halfword, sizeof(u16));
        break;
      }
      case 4:
      {
        u32 word = 0;
        std::memcpy(&word, buffer, sizeof(u32));
        word = Common::bSwap32(word);
        std::memcpy(buffer, &word, sizeof(u32));
        break;
      }
      case 8:
      {
        u64 doubleword = 0;
        std::memcpy(&doubleword, buffer, sizeof(u64));
        doubleword = Common::bSwap64(doubleword);
        std::memcpy(buffer, &doubleword, sizeof(u64));
        break;
      }
      }
    }
    return true;
  }
  return false;
}

bool WindowsDolphinProcess::writeToRAM(const u32 offset, const char* buffer, const size_t size,
                                       const bool withBSwap)
{
  u64 RAMAddress = 0;
  if (m_ARAMAccessible)
  {
    if (offset >= Common::ARAM_FAKESIZE)
      RAMAddress = m_emuRAMAddressStart + offset - Common::ARAM_FAKESIZE;
    else
      RAMAddress = m_emuARAMAdressStart + offset;
  }
  else if (offset >= (Common::MEM2_START - Common::MEM1_START))
  {
    RAMAddress = m_MEM2AddressStart + offset - (Common::MEM2_START - Common::MEM1_START);
  }
  else
  {
    RAMAddress = m_emuRAMAddressStart + offset;
  }

  SIZE_T nread = 0;
  char* bufferCopy = new char[size];
  std::memcpy(bufferCopy, buffer, size);
  if (withBSwap)
  {
    switch (size)
    {
    case 2:
    {
      u16 halfword = 0;
      std::memcpy(&halfword, bufferCopy, sizeof(u16));
      halfword = Common::bSwap16(halfword);
      std::memcpy(bufferCopy, &halfword, sizeof(u16));
      break;
    }
    case 4:
    {
      u32 word = 0;
      std::memcpy(&word, bufferCopy, sizeof(u32));
      word = Common::bSwap32(word);
      std::memcpy(bufferCopy, &word, sizeof(u32));
      break;
    }
    case 8:
    {
      u64 doubleword = 0;
      std::memcpy(&doubleword, bufferCopy, sizeof(u64));
      doubleword = Common::bSwap64(doubleword);
      std::memcpy(bufferCopy, &doubleword, sizeof(u64));
      break;
    }
    }
  }

  bool bResult = WriteProcessMemory(m_hDolphin, (void*)RAMAddress, bufferCopy, size, &nread);
  delete[] bufferCopy;
  return (bResult && nread == size);
}
}  // namespace DolphinComm
#endif
