#include "pe.hpp"

#include <algorithm>
#include <sstream>
#include <vector>

namespace
{
std::string FixedCString(const char* value, size_t maxSize)
{
    size_t length = 0;
    while (length < maxSize && value[length] != 0)
        length++;
    return { value, length };
}

std::string InstructionBytesToString(const GView::Dissasembly::Instruction& instruction)
{
    std::ostringstream result;
    result << std::hex;
    for (int i = 0; i < instruction.size && i < GView::Dissasembly::BYTES_SIZE; i++) {
        if (i != 0)
            result << ' ';
        result.width(2);
        result.fill('0');
        result << static_cast<uint32>(instruction.bytes[i]);
    }
    return result.str();
}

std::string SectionName(const GView::Type::PE::ImageSectionHeader& section)
{
    size_t length = 0;
    while (length < __IMAGE_SIZEOF_SHORT_NAME && section.Name[length] != 0)
        length++;
    return { reinterpret_cast<const char*>(section.Name), length };
}

GView::Dissasembly::Architecture GetArchitecture(GView::Type::PE::MachineType machineType)
{
    switch (machineType) {
    case GView::Type::PE::MachineType::I386:
        return GView::Dissasembly::Architecture::x86;
    case GView::Type::PE::MachineType::AMD64:
        return GView::Dissasembly::Architecture::x64;
    default:
        return GView::Dissasembly::Architecture::Invalid;
    }
}

const GView::Type::PE::ImageSectionHeader* GetTextSection(Reference<GView::Type::PE::PEFile> pe)
{
    for (uint32 i = 0; i < pe->nrSections; i++) {
        const auto& section = pe->sect[i];
        if (SectionName(section) == ".text" && section.SizeOfRawData > 0)
            return &section;
    }
    return nullptr;
}

uint64 GetEntryPointRva(Reference<GView::Type::PE::PEFile> pe)
{
    return pe->hdr64 ? pe->nth64.OptionalHeader.AddressOfEntryPoint : pe->nth32.OptionalHeader.AddressOfEntryPoint;
}

uint64 GetEntryPointAddress(Reference<GView::Type::PE::PEFile> pe)
{
    return pe->imageBase + GetEntryPointRva(pe);
}

std::vector<uint8_t> CopyRawData(Reference<GView::Object> object)
{
    auto buffer = object->GetData().CopyEntireFile(false);
    if (!buffer.IsValid())
        return {};

    const auto* data = reinterpret_cast<const uint8_t*>(buffer.GetData());
    return { data, data + buffer.GetLength() };
}

std::vector<::Decompiler::SectionInfo> BuildSections(Reference<GView::Type::PE::PEFile> pe)
{
    std::vector<::Decompiler::SectionInfo> sections;
    sections.reserve(pe->nrSections);

    for (uint32 i = 0; i < pe->nrSections; i++) {
        const auto& section      = pe->sect[i];
        const bool isExecutable  = (section.Characteristics & __IMAGE_SCN_MEM_EXECUTE) == __IMAGE_SCN_MEM_EXECUTE;
        const auto virtualSize   = static_cast<uint64>(section.Misc.VirtualSize);
        const auto fileOffset    = static_cast<uint64>(section.PointerToRawData);
        const auto virtualAdress = pe->imageBase + section.VirtualAddress;

        sections.push_back(::Decompiler::SectionInfo{ SectionName(section), virtualAdress, virtualSize, fileOffset, isExecutable });
    }

    return sections;
}

std::vector<::Decompiler::AssemblyInstruction> BuildInstructions(const std::vector<GView::Dissasembly::Instruction>& disassembled)
{
    std::vector<::Decompiler::AssemblyInstruction> instructions;
    instructions.reserve(disassembled.size());

    for (const auto& instruction : disassembled) {
        instructions.push_back(
              ::Decompiler::AssemblyInstruction{ instruction.address,
                                                 instruction.size,
                                                 FixedCString(instruction.mnemonic, GView::Dissasembly::MNEMONIC_SIZE),
                                                 FixedCString(instruction.opStr, GView::Dissasembly::OP_STR_SIZE),
                                                 InstructionBytesToString(instruction),
                                                 {} });
    }

    return instructions;
}

std::vector<::Decompiler::COFFSymbolInfo> BuildCOFFSymbols(Reference<GView::Type::PE::PEFile> pe)
{
    std::vector<::Decompiler::COFFSymbolInfo> symbols;
    symbols.reserve(pe->symbols.size());
    for (const auto& symbol : pe->symbols) {
        symbols.push_back(
              ::Decompiler::COFFSymbolInfo{ symbol.name.GetText(),
                                            static_cast<uint32_t>(symbol.is.Value),
                                            static_cast<int16_t>(symbol.is.SectionNumber),
                                            static_cast<uint16_t>(symbol.is.Type),
                                            static_cast<uint8_t>(symbol.is.StorageClass) });
    }

    return symbols;
}
} // namespace

namespace GView::Type::PE::Panels::DecompilerAdapter
{
std::string BuildText(Reference<Object> object, Reference<GView::Type::PE::PEFile> pe)
{
    const auto architecture = GetArchitecture(static_cast<PE::MachineType>(pe->nth32.FileHeader.Machine));
    if (architecture == GView::Dissasembly::Architecture::Invalid)
        return "Decompiler supports PE x86/x64 files only.";

    GView::Dissasembly::DissasemblerIntel dissasembler;
    if (!dissasembler.Init(GView::Dissasembly::Design::Intel, architecture, GView::Dissasembly::Endianess::Little))
        return "Unable to initialize the Intel disassembler.";

    const auto sections    = BuildSections(pe);
    const auto coffSymbols = BuildCOFFSymbols(pe);

    const auto* textSection = GetTextSection(pe);
    if (textSection == nullptr || textSection->PointerToRawData >= object->GetData().GetSize())
        return "No .text PE section was found.";

    const auto fileOffset        = static_cast<uint64>(textSection->PointerToRawData);
    const auto virtualAddress    = pe->imageBase + textSection->VirtualAddress;
    const auto remainingFileSize = object->GetData().GetSize() - fileOffset;
    const auto size              = std::min<uint64>(static_cast<uint64>(textSection->SizeOfRawData), remainingFileSize);
    if (size == 0)
        return "The executable PE section is empty.";

    auto buffer = object->GetData().Get(fileOffset, static_cast<uint32>(size), false);
    std::vector<GView::Dissasembly::Instruction> disassembled;
    if (!dissasembler.DissasembleInstructions(buffer, virtualAddress, disassembled))
        return "Unable to disassemble the executable PE section.";

    const auto instructions = BuildInstructions(disassembled);
    if (instructions.empty())
        return "No x86/x64 instructions were found in executable PE sections.";

    const auto rawData = CopyRawData(object);
    const ::Decompiler::DecompileContext context{ sections,
                                                  coffSymbols,
                                                  &rawData,
                                                  GetEntryPointAddress(pe),
                                                  false,
                                                  ::Decompiler::BinaryFormat::PE,
                                                  pe->hdr64 ? ::Decompiler::BinarySubformat::PE64 : ::Decompiler::BinarySubformat::PE32 };
    return ::Decompiler::DecompileToString(instructions, context, 0);
}
} // namespace GView::Type::PE::Panels::DecompilerAdapter
