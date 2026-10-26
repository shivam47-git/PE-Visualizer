#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <Zycore/Zycore.h>
#include <Zydis/Zydis.h>

namespace pe {

struct Instruction {
    uint64_t    address;       // Virtual address
    uint64_t    offset;        // File offset
    uint32_t    size;          // Byte length
    std::string mnemonic;
    std::string operands;
    std::string bytes_hex;
    std::string full_text;     // "mnemonic operands"
    // Metadata
    bool        is_call;
    bool        is_jump;
    bool        is_ret;
    bool        is_nop;
    bool        is_privileged;
    std::string branch_target; // For calls/jumps
    // Operand details
    struct Operand {
        std::string type;   // REG, IMM, MEM
        std::string text;
        uint64_t    value;
    };
    std::vector<Operand> decoded_operands;
    // Formatting
    std::string color_class; // "call","jmp","ret","nop","priv","default"
};

class Disassembler {
public:
    enum class Mode { X86_32, X86_64 };

    explicit Disassembler(Mode mode = Mode::X86_64);
    ~Disassembler() = default;

    // Disassemble bytes, virtual_base = starting VA for addresses
    std::vector<Instruction> disassemble(
        const uint8_t* data,
        size_t size,
        uint64_t virtual_base,
        uint32_t max_instructions = 2000
    );

    nlohmann::json disassemble_json(
        const uint8_t* data,
        size_t size,
        uint64_t virtual_base,
        uint32_t max_instructions = 2000
    );

    // Single instruction decode
    std::optional<Instruction> decode_one(const uint8_t* data, size_t size, uint64_t va);

    // Format with syntax highlighting info
    std::string format_instruction(const ZydisDecodedInstruction& insn,
                                    const ZydisDecodedOperand* ops,
                                    uint64_t va) const;

private:
    ZydisDecoder   m_decoder;
    ZydisFormatter m_formatter;
    Mode           m_mode;

    std::string operand_type_str(ZydisOperandType type) const;
    std::string color_class_for(const ZydisDecodedInstruction& insn) const;
    bool is_nop(const ZydisDecodedInstruction& insn,
                const ZydisDecodedOperand* ops) const;
};

} // namespace pe
