#include "disassembler.hpp"
#include <sstream>
#include <iomanip>
#include <optional>

namespace pe {

Disassembler::Disassembler(Mode mode) : m_mode(mode) {
    ZydisMachineMode machine = (mode == Mode::X86_64)
        ? ZYDIS_MACHINE_MODE_LONG_64
        : ZYDIS_MACHINE_MODE_LEGACY_32;
    ZydisStackWidth stack_width = (mode == Mode::X86_64)
        ? ZYDIS_STACK_WIDTH_64
        : ZYDIS_STACK_WIDTH_32;

    ZydisDecoderInit(&m_decoder, machine, stack_width);
    ZydisFormatterInit(&m_formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&m_formatter,
        ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
    ZydisFormatterSetProperty(&m_formatter,
        ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
    ZydisFormatterSetProperty(&m_formatter,
        ZYDIS_FORMATTER_PROP_ADDR_PADDING_ABSOLUTE,
        ZYDIS_PADDING_DISABLED);
}

std::vector<Instruction> Disassembler::disassemble(
    const uint8_t* data, size_t size,
    uint64_t virtual_base, uint32_t max_instructions)
{
    std::vector<Instruction> result;
    result.reserve(std::min(max_instructions, 4096u));

    ZydisDecodedInstruction zinsn;
    ZydisDecodedOperand     zops[ZYDIS_MAX_OPERAND_COUNT];
    ZydisDecoderContext     ctx;

    uint64_t offset = 0;
    while (offset < size && result.size() < max_instructions) {
        ZyanStatus status = ZydisDecoderDecodeFull(
            &m_decoder, data + offset, size - offset,
            &zinsn, zops);

        if (!ZYAN_SUCCESS(status)) {
            // Emit invalid byte
            Instruction bad;
            bad.address    = virtual_base + offset;
            bad.offset     = offset;
            bad.size       = 1;
            bad.mnemonic   = "??";
            char hbuf[4]; snprintf(hbuf, sizeof(hbuf), "%02X", data[offset]);
            bad.bytes_hex  = hbuf;
            bad.full_text  = "?? " + std::string(hbuf);
            bad.color_class = "invalid";
            result.push_back(bad);
            offset++;
            continue;
        }

        Instruction insn;
        insn.address = virtual_base + offset;
        insn.offset  = offset;
        insn.size    = zinsn.length;

        // Bytes hex
        std::ostringstream bytes_oss;
        for (uint8_t i = 0; i < zinsn.length; i++) {
            if (i) bytes_oss << ' ';
            bytes_oss << std::hex << std::uppercase
                      << std::setw(2) << std::setfill('0')
                      << (int)data[offset + i];
        }
        insn.bytes_hex = bytes_oss.str();

        // Format full text
        char fmt_buf[256] = {};
        ZydisFormatterFormatInstruction(
            &m_formatter, &zinsn, zops, zinsn.operand_count,
            fmt_buf, sizeof(fmt_buf), virtual_base + offset, nullptr);
        insn.full_text = fmt_buf;

        // Split mnemonic / operands
        std::string full = fmt_buf;
        auto space_pos = full.find(' ');
        if (space_pos != std::string::npos) {
            insn.mnemonic = full.substr(0, space_pos);
            insn.operands = full.substr(space_pos + 1);
        } else {
            insn.mnemonic = full;
        }

        // Classification
        insn.is_call      = (zinsn.meta.category == ZYDIS_CATEGORY_CALL);
        insn.is_jump      = (zinsn.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE &&
                             zinsn.meta.category != ZYDIS_CATEGORY_CALL);
        insn.is_ret       = (zinsn.meta.category == ZYDIS_CATEGORY_RET);
        insn.is_nop       = is_nop(zinsn, zops);
        insn.is_privileged = (zinsn.attributes & ZYDIS_ATTRIB_IS_PRIVILEGED) != 0;
        insn.color_class  = color_class_for(zinsn);

        // Branch target
        if ((insn.is_call || insn.is_jump) &&
            zinsn.operand_count > 0 &&
            zops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            uint64_t target = 0;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                    &zinsn, &zops[0],
                    virtual_base + offset, &target))) {
                char tbuf[32];
                snprintf(tbuf, sizeof(tbuf), "0x%llX", (unsigned long long)target);
                insn.branch_target = tbuf;
            }
        }

        // Decoded operands
        for (uint8_t oi = 0; oi < zinsn.operand_count_visible; oi++) {
            const auto& op = zops[oi];
            Instruction::Operand dop;
            dop.type = operand_type_str(op.type);

            char op_buf[128] = {};
            ZydisFormatterFormatOperand(
                &m_formatter, &zinsn, &op,
                op_buf, sizeof(op_buf), virtual_base + offset, nullptr);
            dop.text = op_buf;

            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                dop.value = op.imm.value.u;
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
                dop.value = op.mem.disp.has_displacement ? op.mem.disp.value : 0;

            insn.decoded_operands.push_back(dop);
        }

        result.push_back(insn);
        offset += zinsn.length;
    }

    return result;
}

nlohmann::json Disassembler::disassemble_json(
    const uint8_t* data, size_t size,
    uint64_t virtual_base, uint32_t max_instructions)
{
    auto insns = disassemble(data, size, virtual_base, max_instructions);
    nlohmann::json arr = nlohmann::json::array();
    for (auto& i : insns) {
        nlohmann::json ji;
        ji["address"]       = i.address;
        ji["offset"]        = i.offset;
        ji["size"]          = i.size;
        ji["mnemonic"]      = i.mnemonic;
        ji["operands"]      = i.operands;
        ji["bytes"]         = i.bytes_hex;
        ji["full"]          = i.full_text;
        ji["is_call"]       = i.is_call;
        ji["is_jump"]       = i.is_jump;
        ji["is_ret"]        = i.is_ret;
        ji["is_nop"]        = i.is_nop;
        ji["is_privileged"] = i.is_privileged;
        ji["branch_target"] = i.branch_target;
        ji["color_class"]   = i.color_class;
        ji["ops"]           = nlohmann::json::array();
        for (auto& op : i.decoded_operands)
            ji["ops"].push_back({{"type", op.type}, {"text", op.text}, {"value", op.value}});
        arr.push_back(ji);
    }
    return arr;
}

std::optional<Instruction> Disassembler::decode_one(
    const uint8_t* data, size_t size, uint64_t va)
{
    auto vec = disassemble(data, size, va, 1);
    if (vec.empty()) return std::nullopt;
    return vec[0];
}

std::string Disassembler::operand_type_str(ZydisOperandType type) const {
    switch (type) {
    case ZYDIS_OPERAND_TYPE_REGISTER: return "REG";
    case ZYDIS_OPERAND_TYPE_MEMORY:   return "MEM";
    case ZYDIS_OPERAND_TYPE_POINTER:  return "PTR";
    case ZYDIS_OPERAND_TYPE_IMMEDIATE:return "IMM";
    default: return "UNK";
    }
}

std::string Disassembler::color_class_for(const ZydisDecodedInstruction& insn) const {
    if (is_nop(insn, nullptr)) return "nop";
    switch (insn.meta.category) {
    case ZYDIS_CATEGORY_CALL:      return "call";
    case ZYDIS_CATEGORY_RET:       return "ret";
    case ZYDIS_CATEGORY_INTERRUPT: return "interrupt";
    case ZYDIS_CATEGORY_SYSCALL:   return "syscall";
    default: break;
    }
    if (insn.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE) {
        return (insn.meta.branch_type == ZYDIS_BRANCH_TYPE_NEAR ||
                insn.meta.branch_type == ZYDIS_BRANCH_TYPE_FAR)
            ? "jmp" : "jcc";
    }
    if (insn.attributes & ZYDIS_ATTRIB_IS_PRIVILEGED) return "privileged";
    if (insn.mnemonic == ZYDIS_MNEMONIC_PUSH ||
        insn.mnemonic == ZYDIS_MNEMONIC_POP)  return "stack";
    if (insn.mnemonic == ZYDIS_MNEMONIC_MOV ||
        insn.mnemonic == ZYDIS_MNEMONIC_LEA ||
        insn.mnemonic == ZYDIS_MNEMONIC_MOVSX||
        insn.mnemonic == ZYDIS_MNEMONIC_MOVZX) return "mov";
    return "default";
}

bool Disassembler::is_nop(const ZydisDecodedInstruction& insn,
                            const ZydisDecodedOperand* ops) const {
    if (insn.mnemonic == ZYDIS_MNEMONIC_NOP) return true;
    // xchg eax, eax / xchg rax, rax variants
    if (insn.mnemonic == ZYDIS_MNEMONIC_XCHG && ops &&
        insn.operand_count == 2 &&
        ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        ops[0].reg.value == ops[1].reg.value) return true;
    return false;
}

} // namespace pe
