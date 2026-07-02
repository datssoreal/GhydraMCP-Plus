package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.MemoryBlockDto;
import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
import eu.starsong.ghidra.util.GhidraSwing;
import eu.starsong.ghidra.util.GhidraUtil;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

import java.util.Arrays;
import java.util.List;

/**
 * Service for memory-related operations.
 */
public class MemoryService {

    /**
     * List all memory blocks/segments.
     */
    public List<MemoryBlockDto> listBlocks(Program program) {
        Memory memory = program.getMemory();
        return GhidraSwing.runRead(() -> Arrays.stream(memory.getBlocks())
            .map(MemoryBlockDto::from)
            .toList());
    }

    /**
     * Get a memory block by name.
     */
    public MemoryBlockDto getBlockByName(Program program, String name) {
        return GhidraSwing.runRead(() -> {
            Memory memory = program.getMemory();
            MemoryBlock block = memory.getBlock(name);
            if (block == null) {
                throw new NotFoundException("Memory block not found: " + name, "BLOCK_NOT_FOUND");
            }
            return MemoryBlockDto.from(block);
        });
    }

    /**
     * Get the memory block containing an address.
     */
    public MemoryBlockDto getBlockContaining(Program program, String addressStr) {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }

        return GhidraSwing.runRead(() -> {
            Memory memory = program.getMemory();
            MemoryBlock block = memory.getBlock(address);
            if (block == null) {
                throw new NotFoundException("No memory block at address: " + addressStr, "BLOCK_NOT_FOUND");
            }
            return MemoryBlockDto.from(block);
        });
    }

    /**
     * Read bytes from memory.
     */
    public byte[] readBytes(Program program, String addressStr, int length) {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }

        return GhidraSwing.runRead(() -> {
            Memory memory = program.getMemory();
            byte[] bytes = new byte[length];
            try {
                int bytesRead = memory.getBytes(address, bytes);
                if (bytesRead < length) {
                    byte[] result = new byte[bytesRead];
                    System.arraycopy(bytes, 0, result, 0, bytesRead);
                    return result;
                }
                return bytes;
            } catch (Exception e) {
                throw new RuntimeException("Failed to read memory at " + addressStr + ": " + e.getMessage(), e);
            }
        });
    }

    /**
     * Read bytes as hex string.
     */
    public String readBytesAsHex(Program program, String addressStr, int length) {
        byte[] bytes = readBytes(program, addressStr, length);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    /**
     * Write bytes to memory. Input is a hex string (space/non-hex chars stripped).
     */
    public int writeBytes(Program program, String addressStr, String hexBytes) throws Exception {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        if (hexBytes == null || hexBytes.isEmpty()) {
            throw new IllegalArgumentException("bytes is required");
        }
        String cleaned = hexBytes.replaceAll("[^0-9a-fA-F]", "");
        if (cleaned.length() % 2 != 0) {
            throw new IllegalArgumentException("hex byte string must have even length");
        }
        byte[] data = new byte[cleaned.length() / 2];
        for (int i = 0; i < cleaned.length(); i += 2) {
            data[i / 2] = (byte) Integer.parseInt(cleaned.substring(i, i + 2), 16);
        }
        Address finalAddress = address;
        byte[] finalData = data;
        return TransactionHelper.executeInTransaction(program,
            "Write memory at " + addressStr, () -> {
                program.getMemory().setBytes(finalAddress, finalData);
                return finalData.length;
            });
    }

    /**
     * Create a new initialized memory block and optionally fill it with hex bytes.
     * Used to receive unpacked/heap regions synced back from the Unicorn engine.
     */
    public java.util.Map<String, Object> createBlock(Program program, String name,
            String addressStr, long size, String hexBytes, String permissions) throws Exception {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        if (size <= 0) {
            throw new IllegalArgumentException("size must be positive");
        }
        byte[] data = null;
        if (hexBytes != null && !hexBytes.isEmpty()) {
            String cleaned = hexBytes.replaceAll("[^0-9a-fA-F]", "");
            if (cleaned.length() % 2 != 0) {
                throw new IllegalArgumentException("hex byte string must have even length");
            }
            data = new byte[cleaned.length() / 2];
            for (int i = 0; i < cleaned.length(); i += 2) {
                data[i / 2] = (byte) Integer.parseInt(cleaned.substring(i, i + 2), 16);
            }
        }
        final String blockName = (name == null || name.isEmpty()) ? "unicorn_sync" : name;
        final long finalSize = size;
        final byte[] finalData = data;
        final String perms = permissions;
        final Address finalAddress = address;
        return TransactionHelper.executeInTransaction(program,
            "Create memory block " + blockName, () -> {
                Memory mem = program.getMemory();
                if (mem.getBlock(finalAddress) != null) {
                    throw new IllegalArgumentException(
                        "address " + addressStr + " overlaps an existing block");
                }
                MemoryBlock block = mem.createInitializedBlock(
                    blockName, finalAddress, finalSize, (byte) 0, TaskMonitor.DUMMY, false);
                boolean r = perms == null || perms.contains("r");
                boolean w = perms == null || perms.contains("w");
                boolean x = perms != null && perms.contains("x");
                block.setPermissions(r, w, x);
                if (finalData != null) {
                    mem.setBytes(finalAddress, finalData);
                }
                java.util.Map<String, Object> out = new java.util.LinkedHashMap<>();
                out.put("name", block.getName());
                out.put("start", block.getStart().toString());
                out.put("end", block.getEnd().toString());
                out.put("size", block.getSize());
                out.put("permissions", (r ? "r" : "-") + (w ? "w" : "-") + (x ? "x" : "-"));
                return out;
            });
    }

    /**
     * Clear code units in [address, address+length) and run the disassembler,
     * committing real instructions (unlike the read-only disassembleAt view).
     * Returns the number of instructions created in the range.
     */
    public int disassembleCommit(Program program, String addressStr, int length) throws Exception {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        if (length <= 0) {
            throw new IllegalArgumentException("length must be positive");
        }
        final Address start = address;
        final Address end = address.add(length - 1);
        return TransactionHelper.executeInTransaction(program,
            "Disassemble " + addressStr, () -> {
                AddressSet set = new AddressSet(start, end);
                program.getListing().clearCodeUnits(start, end, false);
                DisassembleCommand cmd = new DisassembleCommand(set, null, true);
                cmd.applyTo(program, TaskMonitor.DUMMY);
                int n = 0;
                var it = program.getListing().getInstructions(set, true);
                while (it.hasNext()) {
                    it.next();
                    n++;
                }
                return n;
            });
    }

    /**
     * Disassemble instructions starting at an address.
     */
    public List<eu.starsong.ghidra.dto.DisassemblyInstructionDto> disassembleAt(
            Program program, String addressStr, int limit) {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        Address finalAddress = address;
        return GhidraSwing.runRead(() -> {
            List<eu.starsong.ghidra.dto.DisassemblyInstructionDto> results = new java.util.ArrayList<>();
            var instrIter = program.getListing().getInstructions(finalAddress, true);
            int collected = 0;
            while (instrIter.hasNext() && (limit <= 0 || collected < limit)) {
                var instr = instrIter.next();
                results.add(eu.starsong.ghidra.dto.DisassemblyInstructionDto.from(instr, program));
                collected++;
            }
            return results;
        });
    }

    /**
     * Get a comment at an address of the given type.
     */
    public String getComment(Program program, String addressStr, String commentType) {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        CommentType type = parseCommentType(commentType);
        return GhidraSwing.runRead(() -> {
            return program.getListing().getComment(type, address);
        });
    }

    /**
     * Set a comment at an address of the given type.
     */
    public void setComment(Program program, String addressStr, String commentType, String comment) throws Exception {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        CommentType type = parseCommentType(commentType);
        TransactionHelper.executeInTransaction(program,
            "Set " + commentType + " comment at " + addressStr, () -> {
                program.getListing().setComment(address, type, comment);
                return null;
            });
    }

    private CommentType parseCommentType(String s) {
        if (s == null) throw new IllegalArgumentException("comment_type is required");
        return switch (s.toLowerCase()) {
            case "plate" -> CommentType.PLATE;
            case "pre" -> CommentType.PRE;
            case "post" -> CommentType.POST;
            case "eol" -> CommentType.EOL;
            case "repeatable" -> CommentType.REPEATABLE;
            default -> throw new IllegalArgumentException("Invalid comment type: " + s);
        };
    }

    /**
     * Search for bytes in memory.
     */
    public List<String> searchBytes(Program program, byte[] pattern, int maxResults) {
        Memory memory = program.getMemory();
        return GhidraSwing.runRead(() -> {
            List<String> results = new java.util.ArrayList<>();

            Address start = program.getMinAddress();
            Address end = program.getMaxAddress();

            Address found = memory.findBytes(start, end, pattern, null, true, null);
            while (found != null && results.size() < maxResults) {
                results.add(found.toString());
                try {
                    found = memory.findBytes(found.add(1), end, pattern, null, true, null);
                } catch (Exception e) {
                    break;
                }
            }

            return results;
        });
    }
}
