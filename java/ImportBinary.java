// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

// Finalizes firmware base addresses after headless import, then starts the bridge.
// @category ghidra-mcp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import java.util.ArrayList;
import java.util.List;

public class ImportBinary extends GhidraScript {
  private static final String ERROR_PREFIX = "GHIDRA_MCP_OPEN_ERROR: ";
  private static final String BASE_ADDRESS_PREFIX = "base_address=";

  @Override
  protected void run() throws Exception {
    String baseAddress = null;
    List<String> bridgeArgs = new ArrayList<>();
    for (String arg : getScriptArgs()) {
      if (arg.startsWith(BASE_ADDRESS_PREFIX)) {
        baseAddress = arg.substring(BASE_ADDRESS_PREFIX.length());
      }
      else {
        bridgeArgs.add(arg);
      }
    }
    if (currentProgram == null) {
      String message =
          "Ghidra did not import the file; set processor or loader options for raw firmware";
      printerr(ERROR_PREFIX + message);
      throw new IllegalStateException(message);
    }
    end(true);
    if (baseAddress != null && !baseAddress.isEmpty()) {
      applyBaseAddress(currentProgram, baseAddress);
    }
    runScript("Bridge.java", bridgeArgs.toArray(new String[0]), state);
  }

  private void applyBaseAddress(Program program, String rawAddress) throws Exception {
    Address target = resolveBaseAddress(program, rawAddress);
    Address currentBase = program.getImageBase();
    if (target.equals(currentBase)) {
      return;
    }
    AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
    if (!target.getAddressSpace().equals(defaultSpace)) {
      return;
    }
    List<MemoryBlock> defaultBlocks = new ArrayList<>();
    Address minStart = null;
    for (MemoryBlock block : program.getMemory().getBlocks()) {
      if (block.getStart().getAddressSpace().equals(defaultSpace)) {
        defaultBlocks.add(block);
        if (minStart == null || block.getStart().compareTo(minStart) < 0) {
          minStart = block.getStart();
        }
      }
    }

    int tx = program.startTransaction("Set firmware base address");
    boolean committed = false;
    try {
      // BinaryLoader moves blocks to -loader-baseAddr while imageBase stays at zero.
      // IntelHexLoader and MotorolaHexLoader ignore -loader-baseAddr and keep blocks at zero.
      boolean blocksAlreadyShifted =
          currentBase.getOffset() == 0 && minStart != null && minStart.compareTo(target) >= 0;
      if (blocksAlreadyShifted) {
        Address zero = defaultSpace.getAddress(0);
        for (MemoryBlock block : defaultBlocks) {
          long delta = block.getStart().subtract(target);
          program.getMemory().moveBlock(block, zero.addNoWrap(delta), monitor);
        }
      }
      program.setImageBase(target, true);
      committed = true;
    }
    catch (Exception error) {
      String message = "Cannot apply baseAddress " + rawAddress + ": " + error.getMessage();
      printerr(ERROR_PREFIX + message);
      throw error;
    }
    finally {
      program.endTransaction(tx, committed);
    }
  }

  private Address resolveBaseAddress(Program program, String rawAddress) {
    int colon = rawAddress.indexOf(':');
    if (colon >= 0) {
      String spaceName = rawAddress.substring(0, colon);
      String hex = stripHexPrefix(rawAddress.substring(colon + 1));
      AddressSpace space = program.getAddressFactory().getAddressSpace(spaceName);
      if (space == null) {
        String message = "Unknown address space in baseAddress: " + spaceName;
        printerr(ERROR_PREFIX + message);
        throw new IllegalArgumentException(message);
      }
      Address resolved;
      try {
        resolved = space.getAddress(hex);
      }
      catch (AddressFormatException error) {
        String message = "Invalid baseAddress offset for space " + spaceName + ": " + rawAddress;
        printerr(ERROR_PREFIX + message);
        throw new IllegalArgumentException(message, error);
      }
      if (resolved == null) {
        String message = "Invalid baseAddress offset for space " + spaceName + ": " + rawAddress;
        printerr(ERROR_PREFIX + message);
        throw new IllegalArgumentException(message);
      }
      return resolved;
    }
    String hex = stripHexPrefix(rawAddress);
    Address resolved;
    try {
      resolved = program.getAddressFactory().getDefaultAddressSpace().getAddress(hex);
    }
    catch (AddressFormatException error) {
      String message = "Invalid baseAddress for processor address space: " + rawAddress;
      printerr(ERROR_PREFIX + message);
      throw new IllegalArgumentException(message, error);
    }
    if (resolved == null) {
      String message = "Invalid baseAddress for processor address space: " + rawAddress;
      printerr(ERROR_PREFIX + message);
      throw new IllegalArgumentException(message);
    }
    return resolved;
  }

  private static String stripHexPrefix(String value) {
    if (value.startsWith("0x") || value.startsWith("0X")) {
      return value.substring(2);
    }
    return value;
  }
}
