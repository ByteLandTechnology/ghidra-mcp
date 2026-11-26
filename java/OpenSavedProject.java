// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

// Opens a saved or attached program with crash recovery enabled before it starts the bridge.
// @category ghidra-mcp

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.model.listing.Program;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

public class OpenSavedProject extends GhidraScript {
  private static final String ERROR_PREFIX = "GHIDRA_MCP_OPEN_ERROR: ";
  private static final String PROGRAM_NAME_HEX_PREFIX = "program_name_hex=";
  private static final String BACKUP_DIR_PREFIX = "backup_dir=";
  private static final String ATTACHED_GPR_ARG = "attached_gpr=true";
  private static final String[] SAVED_BINARY_NAMES = {
      "binary", "binary.bin", "binary.hex", "binary.ihex", "binary.srec"
  };

  @Override
  protected void run() throws Exception {
    String programName = null;
    Path backupDir = null;
    boolean attachedGpr = false;
    List<String> bridgeArgs = new ArrayList<>();
    for (String arg : getScriptArgs()) {
      if (arg.startsWith(PROGRAM_NAME_HEX_PREFIX)) {
        byte[] decoded = HexFormat.of().parseHex(arg.substring(PROGRAM_NAME_HEX_PREFIX.length()));
        programName = new String(decoded, StandardCharsets.UTF_8);
      }
      else if (arg.startsWith(BACKUP_DIR_PREFIX)) {
        backupDir = Paths.get(arg.substring(BACKUP_DIR_PREFIX.length()));
      }
      else if (ATTACHED_GPR_ARG.equals(arg)) {
        attachedGpr = true;
      }
      else {
        bridgeArgs.add(arg);
      }
    }

    DomainFile savedProgram = selectProgram(programName, attachedGpr);
    if (savedProgram.canRecover()) {
      // If a save fails, a program close can discard its recovery files.
      // Keep a complete copy before a consumer opens the program.
      // Headless already holds the project lock during this copy.
      backupRecoveryProject(backupDir);
    }

    // Headless -process opens programs with okToRecover=false, which can delete
    // recovery data before any pre-script runs. This script runs without
    // -process or -import and is the first consumer to open the saved program.
    Program program = (Program) savedProgram.getDomainObject(this, true, true, monitor);
    try {
      // The script commits recovered changes before the bridge can announce readiness or stop.
      // No script transaction is active during this save.
      if (program.isChanged()) {
        savedProgram.save(monitor);
      }
      currentProgram = program;
      state.setCurrentProgram(program);
      runScript("Bridge.java", bridgeArgs.toArray(new String[0]), state);
    }
    finally {
      try {
        if (program.isChanged()) {
          savedProgram.save(monitor);
        }
      }
      finally {
        currentProgram = null;
        state.setCurrentProgram(null);
        program.release(this);
      }
    }
  }

  private DomainFile selectProgram(String programName, boolean attachedGpr) {
    List<DomainFile> programs = collectPrograms();
    if (programName != null) {
      return selectNamedProgram(programs, programName);
    }
    if (!attachedGpr) {
      DomainFolder root = state.getProject().getProjectData().getRootFolder();
      for (String candidate : SAVED_BINARY_NAMES) {
        DomainFile file = root.getFile(candidate);
        if (isProgramFile(file)) {
          return file;
        }
      }
    }
    if (programs.isEmpty()) {
      throw reportOpenError("No Program files were found in the Ghidra project");
    }
    if (programs.size() > 1) {
      throw reportOpenError(
          "Project contains multiple programs; specify programName. Candidate programs: "
              + formatCandidates(programs));
    }
    return programs.get(0);
  }

  private DomainFile selectNamedProgram(List<DomainFile> programs, String programName) {
    if (programs.isEmpty()) {
      throw reportOpenError("No Program files were found in the Ghidra project");
    }
    String normalized = programName.startsWith("/") ? programName : "/" + programName;
    for (DomainFile file : programs) {
      if (normalized.equals(file.getPathname())) {
        return file;
      }
    }
    if (!programName.contains("/")) {
      List<DomainFile> byName = new ArrayList<>();
      for (DomainFile file : programs) {
        if (programName.equals(file.getName())) {
          byName.add(file);
        }
      }
      if (byName.size() == 1) {
        return byName.get(0);
      }
      if (byName.size() > 1) {
        throw reportOpenError(
            "Program name '"
                + programName
                + "' matches multiple project folders; specify the full project path. "
                + "Candidate programs: "
                + formatCandidates(byName));
      }
    }
    throw reportOpenError(
        "Program '"
            + programName
            + "' was not found in the project. Candidate programs: "
            + formatCandidates(programs));
  }

  private List<DomainFile> collectPrograms() {
    List<DomainFile> programs = new ArrayList<>();
    for (DomainFile file : state.getProject().getProjectData()) {
      if (isProgramFile(file)) {
        programs.add(file);
      }
    }
    programs.sort(Comparator.comparing(DomainFile::getPathname));
    return programs;
  }

  private static boolean isProgramFile(DomainFile file) {
    if (file == null) {
      return false;
    }
    Class<?> objectClass = file.getDomainObjectClass();
    return objectClass != null && Program.class.isAssignableFrom(objectClass);
  }

  private static String formatCandidates(List<DomainFile> programs) {
    List<String> names = new ArrayList<>(programs.size());
    for (DomainFile file : programs) {
      String path = file.getPathname();
      names.add(path.startsWith("/") ? path.substring(1) : path);
    }
    return String.join(", ", names);
  }

  private IllegalArgumentException reportOpenError(String message) {
    printerr(ERROR_PREFIX + message);
    return new IllegalArgumentException(message);
  }

  private void backupRecoveryProject(Path customBackupDir) throws IOException {
    ProjectLocator locator = state.getProject().getProjectLocator();
    Path repository = locator.getProjectDir().toPath();
    Path backups =
        customBackupDir != null
            ? customBackupDir
            : repository.getParent().getParent().resolve("recovery-backups");
    Files.createDirectories(backups);
    if (backups.getParent() != null) {
      syncDirectory(backups.getParent());
    }
    Path pending = Files.createTempDirectory(backups, ".pending-");
    copySynced(locator.getMarkerFile().toPath(), pending.resolve("project.gpr"));
    Path backupRepository = pending.resolve("project.rep");
    Files.walkFileTree(repository, new SimpleFileVisitor<Path>() {
      @Override
      public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attributes)
          throws IOException {
        checkBackupCancelled();
        Files.createDirectory(backupRepository.resolve(repository.relativize(directory)));
        return FileVisitResult.CONTINUE;
      }

      @Override
      public FileVisitResult visitFile(Path file, BasicFileAttributes attributes)
          throws IOException {
        checkBackupCancelled();
        if (!attributes.isRegularFile()) {
          throw new IOException("Cannot safely back up project entry: " + file);
        }
        copySynced(file, backupRepository.resolve(repository.relativize(file)));
        return FileVisitResult.CONTINUE;
      }

      @Override
      public FileVisitResult postVisitDirectory(Path directory, IOException error)
          throws IOException {
        if (error != null) {
          throw error;
        }
        syncDirectory(backupRepository.resolve(repository.relativize(directory)));
        return FileVisitResult.CONTINUE;
      }
    });
    syncDirectory(pending);
    Path complete = backups.resolve(UUID.randomUUID().toString());
    Files.move(pending, complete, StandardCopyOption.ATOMIC_MOVE);
    syncDirectory(backups);
    println("Preserved crash recovery project at " + complete);
  }

  private void checkBackupCancelled() throws IOException {
    if (monitor.isCancelled()) {
      throw new IOException("Project backup cancelled; recovery has not started");
    }
  }

  private static void copySynced(Path source, Path destination) throws IOException {
    Files.copy(source, destination);
    try (FileChannel file = FileChannel.open(destination, StandardOpenOption.WRITE)) {
      file.force(true);
    }
  }

  private static void syncDirectory(Path directory) throws IOException {
    // Java cannot open Windows directories as FileChannels. File contents are
    // still flushed there. Directory fsync is available on our Unix platforms.
    if (!System.getProperty("os.name").startsWith("Windows")) {
      try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
        channel.force(true);
      }
    }
  }
}
