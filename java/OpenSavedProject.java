// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

// Opens the saved program with crash recovery enabled before it starts the bridge.
// @category ghidra-mcp

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.model.listing.Program;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.UUID;

public class OpenSavedProject extends GhidraScript {
  @Override
  protected void run() throws Exception {
    // Imports use the fixed filename binary. Ghidra can also import dependent
    // libraries, so a normal project can contain several Program files.
    DomainFile savedProgram = state.getProject().getProjectData().getRootFolder().getFile("binary");
    if (savedProgram == null) {
    // A main program with a new name or location is usable if it is unambiguous.
      for (DomainFile file : state.getProject().getProjectData()) {
        Class<?> objectClass = file.getDomainObjectClass();
        if (objectClass != null && Program.class.isAssignableFrom(objectClass)) {
          if (savedProgram != null) {
            throw new IllegalStateException("Cannot select saved program; preserving ambiguous project");
          }
          savedProgram = file;
        }
      }
    }
    if (savedProgram == null || savedProgram.getDomainObjectClass() == null ||
        !Program.class.isAssignableFrom(savedProgram.getDomainObjectClass())) {
      throw new IllegalStateException("No saved program found; preserving existing project");
    }
    if (savedProgram.canRecover()) {
      // If a save fails, a program close can discard its recovery files.
      // Keep a complete copy before a consumer opens the program.
      // Headless already holds the project lock during this copy.
      backupRecoveryProject();
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
      runScript("Bridge.java", getScriptArgs(), state);
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

  private void backupRecoveryProject() throws IOException {
    ProjectLocator locator = state.getProject().getProjectLocator();
    Path repository = locator.getProjectDir().toPath();
    Path backups = repository.getParent().getParent().resolve("recovery-backups");
    Files.createDirectories(backups);
    syncDirectory(backups.getParent());
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
