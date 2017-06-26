/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.zeppelin.notebook.repo;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.apache.zeppelin.conf.ZeppelinConfiguration;
import org.apache.zeppelin.notebook.Note;
import org.apache.zeppelin.notebook.NoteInfo;
import org.apache.zeppelin.user.AuthenticationInfo;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * NotebookRepo that hosts all the notebook FS in a single Git repo.
 * This repo will try to automatically keep a remote in sync, so it will:
 * <p>
 * - Git clone the repo if it's not already downloaded
 * - Git push local changes
 * - Git pull on refresh
 */
public class RemoteGitNotebookRepo implements NotebookRepo {
  private static final Logger LOG = LoggerFactory.getLogger(RemoteGitNotebookRepo.class);

  private GitNotebookRepo localRepo;
  private String remoteRepo;
  private Git git;

  public RemoteGitNotebookRepo(ZeppelinConfiguration conf) throws IOException, GitAPIException {
    cloneRepo(conf.getNotebookGitRepo(), conf.getNotebookDir());
    remoteRepo = conf.getNotebookGitRepo();
    File localPath = new File(conf.getNotebookDir());
    LOG.info("Opening a git repo at '{}', remote: '{}'", localPath, remoteRepo);

    // update the local repo
    git = localRepo.getGit();
    git.pull().call();
  }

  @Override
  public synchronized void save(Note note, AuthenticationInfo subject) throws IOException {
    localRepo.save(note, subject);
  }

  @Override
  public void remove(String noteId, AuthenticationInfo subject) throws IOException {
    localRepo.remove(noteId, subject);
    try {
      git.push().call();
    } catch (GitAPIException e) {
      LOG.error(e.getMessage(), e);
    }
  }

  // Listing refreshes from remote
  @Override
  public List<NoteInfo> list(AuthenticationInfo subject) throws IOException {
    try {
      git.pull().call();
    } catch (GitAPIException e) {
      LOG.error(e.getMessage(), e);
    }

    return localRepo.list(subject);
  }

  @Override
  public Note get(String noteId, AuthenticationInfo subject) throws IOException {
    return localRepo.get(noteId, subject);
  }

  // Checkpointing pushes to remote
  @Override
  public Revision checkpoint(String pattern, String commitMessage, AuthenticationInfo subject) {
    Revision newRev = localRepo.checkpoint(pattern, commitMessage, subject);
    if (newRev != Revision.EMPTY) {
      LOG.debug("Pushing revision {}", newRev);
      try {
        git.push().call();
      } catch (GitAPIException e) {
        LOG.error(e.getMessage(), e);
      }
    }
    return newRev;
  }

  @Override
  public synchronized Note get(String noteId, String revId, AuthenticationInfo subject)
      throws IOException {
    return localRepo.get(noteId, revId, subject);
  }

  @Override
  public List<Revision> revisionHistory(String noteId, AuthenticationInfo subject) {
    return localRepo.revisionHistory(noteId, subject);
  }

  @Override
  public Note setNoteRevision(String noteId, String revId, AuthenticationInfo subject)
      throws IOException {
    return localRepo.setNoteRevision(noteId, revId, subject);
  }

  @Override
  public List<NotebookRepoSettingsInfo> getSettings(AuthenticationInfo subject) {
    return localRepo.getSettings(subject);
  }

  @Override
  public void updateSettings(Map<String, String> settings, AuthenticationInfo subject) {
    // TODO support updating repo?
    localRepo.updateSettings(settings, subject);
  }

  @Override
  public void close() {
    localRepo.close();
  }

  private void cloneRepo(String notebookGitRepo, String notebookDir) throws GitAPIException {
    File localPath = new File(notebookDir);
    LOG.info("Opening a git repo at '{}', remote: '{}'", localPath, remoteRepo);

    if (!localPath.exists()) {
      LOG.info("Git repo {} does not exist, cloning");
      Git.cloneRepository()
          .setURI(notebookGitRepo)
          .setDirectory(localPath)
          .call();
    }
  }
}
