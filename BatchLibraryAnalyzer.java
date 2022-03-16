
/* ###
 * IP: GHIDRA
 * REVIEWED: YES
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Batch Performs analysis in preparation for FIDDB creation
//@category FunctionID

import static ghidra.program.util.GhidraProgramUtilities.setAnalyzedFlag;

import java.io.IOException;
import java.util.*;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.framework.options.Options;

public class BatchLibraryAnalyzer extends GhidraScript {

	private static final Set<String> IGNORE_OPTIONS = Set.of(
		"GCC C++ Class Analyzer",
		"GCC RTTI Analyzer",
		"Function ID",
		"Library Identification",
		"Demangler GNU",
		"Apply Data Archives"
	);
	
	private Progress progress;

	public void analyzeAll(AutoAnalysisManager mgr) {

		Program program = mgr.getProgram();

		mgr.reAnalyzeAll(null);

		analyzeChanges(program);
	}

	@Override
	public void run() throws Exception {

		if (currentProgram != null) {
			popup("This script should be run from a tool with no open programs");
			return;
		}

        Project project = state.getProject();
		ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();
		LinkedList<DomainFolder> folders = new LinkedList<>();
		List<DomainFile> files = new ArrayList<>();
		folders.push(rootFolder);
		while (!folders.isEmpty()) {
			monitor.checkCanceled();
			DomainFolder folder = folders.pop();
			List.of(folder.getFolders()).forEach(folders::push);
			files.addAll(List.of(folder.getFiles()));
		}
		this.progress = new Progress(files.size());
		monitor.initialize(files.size());
		monitor.setMessage("Processing Files");
		for (DomainFile file : files) {
			monitor.checkCanceled();
			processDomainFile(file);
			monitor.incrementProgress(1);
			progress.incrementProgress(file);
		}
	}

	private void processDomainFile(DomainFile domainFile) throws CancelledException, IOException {
		if (!ProgramContentHandler.PROGRAM_CONTENT_TYPE.equals(domainFile.getContentType())) {
			return; // skip non-Program files
		}
		if (domainFile.isVersioned() && !domainFile.isCheckedOut()) {
			println("WARNING! Skipping versioned file - not checked-out: " +
				domainFile.getPathname());
			return;
		}
		Program program = null;
		try {
			program =
				(Program) domainFile.getDomainObject(this, true /*upgrade*/,
					false /*don't recover*/, monitor);
			processProgram(program);
		} catch (VersionException e) {
			println("ERROR! Failed to process file due to upgrade issue: " +
				domainFile.getPathname());
		} finally {
			if (program != null) {
				program.release(this);
			}
		}
	}

	private static boolean wasAnalyzed(Program program) {
		Options options = program.getOptions(Program.PROGRAM_INFO);
		return options.contains(Program.ANALYZED) || options.getBoolean(Program.ANALYZED, false);
	}

	private void processProgram(Program program) throws CancelledException, IOException {
		AutoAnalysisManager amgr = AutoAnalysisManager.getAnalysisManager(program);
		if (!wasAnalyzed(program)) {
			int id = program.startTransaction("Batch Script Transaction");
			boolean success = false;
			try {
				setAnalysisOptions(amgr);
				analyzeAll(amgr);
				setAnalyzedFlag(program, true);
				success = true;
			} finally {
				program.endTransaction(id, success);
				if (success) {
					// ...save any changes
					program.save("Changes made by script: " + getClass().getSimpleName(), monitor);
				}
			}
		}
	}

	private void setAnalysisOptions(AutoAnalysisManager amgr) {
		Program program = amgr.getProgram();
		amgr.restoreDefaultOptions();
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		for (String option : options.getOptionNames()) {
			if (IGNORE_OPTIONS.contains(option)) {
				options.setBoolean(option, false);
			}
		}
		amgr.initializeOptions(options);
	}
	
	private class Progress {
		
		final int max;
		int count;
		
		Progress(int max) {
			this.max = max;
			this.count = 0;
		}
		
		void incrementProgress(DomainFile f) {
			println(String.format("Processed: %s (%d / %d)", f.getName(), count++, max));
		}
	}
}
