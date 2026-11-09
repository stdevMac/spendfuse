// runs.ts - the recorded attack runs the hosted dashboard serves, bundled at build time.
// To publish another run: copy it from .spendfuse/runs/ to docs/proofs/ (check that canary ids are
// redacted - the Worker has no canaries.json), import it here and add it to RECORDED.
import run20261109 from '../../docs/proofs/live-run-2026-11-09T04-59-38-380Z.json' with { type: 'json' };

export interface RecordedRun {
  id: string;
  run: unknown;
}

export const RECORDED: readonly RecordedRun[] = [{ id: 'live-run-2026-11-09T04-59-38-380Z', run: run20261109 }];
