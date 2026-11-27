export interface Limits { evidenceFindings:number; evidenceRows:number; captureBytes:number; rulesBytes: number; inputBytes: number; outputBytes: number; occurrences: number; rules: number; memoryBytes: number; heapBytes: number; timeoutMs: number; startupMs: number }
export interface Config { workerURL: string; version: string; limits: Limits }
export interface EvidenceField { name:string; pattern:string; offset:number; length:number; dataTruncated:boolean; missing:boolean }
export interface Finding { rule:string; declaration:string; status:string; anchorOffset:number; fieldRowCount:number; fields:EvidenceField[] }
export interface ScanResult { evidenceEnabled:boolean; evidence:Finding[]; evidenceCount:number; evidenceRowCount:number; error?: string; rules: string[]; ruleCount: number; occurrences: {rule:string; pattern:string; offset:number; length:number}[]; occurrenceCount:number; truncated:boolean; compileMs:number; scanMs:number }

export interface PCAPObservation {
  outcome: 'match' | 'complete_negative' | 'unobservable';
  matches?: string[];
  evidence: {request_packet:number; request_offset:number; response_packet:number; response_offset:number}[];
}
export interface PCAPReport {
  schema_version: number;
  fixtures: {error?:string; evidence?: {rule:string; baseline:PCAPObservation; candidate:PCAPObservation; evidence_changed:boolean}}[];
  error?: string;
}
export interface PCAPRequest {
  baseline: string;
  candidate: string;
  rule: string;
  fixture: string;
  input: ArrayBuffer | File;
}

export function scan(config: Config, rules: string, input: ArrayBuffer, signal: AbortSignal, onReady: () => void = () => {}, extractEvidence = false): Promise<ScanResult> {
  return runWorker(config, {rules, input, evidence:extractEvidence}, signal, onReady, [rules]);
}

export function comparePCAP(config: Config, request: PCAPRequest, signal: AbortSignal): Promise<PCAPReport> {
  return runWorker(config, {...request, kind:'pcap'}, signal, () => {}, [request.baseline, request.candidate]);
}

// Each operation gets a fresh worker. Cancellation and completion release its
// Go heap, compiled program, input, and results.
type WorkerRequest = {rules:string; input:ArrayBuffer; evidence:boolean} | (PCAPRequest & {kind:'pcap'});

function runWorker<Result>(
  config: Config, request: WorkerRequest, signal: AbortSignal,
  onReady: () => void, sources: string[],
): Promise<Result> {
  if (sources.some(rules => rules.length > config.limits.rulesBytes || new TextEncoder().encode(rules).length > config.limits.rulesBytes)) {
    return Promise.reject(new Error('Rule source exceeds 16 KiB.'));
  }
  const input = request.input;
  const size = input instanceof ArrayBuffer ? input.byteLength : input.size;
  if (size > config.limits.inputBytes) return Promise.reject(new Error('Input exceeds 1 MiB.'));
  if (signal.aborted) return Promise.reject(new Error('Scan cancelled.'));
  return new Promise((resolve, reject) => {
    const worker = new Worker(config.workerURL);
    let finished = false;
    let sent = false;
    let timer = setTimeout(() => finish(new Error('Scanner download timed out. Try again.')), config.limits.startupMs);
    const cancel = () => finish(new Error('Scan cancelled. No complete result is available.'));
    const finish = (error?: Error, result?: Result) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      worker.terminate();
      signal.removeEventListener('abort', cancel);
      if (error) reject(error); else resolve(result!);
    };
    signal.addEventListener('abort', cancel, { once:true });
    worker.onerror = () => finish(new Error('The scanner stopped before completing. Try a smaller input or simpler rules.'));
    worker.onmessageerror = () => finish(new Error('Could not read scanner results.'));
    worker.onmessage = ({ data }) => {
      if (data.fatal || data.error) { finish(new Error(data.fatal || data.error)); return; }
      if (data.ready && !sent) {
        if (data.version !== config.version) { finish(new Error('Scanner version mismatch. Reload the page.')); return; }
        sent = true;
        onReady();
        clearTimeout(timer);
        timer = setTimeout(() => finish(new Error('The three-second scan limit was reached. No complete result is available.')), config.limits.timeoutMs);
        worker.postMessage(request, input instanceof ArrayBuffer ? [input] : []);
      } else if (data.result) {
        if (data.version !== config.version || data.memoryBytes > config.limits.memoryBytes || new TextEncoder().encode(JSON.stringify(data.result)).length > config.limits.outputBytes) { finish(new Error('Scanner result exceeded its limits.')); return; }
        finish(undefined, data.result);
      }
    };
  });
}
