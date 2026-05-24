import { useState, useEffect } from "react";
import { analyzePolicy, PolicyAnalysis } from "../lib/policyAnalyzer";
import { loadIAMDataset, IAMDatasetMap } from "../lib/iamDataset";

export default function AuditPage() {
  const [policyText, setPolicyText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<PolicyAnalysis | null>(null);
  const [iamDataset, setIamDataset] = useState<IAMDatasetMap | undefined>(undefined);
  const [datasetLoading, setDatasetLoading] = useState(true);

  useEffect(() => {
    loadIAMDataset()
      .then((map) => setIamDataset(map))
      .catch(() => {})
      .finally(() => setDatasetLoading(false));
  }, []);

  const handleAudit = () => {
    setError(null);
    setAnalysis(null);
    if (!policyText.trim()) return;
    try {
      const result = analyzePolicy(policyText, iamDataset);
      setAnalysis(result);
    } catch {
      setError("This doesn't look like a valid policy. Please paste the exact text your cloud team provided.");
    }
  };

  const loadExample = (example: object) => {
    setPolicyText(JSON.stringify(example, null, 2));
    setError(null);
    setAnalysis(null);
  };

  const TOO_MUCH_ACCESS = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]};
  const PROPERLY_SCOPED = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"arn:aws:s3:::my-company-reports/*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]};
  const THIRD_PARTY_ACCESS = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]};

  return (
    <div className="min-h-screen w-full bg-white pb-24">
      <div className="max-w-[740px] mx-auto pt-16 px-6">
        <div className="flex items-start justify-between mb-2">
          <h1 className="text-3xl font-serif font-bold text-gray-900">AWS Policy Auditor</h1>
          {datasetLoading && (
            <span className="text-xs text-gray-400 mt-2 animate-pulse">Loading permission database...</span>
          )}
          {!datasetLoading && iamDataset && (
            <span className="text-xs text-gray-400 mt-2">{Object.keys(iamDataset).length.toLocaleString()} permissions loaded</span>
          )}
        </div>
        <p className="text-gray-600 mb-8 font-sans">Translate technical cloud policies into plain English risk reports.</p>

        <div className="flex flex-wrap gap-2 mb-4">
          <button
            data-testid="sample-too-much"
            onClick={() => loadExample(TOO_MUCH_ACCESS)}
            className="text-sm px-3 py-1.5 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-md transition-colors"
          >
            Load Example: Too Much Access
          </button>
          <button
            data-testid="sample-scoped"
            onClick={() => loadExample(PROPERLY_SCOPED)}
            className="text-sm px-3 py-1.5 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-md transition-colors"
          >
            Load Example: Properly Scoped
          </button>
          <button
            data-testid="sample-third-party"
            onClick={() => loadExample(THIRD_PARTY_ACCESS)}
            className="text-sm px-3 py-1.5 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-md transition-colors"
          >
            Load Example: Third-Party Access
          </button>
        </div>

        <div className="mb-4">
          <textarea
            data-testid="policy-input"
            value={policyText}
            onChange={(e) => setPolicyText(e.target.value)}
            placeholder="Paste your AWS Policy here (ask your cloud team for this)"
            className="w-full h-64 p-4 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-gray-900 font-sans text-sm resize-y"
          />
          {error && (
            <p className="mt-2 text-sm text-gray-600">{error}</p>
          )}
        </div>

        <button
          data-testid="audit-button"
          onClick={handleAudit}
          className="w-full bg-gray-900 hover:bg-gray-800 text-white font-medium py-3 rounded-lg transition-colors"
        >
          Audit This Policy
        </button>

        {analysis && (
          <div className="mt-12 bg-[#f8f8f8] rounded-xl overflow-hidden border border-gray-200 shadow-sm">
            <div
              data-testid="risk-badge"
              className={`p-8 text-center text-white ${
                analysis.riskLevel === 'HIGH' ? 'bg-red-600' :
                analysis.riskLevel === 'MEDIUM' ? 'bg-yellow-500' : 'bg-green-600'
              }`}
            >
              <h2 className="text-[3rem] font-bold leading-none mb-4 font-sans tracking-tight">
                {analysis.badgeText}
              </h2>
              <p className="text-lg font-medium opacity-90">
                {analysis.badgeSubtext}
              </p>
            </div>

            <div className="p-8 space-y-12">
              <section>
                <h3 className="text-xs font-bold tracking-widest text-gray-500 uppercase mb-4">What This Policy Does</h3>
                <ul className="space-y-3">
                  {analysis.translatedActions.critical.map((action, i) => (
                    <li key={`crit-${i}`} className="flex items-start gap-3">
                      <span className="text-red-500 mt-1.5 text-[10px]">●</span>
                      <span className="text-gray-900 leading-relaxed">{action}</span>
                    </li>
                  ))}
                  {analysis.translatedActions.medium.map((action, i) => (
                    <li key={`med-${i}`} className="flex items-start gap-3">
                      <span className="text-yellow-500 mt-1.5 text-[10px]">●</span>
                      <span className="text-gray-900 leading-relaxed">{action}</span>
                    </li>
                  ))}
                  {analysis.translatedActions.low.map((action, i) => (
                    <li key={`low-${i}`} className="flex items-start gap-3">
                      <span className="text-green-500 mt-1.5 text-[10px]">●</span>
                      <span className="text-gray-900 leading-relaxed">{action}</span>
                    </li>
                  ))}
                  {analysis.translatedActions.critical.length === 0 &&
                   analysis.translatedActions.medium.length === 0 &&
                   analysis.translatedActions.low.length === 0 && (
                    <li className="text-gray-500 italic">No clear actions defined.</li>
                  )}
                </ul>
              </section>

              {analysis.findings.length > 0 && (
                <section>
                  <h3 className="text-xs font-bold tracking-widest text-gray-500 uppercase mb-4">Audit Findings</h3>
                  <div className="space-y-3">
                    {analysis.findings.map((finding, i) => (
                      <div key={i} className="flex gap-3">
                        <span className={`font-bold shrink-0 ${finding.type === 'warning' ? 'text-red-600' : 'text-green-600'}`}>
                          {finding.type === 'warning' ? '⚠ Finding:' : '✓ Pass:'}
                        </span>
                        <span className="text-gray-800">{finding.text}</span>
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {analysis.questions.length > 0 && (
                <section>
                  <h3 className="text-xs font-bold tracking-widest text-gray-500 uppercase mb-4">Questions to Ask Your Cloud Team</h3>
                  <div className="space-y-4">
                    {analysis.questions.map((question, i) => (
                      <div key={i} className="flex items-start gap-4 p-4 bg-white rounded-lg border border-gray-200">
                        <p className="flex-1 text-gray-800 font-serif leading-relaxed mt-0.5">{question}</p>
                        <button
                          data-testid={`copy-question-${i}`}
                          onClick={() => navigator.clipboard.writeText(question)}
                          className="text-xs font-medium text-gray-500 hover:text-gray-900 px-3 py-1.5 bg-gray-50 hover:bg-gray-100 rounded border border-gray-200 transition-colors shrink-0"
                        >
                          Copy
                        </button>
                      </div>
                    ))}
                  </div>
                </section>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
