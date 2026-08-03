// Stub for jsPDF's optional HTML-rendering dependencies (dompurify,
// html2canvas, canvg). See the `resolve.alias` block in vite.config.js.
//
// Reaching any of these means something called an HTML or image jsPDF API that
// this application does not use. Failing loudly is better than silently
// pulling ~600 kB of unaudited third-party code into a wallet artefact.
const unavailable = () => {
  throw new Error(
    'jsPDF HTML/image rendering is not bundled in the QRL Offline Wallet Generator. '
    + 'Only text-based PDF output is supported.',
  );
};

export default new Proxy({}, { get: unavailable, apply: unavailable });
