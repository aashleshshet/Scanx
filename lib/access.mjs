export function assetName(parts) {
  if (!parts?.length) return 'index.html';
  if (parts.length !== 1 || !/^[a-zA-Z0-9_-]+\.(html|css|js|json|yaml|svg)$/.test(parts[0])) return null;
  return parts[0];
}
