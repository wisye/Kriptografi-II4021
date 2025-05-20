export const formatTimestamp = (ts: string) => {
  const iso = /T.*Z|[+\-]\d{2}:?\d{2}/.test(ts) ? ts : ts.replace(" ", "T") + "Z";
  return new Date(iso).toLocaleString("id-ID", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
};