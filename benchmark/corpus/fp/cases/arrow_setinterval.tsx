import { useEffect, useState } from "react";

export function QueueTag({ startedAt }: { startedAt: number }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);
  return <span>{Math.max(0, now - startedAt)}</span>;
}
