import React, { useEffect, useRef, useState } from 'react';

/**
 * Counter with smooth live updates without weird 0-to-target refresh flickers or flashing green colors
 */
export function CountUpNumber({ value }: { value: number | string; duration?: number }) {
  const numeric = typeof value === 'number' ? value : Number(String(value).replace(/,/g, ''));
  const isNumeric = !Number.isNaN(numeric);
  const [display, setDisplay] = useState(isNumeric ? numeric : 0);
  const currentRef = useRef(isNumeric ? numeric : 0);

  useEffect(() => {
    if (!isNumeric) return;
    currentRef.current = numeric;
    setDisplay(numeric);
  }, [numeric, isNumeric]);

  if (!isNumeric) {
    return <>{value}</>;
  }

  return (
    <span className="inline-block font-mono tracking-tight font-bold">
      {display.toLocaleString()}
    </span>
  );
}
