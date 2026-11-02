import React, { useEffect, useRef, useState } from 'react';

/**
 * Animated real-time counter:
 * 1. Initial mount: count-up roll from 0 to value.
 * 2. Real-time updates: subtle pop/glow pulse + quick micro-roll so live incoming packets
 *    visibly animate in real-time without needing a page refresh.
 */
export function CountUpNumber({ value, duration = 750 }: { value: number | string; duration?: number }) {
  const numeric = typeof value === 'number' ? value : Number(String(value).replace(/,/g, ''));
  const isNumeric = !Number.isNaN(numeric);
  const [display, setDisplay] = useState(isNumeric ? numeric : 0);
  const [bump, setBump] = useState(false);
  const mountedRef = useRef(false);
  const currentRef = useRef(isNumeric ? numeric : 0);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    if (!isNumeric) return;

    // 1. Initial mount roll: 0 -> target
    if (!mountedRef.current && numeric > 0) {
      mountedRef.current = true;
      const start = 0;
      const end = numeric;
      const startTime = performance.now();

      const tick = (time: number) => {
        const elapsed = time - startTime;
        const progress = Math.min(1, elapsed / duration);
        const ease = 1 - Math.pow(1 - progress, 3);
        const next = Math.round(start + (end - start) * ease);
        currentRef.current = next;
        setDisplay(next);

        if (progress < 1) {
          rafRef.current = requestAnimationFrame(tick);
        } else {
          setDisplay(end);
          currentRef.current = end;
        }
      };

      rafRef.current = requestAnimationFrame(tick);
      return () => {
        if (rafRef.current) cancelAnimationFrame(rafRef.current);
      };
    }

    if (!mountedRef.current) {
      mountedRef.current = true;
      currentRef.current = numeric;
      setDisplay(numeric);
      return;
    }

    // 2. Real-time live update while staying on the page (no refresh needed)
    const from = currentRef.current;
    const to = numeric;
    if (from === to) return;

    // Trigger subtle visual pulse on update
    setBump(true);
    const bumpTimer = setTimeout(() => setBump(false), 300);

    // Fast roll (120ms) to target so live changes feel alive and responsive
    const startTime = performance.now();
    const liveDuration = 140;

    const tickLive = (time: number) => {
      const elapsed = time - startTime;
      const progress = Math.min(1, elapsed / liveDuration);
      const ease = 1 - Math.pow(1 - progress, 3);
      const next = Math.round(from + (to - from) * ease);
      currentRef.current = next;
      setDisplay(next);

      if (progress < 1) {
        rafRef.current = requestAnimationFrame(tickLive);
      } else {
        setDisplay(to);
        currentRef.current = to;
      }
    };

    rafRef.current = requestAnimationFrame(tickLive);

    return () => {
      clearTimeout(bumpTimer);
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [numeric, isNumeric, duration]);

  if (!isNumeric) {
    return <>{value}</>;
  }

  return (
    <span className={`inline-block transition-transform duration-200 ${bump ? 'scale-105 text-emerald-400 dark:text-emerald-300' : ''}`}>
      {display.toLocaleString()}
    </span>
  );
}
